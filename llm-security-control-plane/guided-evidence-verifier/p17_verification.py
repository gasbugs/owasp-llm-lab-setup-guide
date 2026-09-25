"""Independent P17 identity, business evidence and current product verification."""
from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import re
import time
import uuid

import httpx

spec = importlib.util.spec_from_file_location('p17_results', Path(__file__).with_name('p17_results.py'))
RESULTS = importlib.util.module_from_spec(spec)
spec.loader.exec_module(RESULTS)
require = RESULTS.require


def identity(receipt, suite_id, started_at):
    require(receipt.get('suite_id') == suite_id and receipt.get('started_at') == started_at,
            'execution identity mismatch')
    require((receipt.get('activity_id'), receipt.get('internal_activity_id'), receipt.get('contract_version'))
            == ('P17', 'H17', 2), 'wrong activity contract')
    started = datetime.fromisoformat(started_at)
    require(started.tzinfo is not None and 0 <= (datetime.now(timezone.utc)-started).total_seconds() <= 180,
            'stale execution')


def check_execution(receipt, ledger, build, runner_digests):
    require(build.get('runner_digests') == runner_digests, 'provided runner changed')
    digest = receipt.get('source_digest')
    require(isinstance(digest, str) and re.fullmatch('[0-9a-f]{64}', digest), 'invalid source digest')
    execution = receipt['execution']
    require(build.get('source_digest') == digest == execution.get('source_digest'), 'source changed after execution')
    require(not receipt.get('execution_error') and not execution.get('execution_error'), 'worker or collection failed')
    require(execution.get('closed') is True and ledger.get('closed') is True, 'execution not closed')
    require(ledger.get('suite_id') == receipt['suite_id'] and ledger.get('started_at') == receipt['started_at'],
            'ledger identity mismatch')
    cases = execution['cases']
    require(len(cases) == 3 and len({c['request_id'] for c in cases}) == 3, 'three unique requests required')
    require([(c['principal'], c['action']) for c in cases] == [
        ('reader', 'notice_lookup'), ('reader', 'notice_publish'), ('anonymous', 'notice_lookup')], 'wrong business suite')
    require(ledger['cases'] == [c['ledger'] for c in cases], 'receipt and independent ledger differ')
    start, end = receipt['query_start_ns'], receipt['query_end_ns']
    require(type(start) is int and type(end) is int and 0 < end-start <= 60_000_000_000,
            'invalid measurement interval')
    issued = int(datetime.fromisoformat(receipt['started_at']).timestamp() * 1e9)
    require(issued <= start <= end <= time.time_ns(), 'interval outside execution')
    for case in cases:
        require(str(uuid.UUID(case['request_id'])) == case['request_id'], 'invalid request ID')
        require(start <= case['started_ns'] <= case['finished_ns'] <= end, 'case outside interval')
        require(case['execution_status'] == 'returned', 'learner did not return')
        require(len(case['ledger']['stages']) in (1, 2, 3), 'missing business stages')
    return cases


def collect_and_verify(receipt, ledger, build, runner_digests, *, client,
                       loki_url, tempo_url, prometheus_url, result, timeout=15):
    cases = check_execution(receipt, ledger, build, runner_digests)
    def get(url, **kwargs):
        response = client.get(url, **kwargs)
        response.raise_for_status()
        return response.json()
    metric_query = 'guided_p17_decisions_total'
    before = get(prometheus_url + '/api/v1/query', params={
        'query': metric_query, 'time': receipt['query_start_ns'] / 1e9})
    after = get(prometheus_url + '/api/v1/query', params={
        'query': metric_query, 'time': receipt['query_end_ns'] / 1e9})
    result.update(prometheus_before=before, prometheus_after=after,
                  source_digest=receipt['source_digest'], cases=[], products=[])
    first, last = RESULTS.counter_values(before), RESULTS.counter_values(after)
    require(first == receipt['counter_before'] and last == receipt['execution']['counter_values'],
            'product Counter differs from actual SDK values')
    require({d: last[d]-first[d] for d in first} == {'allow': 1, 'block': 2}, 'Counter delta differs')
    # Product export may lag execution. Only re-read observations; never replay actions.
    deadline = time.monotonic() + timeout
    for case in cases:
        trace_id = case['ledger']['stages'][0]['trace_id']
        require(bool(re.fullmatch('[0-9a-f]{32}', trace_id)) and trace_id != '0'*32, 'invalid business Trace')
        while True:
            try:
                raw = {'request_id': case['request_id'],
                    'loki': get(loki_url + '/loki/api/v1/query_range', params={
                        'query': '{service_name="guided-h17-telemetry"} | json | request_id = "' + case['request_id'] + '"',
                        'start': case['started_ns'], 'end': case['finished_ns'], 'limit': 20}),
                    'tempo': get(tempo_url + '/api/traces/' + trace_id)}
                result['products'] = [p for p in result['products'] if p['request_id'] != case['request_id']] + [raw]
                analysis = RESULTS.verify_case(case, raw)
                result['cases'].append(analysis)
                break
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code != 404:
                    raise
            except RESULTS.EvidenceMismatch:
                if time.monotonic() >= deadline:
                    raise
            if time.monotonic() >= deadline:
                raise TimeoutError('current telemetry not collected')
            time.sleep(0.25)
    result['counter_delta'] = {d: last[d]-first[d] for d in first}
