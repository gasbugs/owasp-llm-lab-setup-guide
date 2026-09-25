"""Real P17 worker, OTLP products and Prometheus scrape; no Browser or AWS."""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
import re
from pathlib import Path
import time
import uuid

import httpx
from p17_faults import FAILURES

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('p17_results', ROOT / 'llm-security-control-plane/guided-evidence-verifier/p17_results.py')
results = importlib.util.module_from_spec(spec)
spec.loader.exec_module(results)


def until(check, timeout=30):
    deadline = time.monotonic() + timeout
    while True:
        try:
            value = check()
            if value:
                return value
        except (httpx.HTTPError, results.EvidenceMismatch, KeyError):
            pass
        if time.monotonic() >= deadline:
            raise TimeoutError('current P17 product data unavailable')
        time.sleep(0.25)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--starter', action='store_true')
    mode.add_argument('--fault', choices=FAILURES)
    args = parser.parse_args()
    with httpx.Client(timeout=30, trust_env=False) as client:
        def get(url, **kwargs):
            response = client.get(url, **kwargs)
            response.raise_for_status()
            return response.json()
        def metric(query='guided_p17_decisions_total'):
            return get('http://prometheus:9090/api/v1/query', params={'query': query})
        until(lambda: get('http://p17:8000/readyz'))
        before = until(lambda: (value if len(value.get('data', {}).get('result', [])) == 2 else None)
                       if (value := metric()) else None)
        baseline = results.counter_values(before)
        body = {'suite_id': str(uuid.uuid4()), 'started_at': datetime.now(timezone.utc).isoformat()}
        response = client.post('http://p17:8000/v1/run/H17', json=body,
                               headers={'Authorization': 'Bearer publisher-test-control'})
        response.raise_for_status()
        receipt = response.json()
        headers = {'Authorization': 'Bearer publisher-test-verifier'}
        ledger = get('http://p17:8000/v1/h17/ledger/' + body['suite_id'], headers=headers)
        build = get('http://p17:8000/v1/h17/build-info', headers=headers)
        assert receipt['source_digest'] == build['source_digest'] == receipt['execution']['source_digest']
        assert receipt['execution']['closed'] is True
        assert ledger['cases'] == [c['ledger'] for c in receipt['execution']['cases']]
        def fresh_scrape():
            rows = metric('timestamp(guided_p17_decisions_total)')['data']['result']
            return len(rows) == 2 and all(float(r['value'][1]) * 1e9 > receipt['query_end_ns'] for r in rows)
        until(fresh_scrape)
        after = metric()
        current = results.counter_values(after)
        products, analyses = [], []
        if args.starter:
            assert all(c['execution_status'] == 'not_implemented' and c['ledger']['invocations'] == 0
                       for c in receipt['execution']['cases'])
            assert current == baseline
        else:
            assert {d: current[d] - baseline[d] for d in current} == {'allow': 1, 'block': 2}
            for case in receipt['execution']['cases']:
                def observe():
                    query = '{service_name="guided-h17-telemetry"} | json | request_id = "' + case['request_id'] + '"'
                    raw = {'loki': get('http://loki:3100/loki/api/v1/query_range', params={
                        'query': query, 'start': case['started_ns'], 'end': case['finished_ns'], 'limit': 20}),
                        'tempo': get('http://tempo:3200/api/traces/' + case['ledger']['stages'][0]['trace_id'])}
                    if args.fault:
                        return raw, None
                    return raw, results.verify_case(case, raw)
                raw, analysis = until(observe)
                products.append(raw)
                analyses.append(analysis)
        proof = {'scope': __doc__, 'receipt': receipt, 'ledger': ledger, 'build': build,
                 'prometheus_before': before, 'prometheus_after': after,
                 'products': products, 'analyses': analyses, 'starter': args.starter,
                 'fault': args.fault}
        verifier_url = os.environ.get('P17_HTTP_VERIFIER_URL')
        if verifier_url:
            until(lambda: get(verifier_url + '/readyz'))
            verifier_client = httpx.Client(base_url=verifier_url, timeout=45, trust_env=False)
        else:
            from fastapi.testclient import TestClient
            source = Path('/app/server.py')
            for name in re.findall(r'os.environ\["([A-Z0-9_]+)"\]', source.read_text()):
                os.environ[name] = 'publisher-test-unused'
            os.environ.update(GUIDED_CONTROL_VERIFIER_TOKEN='publisher-test-control',
                              GUIDED_VERIFIER_H17_TOKEN='publisher-test-verifier', GUIDED_H17_URL='http://p17:8000',
                              GUIDED_VERIFIER_DATABASE='/tmp/p17-verifier.sqlite3')
            spec = importlib.util.spec_from_file_location('packaged_verifier', source)
            verifier_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(verifier_module)
            verifier_client = TestClient(verifier_module.app)
        with verifier_client as verifier:
            auth = {'Authorization': 'Bearer publisher-test-control'}
            assert verifier.post('/v1/verify/h17', json=body).status_code == 401
            assert verifier.post('/v1/verify/h17', json={**body, 'task_completed': True}, headers=auth).status_code == 422
            verified = verifier.post('/v1/verify/h17', json=body, headers=auth)
            assert verified.status_code == 200
            proof['http_verification'] = verified.json()
            expected_completion = not (args.starter or args.fault)
            assert verified.json()['task_completed'] is expected_completion, verified.json().get('result')
            assert verified.json()['security_verdict'] == ('PASS' if expected_completion else 'ERR')
            if args.fault:
                assert verified.json()['result'].get('failed_requirement') == FAILURES[args.fault], verified.json()
                assert [c['ledger']['closures'][0]['downstream_count'] for c in receipt['execution']['cases']] == [1, 0, 0]
        transport = 'TCP verifier' if verifier_url else 'packaged verifier TestClient'
        proof['scope'] = 'P17 HTTP + actual products + ' + transport + '; no Browser or AWS'
        args.output.write_text(json.dumps(proof, ensure_ascii=False, indent=2))
        print(json.dumps({'scope': proof['scope'], 'starter': args.starter, 'fault': args.fault,
                          'task_completed': proof['http_verification']['task_completed'],
                          'failed_requirement': proof['http_verification']['result'].get('failed_requirement'),
                          'counter_delta': {d: current[d]-baseline[d] for d in current},
                          'analyses': analyses}), flush=True)


if __name__ == '__main__':
    main()
