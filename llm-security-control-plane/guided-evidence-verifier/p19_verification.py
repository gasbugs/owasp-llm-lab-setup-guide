"""Read-only P19 suite verification; callers re-fetch ledger, build and products."""
from datetime import datetime, timezone
import importlib.util
from pathlib import Path


def helper(filename, fallback=None):
    path = Path(__file__).with_name(filename)
    if not path.exists() and fallback:
        path = Path(__file__).resolve().parents[1] / fallback
    spec = importlib.util.spec_from_file_location('p19_' + filename.removesuffix('.py'), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


RESULTS = helper('p19_results.py')
INPUTS = helper('p19_inputs.py', 'guided-labs/h19-incident-investigation/analysis_inputs.py')
require = RESULTS.require


def verify(receipt, ledger, build, observed, *, suite_id, started_at, runner_digests):
    require(receipt.get('activity_id') == 'P19' and receipt.get('internal_activity_id') == 'H19'
            and receipt.get('contract_version') == 2, 'P19 contract mismatch')
    for record in (receipt, ledger):
        require(record.get('suite_id') == suite_id and record.get('started_at') == started_at,
                'execution identity mismatch')
    started = datetime.fromisoformat(started_at)
    now = datetime.now(timezone.utc)
    require(started.tzinfo is not None and 0 <= (now - started).total_seconds() <= 180, 'stale execution')
    require(not receipt.get('execution_error') and ledger.get('closed') is True, 'execution or collection incomplete')
    require(build.get('runner_digests') == runner_digests and bool(runner_digests), 'provided runner changed')
    source = receipt.get('source_digest')
    require(isinstance(source, str) and len(source) == 64 and build.get('source_digest') == source,
            'learner source changed after execution')
    cases = ledger.get('cases', [])
    require(len(cases) == 3 and receipt.get('cases') == cases, 'request cases differ')
    require(len({case['request_id'] for case in cases}) == len({case['trace_id'] for case in cases}) == 3,
            'request identities must be distinct')
    require([case.get('decision') for case in cases] == ['allow', 'block', 'block']
            and [case.get('stop_stage') for case in cases] == [None, 'authorize', 'authenticate'],
            'normal or explicit denial missing')
    require(all(case.get('closed') is True and started.timestamp() * 1e9 <= case['started_ns']
                <= case['finished_ns'] <= now.timestamp() * 1e9 for case in cases), 'open or stale request')
    calls = ledger.get('downstream_calls', [])
    require(len(calls) == 1 and calls[0].get('request_id') == cases[0]['request_id']
            and calls[0].get('trace_id') == cases[0]['trace_id']
            and calls[0].get('operation') == 'notice_lookup'
            and calls[0].get('result') == cases[0].get('result')
            and calls[0].get('result', {}).get('notice_id') == 'p19-training-notice',
            'downstream evidence differs')
    bundle = observed['bundle']
    require(bundle.get('closures') == cases and bundle.get('downstream_calls') == calls,
            'product bundle is not bound to the closed ledger')
    require(INPUTS.canonical(receipt['bundle']) == INPUTS.canonical(bundle), 'collected evidence changed')
    analyses = [RESULTS.expected_analysis(bundle, case['request_id']) for case in cases]
    require([row['downstream_count'] for row in analyses] == [1, 0, 0], 'denied request reached downstream')
    expected = INPUTS.build_inputs(bundle, [case['request_id'] for case in cases])
    executions = receipt.get('analysis_executions', [])
    require(len(executions) == len(expected), 'analysis suite incomplete')
    checked = []
    for actual, case in zip(executions, expected):
        require(all(actual.get(key) == case[key] for key in ('case_id', 'request_id', 'input_digest'))
                and actual.get('expected_invalid') is case['expected_invalid'], 'analysis input identity differs')
        require(actual.get('source_digest') == source, 'analysis used another learner source')
        result = RESULTS.check_analysis(case['bundle'], case['request_id'], actual,
                                        expected_invalid=case['expected_invalid'])
        checked.append({'case_id': case['case_id'], **result})
    return {'activity_id': 'P19', 'internal_activity_id': 'H19', 'contract_version': 2,
            'task_completed': True, 'security_verdict': 'PASS', 'analyses': analyses,
            'checks': checked, 'source_digest': source}
