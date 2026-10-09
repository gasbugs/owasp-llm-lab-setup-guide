"""Publisher P19 HTTP->products->actual child function->independent verification."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import time
import uuid

import httpx

ROOT = Path('llm-security-control-plane')
RUNNER = ROOT / 'guided-labs/h19-incident-investigation'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--expect-complete', action='store_true')
    parser.add_argument('--expected-failure', default='analysis did not return a result')
    args = parser.parse_args()
    collection = load('p19_collection', RUNNER / 'collection.py')
    verification = load('p19_verification', ROOT / 'guided-evidence-verifier/p19_verification.py')
    with httpx.Client(timeout=60, trust_env=False) as client:
        pending = ['http://p19:8000/readyz', 'http://loki:3100/ready', 'http://tempo:3200/ready']
        verifier_url = os.getenv('P19_HTTP_VERIFIER_URL')
        if verifier_url:
            pending.append(verifier_url + '/readyz')
        deadline = time.monotonic() + 90
        while pending and time.monotonic() < deadline:
            for url in list(pending):
                try:
                    if client.get(url, timeout=3).status_code == 200:
                        pending.remove(url)
                except httpx.HTTPError:
                    pass
            if pending:
                time.sleep(1)
        assert not pending, f'not ready: {pending}'
        body = {'suite_id': str(uuid.uuid4()), 'started_at': datetime.now(timezone.utc).isoformat()}
        response = client.post('http://p19:8000/v1/run/H19', json=body,
                               headers={'Authorization': 'Bearer publisher-test-control'})
        response.raise_for_status()
        headers = {'Authorization': 'Bearer publisher-test-verifier'}
        def fetch(path):
            result = client.get('http://p19:8000' + path, headers=headers)
            result.raise_for_status()
            return result.json()
        receipt = fetch('/v1/receipts/H19/' + body['suite_id'])
        assert receipt == response.json()
        ledger = fetch('/v1/h19/ledger/' + body['suite_id'])
        build = fetch('/v1/h19/build-info')
        observed = collection.collect(ledger['cases'], ledger['downstream_calls'], client=client)
        expected_runner = {name: hashlib.sha256((RUNNER / name).read_bytes()).hexdigest()
                           for name in ('server.py', 'analysis_inputs.py', 'collection.py', 'execution.py', 'workflow.py')}
        core_result = None
        failed_requirement = None
        try:
            core_result = verification.verify(receipt, ledger, build, observed, **body, runner_digests=expected_runner)
        except verification.RESULTS.EvidenceMismatch as exc:
            failed_requirement = str(exc)
        assert len(receipt['analysis_executions']) == 10
        if args.expect_complete:
            assert failed_requirement is None, failed_requirement
            assert core_result['task_completed'] is True
            statuses = [row['execution_status'] for row in receipt['analysis_executions']]
            assert statuses.count('returned') == 6 and statuses.count('invalid_evidence') == 4
        else:
            assert failed_requirement == args.expected_failure, failed_requirement
        proof = {'scope': 'P19 HTTP and real products; verifier core only, no Browser or AWS',
                 'request': body, 'receipt': receipt, 'ledger': ledger, 'build': build,
                 'rechecked_products': observed, 'failed_requirement': failed_requirement,
                 'core_verification': core_result}
        if verifier_url:
            path = verifier_url + '/v1/verify/h19'
            assert client.post(path, json=body).status_code == 401
            authorization = {'Authorization': 'Bearer publisher-test-control'}
            assert client.post(path, json={**body, 'task_completed': True},
                               headers=authorization).status_code == 422
            response = client.post(path, json=body, headers=authorization)
            proof['scope'] = 'P19 and verifier TCP services + actual products; no Browser or AWS'
            proof['boundary_checks'] = {'missing_credential': 401, 'submitted_verdict': 422}
        elif verifier_source := os.getenv('P19_HTTP_VERIFIER_SOURCE'):
            from fastapi.testclient import TestClient
            source = Path(verifier_source)
            for name in re.findall(r'os.environ\["([A-Z0-9_]+)"\]', source.read_text()):
                os.environ[name] = 'publisher-test-unused'
            os.environ.update(GUIDED_CONTROL_VERIFIER_TOKEN='publisher-test-control',
                              GUIDED_VERIFIER_H19_TOKEN='publisher-test-verifier',
                              GUIDED_H19_URL='http://p19:8000', GUIDED_VERIFIER_DATABASE='/tmp/p19-verifier.sqlite3')
            module = load('p19_packaged_verifier', source)
            with TestClient(module.app) as verifier:
                response = verifier.post('/v1/verify/h19', json=body,
                    headers={'Authorization': 'Bearer publisher-test-control'})
            proof['scope'] = 'P19 HTTP + actual products + packaged verifier TestClient; no Browser or AWS'
        if verifier_url or os.getenv('P19_HTTP_VERIFIER_SOURCE'):
            assert response.status_code == 200
            verified = response.json()
            assert verified['task_completed'] is args.expect_complete
            assert verified['security_verdict'] == ('PASS' if args.expect_complete else 'ERR')
            if not args.expect_complete:
                assert verified['result']['failed_requirement'] == failed_requirement
            assert len(verified['result']['products']) == 3
            proof['http_verification'] = verified
        hunt_queries = {
            'by_ip_rule': 'sum by (client_ip, policy_rule) (count_over_time({service_name="guided-h19-investigation"} | json | decision="block" | __error__="" [15m]))',
            'blocked_ip': '{service_name="guided-h19-investigation"} | json | client_ip="192.0.2.20" | decision="block"',
            'authenticated_user': '{service_name="guided-h19-investigation"} | json | user_id="reader"',
        }
        hunts = {}
        for name, query in hunt_queries.items():
            is_metric = name == 'by_ip_rule'
            url = 'http://loki:3100/loki/api/v1/' + ('query' if is_metric else 'query_range')
            params = {'query': query}
            if not is_metric:
                params.update(start=min(row['started_ns'] for row in ledger['cases']),
                              end=max(row['finished_ns'] for row in ledger['cases']), limit=100)
            raw = client.get(url, params=params)
            raw.raise_for_status()
            value = raw.json()
            assert value['status'] == 'success', value
            if is_metric:
                rules = {row['metric']['policy_rule']: row for row in value['data']['result']}
                assert set(rules) == {'notice-read-only', 'authentication-required'}, value
                assert all(row['metric']['client_ip'] == '192.0.2.20'
                           and float(row['value'][1]) == 1 for row in rules.values()), value
            else:
                events = [json.loads(row[1]) for stream in value['data']['result'] for row in stream['values']]
                assert len(events) == 2, value
                if name == 'blocked_ip':
                    assert {row['user_id'] for row in events} == {'reader', None}, value
                    assert all(row['decision'] == 'block' for row in events), value
                else:
                    assert {row['decision'] for row in events} == {'allow', 'block'}, value
                    assert all(row['user_id'] == 'reader' for row in events), value
            hunts[name] = {'query': query, 'response': value}
        proof['hunting_queries'] = hunts
        args.output.write_text(json.dumps(proof, ensure_ascii=False, indent=2))
        print(json.dumps({'scope': proof['scope'], 'suite_id': body['suite_id'],
                          'analysis_executions': 10, 'task_completed': args.expect_complete,
                          'failed_requirement': failed_requirement}))


if __name__ == '__main__':
    main()
