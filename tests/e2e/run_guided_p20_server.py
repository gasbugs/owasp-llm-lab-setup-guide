"""Exercise P20's single execution endpoint against native isolated products."""
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import time
import uuid

import httpx


def main():
    output = Path(sys.argv[1])
    starter = '--starter' in sys.argv[2:]
    fault = sys.argv[sys.argv.index('--fault') + 1] if '--fault' in sys.argv else None
    incomplete = starter or fault is not None
    tcp_verifier = '--tcp-verifier' in sys.argv[2:]
    proof = {'scope': __doc__ + ' Product verifier helper is in this publisher process; no Browser/AWS.'}
    if tcp_verifier:
        proof['scope'] = 'Single P20 execution API and independent TCP verifier with native products; no Browser/AWS.'
    base = 'http://p20:8000'
    control = {'Authorization': 'Bearer publisher-test-control'}
    reader = {'Authorization': 'Bearer publisher-test-verifier'}
    try:
        with httpx.Client(timeout=5, trust_env=False) as client:
            urls = [base + '/readyz', 'http://prometheus:9090/-/ready',
                    'http://alertmanager:9093/-/ready', 'http://grafana:3000/api/dashboards/uid/guided-p20']
            if tcp_verifier:
                urls.append('http://verifier:8000/readyz')
            deadline = time.monotonic() + 90
            while urls and time.monotonic() < deadline:
                for url in list(urls):
                    try:
                        auth = ('p20-reader', 'publisher-test-reader') if 'grafana:3000' in url else None
                        if client.get(url, auth=auth).status_code == 200:
                            urls.remove(url)
                    except httpx.HTTPError:
                        pass
                if urls:
                    time.sleep(.25)
            if urls:
                raise TimeoutError('product readiness')
            user = client.get('http://grafana:3000/api/user', auth=('p20-reader', 'publisher-test-reader'))
            user.raise_for_status()
            proof['grafana_reader_id'] = user.json()['id']
            identity = {'suite_id': str(uuid.uuid4()), 'started_at': datetime.now(timezone.utc).isoformat()}
            proof.update(identity)
            response = client.post(base + '/v1/run/H20', json=identity, headers=control, timeout=150)
            response.raise_for_status()
            proof['receipt'] = response.json()
            proof['fault'] = fault
            if fault and fault != 'constant-panel':
                receipt = proof['receipt']
                assert receipt['execution_status'] == 'error', receipt
                assert not receipt['closed'], receipt
                expected = {'always-on': ({0, 4}, {'TimeoutError', 'ValueError'}),
                            'always-off': ({6}, {'TimeoutError'}),
                            'background-scope': ({4}, {'ValueError'}),
                            'notification-loss': ({7}, {'TimeoutError'})}[fault]
                assert len(receipt['cases']) in expected[0], receipt
                assert receipt['execution_error'] in expected[1], receipt
                if fault == 'notification-loss':
                    assert receipt['requests_closed'], receipt
            elif starter:
                assert proof['receipt']['execution_status'] == 'error', proof['receipt']
                assert proof['receipt']['execution_error'] == 'TimeoutError'
                assert not proof['receipt']['closed'] and not proof['receipt']['requests_closed']
                assert len(proof['receipt']['cases']) == 6
            else:
                assert proof['receipt']['execution_status'] == 'complete', proof['receipt']
                assert not proof['receipt']['execution_error']
            assert 'task_completed' not in proof['receipt']
            fetched = client.get(base + '/v1/receipts/H20/' + identity['suite_id'], headers=reader)
            fetched.raise_for_status()
            assert fetched.json() == proof['receipt']
            proof['replay_status'] = client.post(base + '/v1/run/H20', json=identity, headers=control).status_code
            assert proof['replay_status'] == 409
            proof['verdict_submission_status'] = client.post(base + '/v1/run/H20',
                json={**identity, 'task_completed': True}, headers=control).status_code
            assert proof['verdict_submission_status'] == 422
            root = Path(__file__).resolve().parents[2] / 'llm-security-control-plane'
            spec = importlib.util.spec_from_file_location('p20_verification', root / 'guided-evidence-verifier/p20_verification.py')
            verifier = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(verifier)
            proof['independent_product_check'] = {}
            try:
                verifier.collect_and_verify(identity['suite_id'], identity['started_at'], client=client,
                    app_url=base, prometheus_url='http://prometheus:9090', grafana_url='http://grafana:3000',
                    verifier_token='publisher-test-verifier', grafana_auth=('p20-reader', 'publisher-test-reader'),
                    runner_digests={name: hashlib.sha256((root / 'guided-labs/h20-alert-dashboard' / name).read_bytes()).hexdigest()
                                    for name in ('server.py', 'workflow.py', 'execution.py')},
                    result=proof['independent_product_check'])
            except verifier.RESULTS.EvidenceMismatch as exc:
                if not incomplete:
                    raise
                proof['expected_rejection'] = str(exc)
            assert proof['independent_product_check']['product_contract_verified'] is (not incomplete)
            if tcp_verifier:
                verify_url = 'http://verifier:8000/v1/verify/h20'
                assert client.post(verify_url, json=identity).status_code == 401
                assert client.post(verify_url, json={**identity, 'task_completed': True}, headers=control).status_code == 422
                verified = client.post(verify_url, json=identity, headers=control, timeout=60)
                verified.raise_for_status()
                proof['course_verification'] = verified.json()
                assert proof['course_verification']['activity_id'] == 'P20'
                assert proof['course_verification']['task_completed'] is (not incomplete), verified.text
                assert proof['course_verification']['security_verdict'] == ('ERR' if incomplete else 'PASS'), verified.text
                assert proof['course_verification']['result']['source_digest'] == proof['receipt']['build']['source_digest']
            proof['product_checks_completed'] = True
            print(json.dumps({'suite_id': identity['suite_id'], 'product_checks_completed': True,
                              'scope': proof['scope']}), flush=True)
    finally:
        output.write_text(json.dumps(proof, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
