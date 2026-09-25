"""Compare a pre-restart P20 receipt and product account after container recreation."""
import json
from pathlib import Path
import sys
import time

import httpx


def main():
    evidence = Path(sys.argv[1])
    original = json.loads((evidence / 'products.json').read_text())
    receipt = original['receipt']
    identity = {key: original[key] for key in ('suite_id', 'started_at')}
    reader = {'Authorization': 'Bearer publisher-test-verifier'}
    control = {'Authorization': 'Bearer publisher-test-control'}
    with httpx.Client(timeout=5, trust_env=False) as client:
        deadline = time.monotonic() + 45
        while True:
            try:
                fetched = client.get('http://p20:8000/v1/receipts/H20/' + identity['suite_id'], headers=reader)
                fetched.raise_for_status()
                if client.get('http://prometheus:9090/-/ready').status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            if time.monotonic() >= deadline:
                raise TimeoutError('recreated P20 readiness')
            time.sleep(.5)
        assert fetched.json() == receipt, 'persisted receipt changed'
        verified = client.post('http://verifier:8000/v1/verify/h20', headers=control, json=identity, timeout=60)
        verified.raise_for_status()
        result = verified.json()
        assert result['task_completed'] is True, result.get('reason')
        assert result['security_verdict'] == 'PASS'
        assert result['result']['source_digest'] == receipt['build']['source_digest']
        user = client.get('http://grafana:3000/api/user', auth=('p20-reader', 'publisher-test-reader'))
        user.raise_for_status()
        assert user.json()['id'] == original['grafana_reader_id']
        (evidence / 'recreated-state.json').write_text(json.dumps({
            'scope': 'operating P20 subset with named volumes; container recreation; no AWS',
            'receipt_unchanged': True, 'reader_identity_unchanged': True, 'verification': result},
            ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
