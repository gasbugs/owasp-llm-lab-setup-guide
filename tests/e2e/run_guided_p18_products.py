"""Publisher-only real-product P18 probe in compose.p18-products.yaml.

No host ports, AWS credentials or other learner services are used.
"""
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import time
import uuid

import httpx
from fastapi.testclient import TestClient


def wait_ready():
    urls = ['http://loki:3100/ready', 'http://tempo:3200/ready',
            'http://prometheus:9090/-/ready', 'http://p18:8000/readyz']
    if verifier_url := os.getenv('P18_HTTP_VERIFIER_URL'):
        urls.append(verifier_url + '/readyz')
    deadline = time.monotonic() + 90
    with httpx.Client(timeout=3, trust_env=False) as client:
        while urls and time.monotonic() < deadline:
            for url in list(urls):
                try:
                    if client.get(url).status_code == 200:
                        urls.remove(url)
                except httpx.HTTPError:
                    pass
            if urls:
                time.sleep(1)
        if urls:
            raise RuntimeError(f'products not ready: {urls}')
        while time.monotonic() < deadline:
            response = client.get('http://prometheus:9090/api/v1/query', params={
                'query': 'guided_security_decisions_total{hands_on="H18"}'})
            if len(response.json().get('data', {}).get('result', [])) == 2:
                return
            time.sleep(1)
    raise RuntimeError('initial Counter scrape missing')


def main():
    wait_ready()
    body = {'suite_id': str(uuid.uuid4()), 'started_at': datetime.now(timezone.utc).isoformat()}
    response = httpx.post('http://p18:8000/v1/run/H18', json=body,
                          headers={'Authorization': 'Bearer publisher-test-control'}, timeout=60)
    response.raise_for_status()
    receipt = response.json()
    quiet = os.getenv('P18_QUIET') == 'true'
    if not quiet:
        print(json.dumps({'receipt': receipt}, ensure_ascii=False), flush=True)
    if verifier_url := os.getenv('P18_HTTP_VERIFIER_URL'):
        client_context = httpx.Client(base_url=verifier_url, timeout=60, trust_env=False)
    else:
        source = Path(os.getenv('P18_VERIFIER_SOURCE', 'llm-security-control-plane/guided-evidence-verifier/server.py'))
        for name in re.findall(r'os.environ\["([A-Z0-9_]+)"\]', source.read_text()):
            os.environ[name] = 'publisher-test-unused'
        os.environ.update(GUIDED_CONTROL_VERIFIER_TOKEN='publisher-test-control',
                          GUIDED_VERIFIER_H18_TOKEN='publisher-test-verifier',
                          GUIDED_H18_URL='http://p18:8000', GUIDED_VERIFIER_DATABASE='/tmp/p18-verifier.sqlite3')
        spec = importlib.util.spec_from_file_location('p18_product_verifier', source)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        client_context = TestClient(module.app)
    with client_context as client:
        assert client.post('/v1/verify/h18', json=body).status_code == 401
        assert client.post('/v1/verify/h18', json={**body, 'task_completed': True},
                           headers={'Authorization': 'Bearer publisher-test-control'}).status_code == 422
        verified = client.post('/v1/verify/h18', json=body,
                               headers={'Authorization': 'Bearer publisher-test-control'})
    verified.raise_for_status()
    verification = verified.json()
    if not quiet:
        print(json.dumps({'verification': verification}, ensure_ascii=False), flush=True)
    if path := os.getenv('P18_EVIDENCE_PATH'):
        Path(path).write_text(json.dumps({'receipt': receipt, 'verification': verification},
                                       ensure_ascii=False, indent=2), encoding='utf-8')
    expected = os.getenv('P18_EXPECT_COMPLETED', 'true') == 'true'
    assert verified.status_code == 200 and verification['task_completed'] is expected
    assert verification['security_verdict'] == ('PASS' if expected else 'ERR')
    print(json.dumps({'suite_id': body['suite_id'], 'source_digest': receipt['source_digest'],
                      'task_completed': verification['task_completed'],
                      'security_verdict': verification['security_verdict'],
                      'reason': verification['reason']}, ensure_ascii=False), flush=True)


if __name__ == '__main__':
    main()
