"""HTTP client for default-CMD P12 runner, common Control Center and verifier."""
import hashlib
from http.cookiejar import CookieJar
import json
import os
from pathlib import Path
import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPCookieProcessor, ProxyHandler, Request, build_opener


def main():
    opener = build_opener(ProxyHandler({}), HTTPCookieProcessor(CookieJar()))
    def request(origin, path, *, token=None, body=None, method=None, headers=None):
        fields = dict(headers or {})
        if token:
            fields['Authorization'] = 'Bearer ' + token
        if body is not None:
            fields['Content-Type'] = 'application/json'
        req = Request(origin + path, headers=fields, method=method,
                      data=json.dumps(body).encode() if body is not None else None)
        try:
            response = opener.open(req, timeout=990)
        except HTTPError as error:
            response = error
        with response:
            raw = response.read(2097153)
            assert len(raw) <= 2097152
            return response.status, json.loads(raw) if 'json' in response.headers.get('Content-Type', '') else raw.decode()

    for service in ('gateway', 'context', 'privacy', 'nemo', 'runner', 'verifier', 'control'):
        deadline = time.monotonic() + 90
        while True:
            try:
                port = 8080 if service == 'gateway' else 8000
                if request(f'http://{service}:{port}', '/readyz')[0] == 200:
                    break
            except (URLError, TimeoutError):
                pass
            if time.monotonic() >= deadline:
                raise TimeoutError('P12 readiness: ' + service)
            time.sleep(.2)
    if os.getenv('P12_READY_ONLY') == '1':
        print('P12 products and common services ready')
        return
    control, runner, verifier = 'http://control:8000', 'http://runner:8000', 'http://verifier:8000'
    read_token = os.environ['P12_RUNNER_VERIFIER']
    control_token = os.environ['P12_VERIFIER_CONTROL']
    assert request(control, '/')[0] == 200
    status, bootstrap = request(control, '/api/bootstrap')
    assert status == 200
    headers = {'Origin': control, 'X-CSRF-Token': bootstrap['csrf_token']}
    path = '/api/practice/P12/verify'
    assert request(control, path, method='POST')[0] == 403
    assert request(control, path, body={'task_completed': True}, headers=headers)[0] == 422
    if os.getenv('P12_EXISTING_ENVELOPE'):
        envelope = json.loads(os.environ['P12_EXISTING_ENVELOPE'])
    else:
        status, envelope = request(control, path, method='POST', headers=headers)
        assert status == 200, envelope
    expected = os.environ['P12_CHECK_STARTER'] != '1'
    assert envelope['task_completed'] is expected, envelope
    assert envelope['security_verdict'] == ('PASS' if expected else 'ERR'), envelope
    suite = envelope['execution_id']
    grade = envelope['result']
    assert grade['suite_id'] == suite and grade['contract_version'] == 2
    status, receipt = request(runner, '/v1/receipts/' + suite, token=read_token)
    assert status == 200 and receipt['run_state'] == 'finished', receipt
    assert len(receipt['cases']) == 8
    status, build = request(runner, '/v1/build-info', token=read_token)
    assert status == 200
    assert receipt['build']['files']['pipeline.py'] == hashlib.sha256(Path('/app/learner/pipeline.py').read_bytes()).hexdigest()
    if expected:
        assert len(grade['cases']) == 8 and grade['provider_call_count'] == 16
        assert grade['source_digest'] == receipt['build']['files']['pipeline.py']
    else:
        assert all(case['lifecycle']['execution']['execution_status'] == 'not_implemented' for case in receipt['cases'])
    assert request(verifier, '/v1/verify/p12', token='wrong', body={'suite_id': suite})[0] == 401
    assert request(verifier, '/v1/verify/p12', token=control_token,
                   body={'suite_id': suite, 'task_completed': True})[0] == 422
    status, rechecked = request(verifier, '/v1/verify/p12', token=control_token, body={'suite_id': suite})
    assert status == 200 and rechecked['result'] == grade
    assert request(runner, '/v1/receipts/' + suite, token=read_token)[1] == receipt
    assert request(runner, '/v1/build-info', token=read_token)[1] == build
    evidence = {'scope': 'default Gateway/runner/common verifier/Control Center over TCP; actual products; no Browser or full Compose',
                'starter': not expected, 'cases': len(receipt['cases']), 'envelope': envelope,
                'runner_receipt': receipt, 'build': build, 'rechecked': rechecked,
                'grade': grade, 'tcp_grade': rechecked['result']}
    serialized = json.dumps(evidence, ensure_ascii=False)
    secrets = [value for key, value in os.environ.items() if ('TOKEN' in key or key in {'P12_RUNNER_VERIFIER', 'P12_VERIFIER_CONTROL'}) and value]
    assert all(value not in serialized for value in secrets)
    print(serialized)


if __name__ == '__main__':
    main()
