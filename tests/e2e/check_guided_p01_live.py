"""Build P01 Starter/Markdown in an isolated Docker stack; never edit the checkout.

Uses packaged Gateway, Control Center, verifier and proxy entrypoints. Contract
mode has no AWS credentials. AWS mode is explicit and creates no cloud resources.
This selected-service test does not certify the full operating Compose stack.
"""
import argparse
import ast
from contextlib import ExitStack
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import build_opener, HTTPCookieProcessor, ProxyHandler, Request
import uuid

from guided_live_stack import LiveStack

ROOT = Path(__file__).resolve().parents[2]
CONTROL = ROOT / 'llm-security-control-plane'
LAB = CONTROL / 'guided-labs/h01-bedrock-gateway'


def markdown_source(path):
    document = path.read_text(encoding='utf-8')
    parts = re.split(r'^## \d+\. 풀이.*$', document, flags=re.MULTILINE)
    if len(parts) != 2:
        raise ValueError('exactly one numbered solution section is required')
    blocks = re.findall(r'^```python\n(.*?)^```$', parts[1], re.MULTILINE | re.DOTALL)
    if len(blocks) != 1 or len(blocks[0].encode()) > 65536:
        raise ValueError('one complete bounded Python solution is required')
    tree = ast.parse(blocks[0])
    if sum(isinstance(node, ast.FunctionDef) and node.name == 'handle_request' for node in tree.body) != 1:
        raise ValueError('one handle_request function is required')
    return blocks[0].encode()


def build(role, recipe, context, project, no_cache=False):
    image = f'localhost/{project}-{role}:test'
    subprocess.run(['docker', 'build', *(['--no-cache'] if no_cache else []), '-f', str(recipe), '-t', image, str(context)], check=True)
    return image


def snapshot(project):
    code = '''import json, sqlite3
with sqlite3.connect("file:/tmp/receipts.sqlite3?mode=ro", uri=True) as db:
    print(json.dumps({"executions": [json.loads(r[0]) for r in db.execute("SELECT record_json FROM executions")],
                      "receipts": [json.loads(r[0]) for r in db.execute("SELECT receipt_json FROM receipts")]}))
'''
    return json.loads(subprocess.check_output(
        ['docker', 'exec', project + '-gateway', 'python', '-c', code], text=True))


def request(opener, url, *, headers=None, body=None):
    try:
        response = opener.open(Request(url, data=body, headers=headers or {}), timeout=240)
    except HTTPError as error:
        response = error
    with response:
        return response.status, json.loads(response.read())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument('--starter', action='store_true')
    selection.add_argument('--markdown', type=Path)
    selection.add_argument('--source', type=Path, help='Publisher fixture; never copied into the Starter image')
    parser.add_argument('--aws-config-dir', type=Path)
    parser.add_argument('--aws-profile', default='default')
    parser.add_argument('--browser-python', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--no-cache', action='store_true', help='Rebuild project layers; existing base images may be reused')
    args = parser.parse_args()
    if args.output.exists():
        parser.error('output already exists; preserve previous evidence')
    if args.aws_config_dir and (args.starter or not args.aws_config_dir.is_dir()):
        parser.error('AWS requires a solution and an existing credential directory')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    mode = 'aws' if args.aws_config_dir else 'contract'
    source = ((LAB / 'learner.py').read_bytes() if args.starter else
              args.source.read_bytes() if args.source else markdown_source(args.markdown))
    compile(source, 'learner.py', 'exec')
    source_files = {name: (source if name == 'learner.py' else (LAB / name).read_bytes())
                    for name in ('server.py', 'learner.py', 'provider.py')}
    identity = hashlib.sha256()
    for name, content in source_files.items():
        identity.update(name.encode() + b'\0' + content + b'\0')
    source_digest = identity.hexdigest()
    project = 'guided-p01-check-' + uuid.uuid4().hex[:10]
    proof = {'scope': 'selected packaged Docker services; not full operational Compose',
             'project_build_cache_disabled': args.no_cache, 'fresh_application_state': True,
             'project': project, 'provider_mode': mode, 'source_digest': source_digest,
             'learner_sha256': hashlib.sha256(source).hexdigest(),
             'markdown_sha256': hashlib.sha256(args.markdown.read_bytes()).hexdigest() if args.markdown else None}
    try:
        with ExitStack() as cleanup:
            temporary = Path(cleanup.enter_context(tempfile.TemporaryDirectory(prefix='p01-build-')))
            target = temporary / 'guided-labs/h01-bedrock-gateway'
            target.mkdir(parents=True)
            for name in ('server.py', 'provider.py', 'requirements.txt', 'Containerfile'):
                shutil.copyfile(LAB / name, target / name)
            (target / 'learner.py').write_bytes(source)
            gateway_image = build('gateway', target / 'Containerfile', temporary, project, args.no_cache)
            verifier_image = build('verifier', CONTROL / 'guided-evidence-verifier/Containerfile', CONTROL, project, args.no_cache)
            network = project + '_default'
            subprocess.run(['docker', 'network', 'create', *([] if mode == 'aws' else ['--internal']), network], check=True)
            cleanup.callback(subprocess.run, ['docker', 'network', 'rm', network], check=True)
            live = LiveStack(ROOT, project, 'H01', 'http://gateway:8000', no_cache=args.no_cache)
            cleanup.callback(live.close)
            gateway_env = {'GUIDED_CONTROL_LAB01_TOKEN': 'publisher-test-control',
                           'GUIDED_VERIFIER_LAB01_TOKEN': 'publisher-test-verifier', 'GUIDED_PROVIDER_MODE': mode}
            extra = ['--network-alias', 'gateway']
            if mode == 'aws':
                gateway_env.update(AWS_PROFILE=args.aws_profile, AWS_REGION='us-east-1',
                    AWS_DEFAULT_REGION='us-east-1', AWS_EC2_METADATA_DISABLED='true',
                    AWS_CONFIG_FILE='/aws/config', AWS_SHARED_CREDENTIALS_FILE='/aws/credentials',
                    AWS_MAX_ATTEMPTS='1', AWS_RETRY_MODE='standard')
                extra += ['--user', f'{os.getuid()}:{os.getgid()}', '-v', f'{args.aws_config_dir.resolve()}:/aws:ro']
            live.launch('gateway', gateway_image, gateway_env, extra)
            live.start_verifier(verifier_image, {'GUIDED_LAB01_URL': 'http://gateway:8000',
                                                'GUIDED_VERIFIER_LAB01_TOKEN': 'publisher-test-verifier'})
            origin = live.start_browser({'GUIDED_LAB01_URL': 'http://gateway:8000',
                                         'GUIDED_CONTROL_LAB01_TOKEN': 'publisher-test-control'})
            opener = build_opener(ProxyHandler({}), HTTPCookieProcessor(http.cookiejar.CookieJar()))
            deadline = time.monotonic() + 60
            while True:
                try:
                    if request(opener, origin + '/readyz')[0] == 200:
                        break
                except (URLError, TimeoutError, json.JSONDecodeError):
                    pass
                if time.monotonic() >= deadline:
                    raise TimeoutError('common UI startup')
                time.sleep(.5)
            if args.browser_python:
                browser_output = args.output.with_suffix('.browser.json')
                command = [str(args.browser_python.absolute()), str(ROOT / 'tests/browser/check_guided_p01_live.py'),
                           origin, str(browser_output), '--source-digest', source_digest]
                if args.starter:
                    command.append('--incomplete')
                subprocess.run(command, check=True, timeout=300)
                browser_proof = json.loads(browser_output.read_text())
                status, response = browser_proof['http_status'], browser_proof['response']
                proof['browser'] = str(browser_output)
            else:
                with opener.open(origin + '/', timeout=5) as index:
                    assert index.status == 200
                status, bootstrap = request(opener, origin + '/api/bootstrap')
                assert status == 200
                headers = {'Origin': origin, 'X-CSRF-Token': bootstrap['csrf_token']}
                status, response = request(opener, origin + '/api/practice/P01/verify', headers=headers, body=b'')
                rejected, _ = request(opener, origin + '/api/practice/P01/verify',
                    headers={**headers, 'Content-Type': 'application/json'}, body=b'{"task_completed":true}')
                assert rejected == 422
                proof['submitted_verdict_status'] = rejected
            proof.update(http_status=status, response=response, images=live.images, ledger=snapshot(project))
            records, receipts = proof['ledger']['executions'], proof['ledger']['receipts']
            if args.starter:
                assert status == 502 and response['detail']['task_completed'] is False
                assert response['detail']['security_verdict'] == 'ERR'
                assert len(records) == 1 and records[0]['http_status'] == 501 and records[0]['closed'] is True
                assert records[0]['provider_attempts'] == 0 and receipts == []
            else:
                assert status == 200 and response['task_completed'] is True and response['security_verdict'] == 'PASS'
                assert len(records) == 21 and len(receipts) == 7
                assert sum(r['provider_attempts'] for r in records) == 7
                assert all(r['closed'] and r['source_digest'] == source_digest for r in records)
                assert all(r['provider_mode'] == mode for r in receipts)
                assert len({r['provider_request_id'] for r in receipts}) == 7
            proof['verified'] = True
    finally:
        remaining = subprocess.check_output(['docker', 'ps', '-a', '--format', '{{.Names}}'], text=True).splitlines()
        proof['owned_containers_removed'] = not any(name.startswith(project + '-') for name in remaining)
        networks = subprocess.check_output(['docker', 'network', 'ls', '--format', '{{.Name}}'], text=True).splitlines()
        proof['owned_networks_removed'] = not any(name.startswith(project) for name in networks)
        args.output.write_text(json.dumps(proof, ensure_ascii=False, indent=2))
    assert proof['owned_containers_removed'] and proof['owned_networks_removed']
    print(json.dumps({'verified': True, 'provider_mode': mode, 'starter': args.starter, 'project': project}), flush=True)


if __name__ == '__main__':
    main()
