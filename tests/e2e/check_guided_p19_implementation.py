"""Build one P19 implementation without changing Starter or existing deployments."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[2]
RELATIVE = Path('guided-labs/h19-incident-investigation')
FILES = ('Containerfile', 'server.py', 'workflow.py', 'collection.py',
         'execution.py', 'analysis_inputs.py')


def extract_solution(document):
    parts = re.split(r'^## \d+\. 풀이.*$', document, flags=re.MULTILINE)
    if len(parts) != 2:
        raise ValueError('one numbered solution section is required')
    blocks = re.findall(
        r"^cat > llm-security-control-plane/guided-labs/h19-incident-investigation/investigation.py <<'EOF'\n(.*?)^EOF$",
        parts[1], re.MULTILINE | re.DOTALL)
    if len(blocks) != 1:
        raise ValueError('one complete investigation.py heredoc is required')
    return blocks[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--starter', action='store_true')
    parser.add_argument('--expected-failure')
    parser.add_argument('--markdown', action='store_true')
    parser.add_argument('--tcp-verifier', action='store_true')
    parser.add_argument('--browser-python', type=Path)
    args = parser.parse_args()
    if args.browser_python and not args.tcp_verifier:
        parser.error('--browser-python requires --tcp-verifier')
    expect_complete = not (args.starter or args.expected_failure)
    original = args.source.read_bytes()
    source = extract_solution(original.decode('utf-8')).encode('utf-8') if args.markdown else original
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    project = 'guided-p19-implementation-' + uuid.uuid4().hex[:10]
    compose = ['docker', 'compose', '-p', project,
               '-f', 'tests/e2e/compose.p18-products.yaml',
               '-f', 'tests/e2e/compose.p19-products.yaml',
               '-f', 'tests/e2e/compose.p19-implementation.yaml']
    with tempfile.TemporaryDirectory(prefix='guided-p19-build-') as temporary:
        context = Path(temporary)
        destination = context / RELATIVE
        destination.mkdir(parents=True)
        for filename in FILES:
            shutil.copy2(ROOT / 'llm-security-control-plane' / RELATIVE / filename, destination / filename)
        (destination / 'investigation.py').write_bytes(source)
        image = 'localhost/' + project + ':test'
        env = {**os.environ, 'P19_BUILD_CONTEXT': temporary, 'P19_TEST_IMAGE': image}
        verifier_name = project + '-verifier'
        verifier_started = False
        ui_containers = []
        browser_network = None
        verifier_image = 'localhost/guided-verifier-p19:check'
        try:
            subprocess.run(compose + ['up', '-d', '--build', 'loki', 'tempo', 'alloy', 'p19'],
                           cwd=ROOT, env=env, check=True)
            if args.tcp_verifier:
                verifier_image = 'localhost/' + verifier_name + ':test'
                subprocess.run(['docker', 'build', '-f', 'guided-evidence-verifier/Containerfile',
                                '-t', verifier_image, '.'],
                               cwd=ROOT / 'llm-security-control-plane', check=True)
                required = re.findall(r'os.environ\["([A-Z0-9_]+)"\]',
                    (ROOT / 'llm-security-control-plane/guided-evidence-verifier/server.py').read_text())
                verifier_env = {name: 'publisher-test-unused' for name in required}
                verifier_env.update(GUIDED_CONTROL_VERIFIER_TOKEN='publisher-test-control',
                                    GUIDED_VERIFIER_H19_TOKEN='publisher-test-verifier',
                                    GUIDED_H19_URL='http://p19:8000')
                start = ['docker', 'run', '-d', '--name', verifier_name,
                         '--network', project + '_default', '--network-alias', 'verifier',
                         '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                         '--tmpfs', '/tmp', '--tmpfs', '/state:uid=65532,gid=65532']
                for key, value in verifier_env.items():
                    start.extend(['-e', key + '=' + value])
                subprocess.run(start + [verifier_image], check=True)
                verifier_started = True
            verifier_option = ('P19_HTTP_VERIFIER_URL=http://verifier:8000' if args.tcp_verifier
                               else 'P19_HTTP_VERIFIER_SOURCE=/app/server.py')
            command = ['docker', 'run', '--rm', '--network', project + '_default',
                       '--read-only', '--tmpfs', '/tmp', '--user', f'{os.getuid()}:{os.getgid()}',
                       '-e', verifier_option,
                       '--entrypoint', 'python', '-w', '/workspace',
                       '-v', f'{ROOT}:/workspace:ro', '-v', f'{output}:/evidence:rw',
                       verifier_image, '-B',
                       'tests/e2e/run_guided_p19_http.py', '/evidence/implementation.json']
            if expect_complete:
                command.append('--expect-complete')
            elif args.expected_failure:
                command.extend(['--expected-failure', args.expected_failure])
            subprocess.run(command, cwd=ROOT, check=True)
            evidence = json.loads((output / 'implementation.json').read_text())
            digest = hashlib.sha256(source).hexdigest()
            assert evidence['build']['source_digest'] == digest
            assert evidence['receipt']['source_digest'] == digest
            assert evidence['http_verification']['task_completed'] is expect_complete
            if args.starter:
                assert all(row['execution_status'] == 'not_implemented'
                           for row in evidence['receipt']['analysis_executions'])
            proof = {'project': project, 'source_sha256': digest, 'image': image,
                     'image_id': subprocess.check_output(
                         ['docker', 'image', 'inspect', '--format', '{{.Id}}', image], text=True).strip(),
                     'scope': evidence['scope'], 'task_completed': expect_complete,
                     'verifier_image_id': subprocess.check_output(
                         ['docker', 'image', 'inspect', '--format', '{{.Id}}', verifier_image], text=True).strip(),
                     'runner_inputs': {name: hashlib.sha256((destination / name).read_bytes()).hexdigest()
                                       for name in FILES}}
            if args.markdown:
                proof['markdown_sha256'] = hashlib.sha256(original).hexdigest()
            if args.browser_python:
                # Publish only the proxy; product and learner services remain internal.
                browser_network = project + '-browser'
                subprocess.run(['docker', 'network', 'create', browser_network], check=True)
                # Ask the OS for an unused loopback port; Docker still fails safely on a race.
                with socket.socket() as listener:
                    listener.bind(('127.0.0.1', 0))
                    port = listener.getsockname()[1]
                origin = f'http://127.0.0.1:{port}'
                ui_images = {}
                for role in ('control-center', 'front-proxy'):
                    ui_image = 'localhost/' + project + '-' + role + ':test'
                    subprocess.run(['docker', 'build', '-f', f'guided-{role}/Containerfile',
                                    '-t', ui_image, '.'], cwd=ROOT / 'llm-security-control-plane', check=True)
                    ui_images[role] = subprocess.check_output(
                        ['docker', 'image', 'inspect', '--format', '{{.Id}}', ui_image], text=True).strip()
                    name = project + '-' + role
                    launch = ['docker', 'run', '-d', '--name', name, '--network', project + '_default',
                              '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                              '--tmpfs', '/tmp:rw,noexec,nosuid,size=32m']
                    if role == 'control-center':
                        launch += ['--network-alias', 'guided-control-center']
                        required = re.findall(r'os.environ\["([A-Z0-9_]+)"\]',
                            (ROOT / 'llm-security-control-plane/guided-control-center/server.py').read_text())
                        ui_env = {name: 'publisher-test-unused' for name in required}
                        ui_env.update(GUIDED_CONTROL_H19_TOKEN='publisher-test-control',
                                      GUIDED_CONTROL_VERIFIER_TOKEN='publisher-test-control',
                                      GUIDED_H19_URL='http://p19:8000', GUIDED_VERIFIER_URL='http://verifier:8000',
                                      GUIDED_ALLOWED_HOSTS=f'127.0.0.1:{port}', GUIDED_ALLOWED_ORIGINS=origin)
                        for key, value in ui_env.items():
                            launch += ['-e', key + '=' + value]
                    else:
                        launch += ['--network', browser_network,
                                   '-p', f'127.0.0.1:{port}:18097', '--tmpfs',
                                   '/var/cache/nginx:rw,noexec,nosuid,size=16m,uid=101,gid=101,mode=0700']
                    subprocess.run(launch + [ui_image], check=True)
                    ui_containers.append(name)
                # Preserve a virtualenv interpreter symlink and its installed browser packages.
                browser_command = [str(args.browser_python.absolute()), 'tests/browser/check_guided_p19_live.py',
                                   origin, str(output / 'browser.json'), '--source-digest', digest]
                if not expect_complete:
                    browser_command.append('--incomplete')
                subprocess.run(browser_command, cwd=ROOT, check=True)
                proof['browser'] = {'scope': 'live proxy and service path', 'images': ui_images}
            (output / 'build.json').write_text(json.dumps(proof, indent=2))
            print(json.dumps(proof), flush=True)
        finally:
            try:
                for name in reversed(ui_containers):
                    subprocess.run(['docker', 'rm', '-f', name], check=True)
                if browser_network:
                    subprocess.run(['docker', 'network', 'rm', browser_network], check=True)
                if verifier_started:
                    subprocess.run(['docker', 'rm', '-f', verifier_name], check=True)
            finally:
                subprocess.run(compose + ['down'], cwd=ROOT, env=env, check=True)


if __name__ == '__main__':
    main()
