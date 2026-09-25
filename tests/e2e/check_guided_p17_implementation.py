"""Build one isolated P17 implementation using the original Containerfile."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import uuid
from p17_faults import FAILURES, inject
from p17_markdown import extract_solution
from guided_live_stack import LiveStack

ROOT = Path(__file__).resolve().parents[2]
RELATIVE = Path('guided-labs/h17-telemetry')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--markdown', action='store_true')
    parser.add_argument('--tcp-verifier', action='store_true')
    parser.add_argument('--browser-python', type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--starter', action='store_true')
    mode.add_argument('--fault', choices=FAILURES)
    args = parser.parse_args()
    if args.markdown and (args.starter or args.fault):
        parser.error('--markdown cannot be combined with --starter or --fault')
    if args.browser_python and not args.tcp_verifier:
        parser.error('--browser-python requires --tcp-verifier')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    source = args.source.read_bytes()
    if args.markdown:
        source = extract_solution(source.decode()).encode()
    if args.fault:
        source = inject(source.decode(), args.fault).encode()
    project = 'guided-p17-check-' + uuid.uuid4().hex[:10]
    compose = ['docker', 'compose', '-p', project, '-f', 'tests/e2e/compose.p18-products.yaml',
               '-f', 'tests/e2e/compose.p17-products.yaml']
    with tempfile.TemporaryDirectory(prefix='guided-p17-build-') as temporary:
        destination = Path(temporary) / RELATIVE
        destination.mkdir(parents=True)
        for name in ('Containerfile', 'server.py', 'runner.py', 'workflow.py'):
            shutil.copy2(ROOT / 'llm-security-control-plane' / RELATIVE / name, destination / name)
        (destination / 'instrumentation.py').write_bytes(source)
        image = 'localhost/' + project + ':test'
        verifier_image = 'localhost/' + project + '-verifier:test'
        env = {**os.environ, 'P17_BUILD_CONTEXT': temporary, 'P17_TEST_IMAGE': image}
        live = LiveStack(ROOT, project, 'H17', 'http://p17:8000')
        try:
            subprocess.run(['docker', 'build', '-f', 'guided-evidence-verifier/Containerfile',
                            '-t', verifier_image, '.'], cwd=ROOT / 'llm-security-control-plane', check=True)
            subprocess.run(compose + ['up', '-d', '--build', 'loki', 'tempo', 'alloy', 'prometheus', 'p17'],
                           cwd=ROOT, env=env, check=True)
            if args.tcp_verifier:
                live.start_verifier(verifier_image)
            verifier_url = 'http://verifier:8000' if args.tcp_verifier else ''
            command = ['docker', 'run', '--rm', '--network', project + '_default', '--read-only',
                       '--tmpfs', '/tmp', '--user', f'{os.getuid()}:{os.getgid()}',
                       '-e', 'P17_HTTP_VERIFIER_URL=' + verifier_url,
                       '-v', f'{ROOT}:/workspace:ro', '-v', f'{output}:/evidence:rw', '-w', '/workspace',
                       '--entrypoint', 'python', verifier_image, '-B',
                       'tests/e2e/run_guided_p17_products.py', '/evidence/products.json']
            if args.starter:
                command.append('--starter')
            if args.fault:
                command.extend(['--fault', args.fault])
            subprocess.run(command, cwd=ROOT, check=True)
            proof = json.loads((output / 'products.json').read_text())
            digest = hashlib.sha256(source).hexdigest()
            assert proof['build']['source_digest'] == digest
            if args.browser_python:
                origin = live.start_browser()
                command = [str(args.browser_python.absolute()), 'tests/browser/check_guided_p17_live.py',
                           origin, str(output / 'browser.json'), '--source-digest', digest]
                if args.starter or args.fault:
                    command.append('--incomplete')
                subprocess.run(command, cwd=ROOT, check=True)
            (output / 'build.json').write_text(json.dumps({
                'source_sha256': digest, 'project': project, 'image': image,
                'verifier_image_id': subprocess.check_output(['docker', 'image', 'inspect', '--format', '{{.Id}}', verifier_image], text=True).strip(),
                'image_id': subprocess.check_output(['docker', 'image', 'inspect', '--format', '{{.Id}}', image], text=True).strip(),
                'scope': proof['scope'], 'live_images': live.images,
                'browser': bool(args.browser_python)}))
        finally:
            try:
                live.close()
            finally:
                subprocess.run(compose + ['down'], cwd=ROOT, env=env, check=True)


if __name__ == '__main__':
    main()
