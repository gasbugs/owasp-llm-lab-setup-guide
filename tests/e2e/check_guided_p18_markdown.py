"""Build the exact Markdown P18 solution and grade it against real products.

Publisher-only: no Markdown shell evaluation, AWS credentials, or existing course
project changes. Optional live Browser publishes only an isolated loopback proxy.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[2]
INPUTS = (
    'guided-labs/h18-product-queries/Containerfile',
    'guided-labs/h18-product-queries/request_workflow.py',
    'guided-labs/observability/server.py',
    'guided-labs/observability/query_execution.py',
)
QUERY = 'guided-labs/h18-product-queries/queries.yaml'


def extract_solution(document):
    parts = re.split(r'^## \d+\. 풀이.*$', document, flags=re.MULTILINE)
    if len(parts) != 2:
        raise ValueError('one numbered solution section is required')
    solutions = re.findall(
        r"^cat > llm-security-control-plane/guided-labs/h18-product-queries/queries.yaml <<'EOF'\n(.*?)^EOF$",
        parts[1], re.MULTILINE | re.DOTALL)
    if len(solutions) != 1:
        raise ValueError('one complete queries.yaml heredoc is required')
    return solutions[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('markdown', type=Path, nargs='?')
    parser.add_argument('--source', type=Path, help='Publisher query fixture, outside the Starter image')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--tcp-verifier', action='store_true')
    parser.add_argument('--browser-python', type=Path)
    parser.add_argument('--starter', action='store_true')
    args = parser.parse_args()
    if bool(args.markdown) == bool(args.source):
        parser.error('select exactly one Markdown or --source query file')
    if args.browser_python and not args.tcp_verifier:
        parser.error('--browser-python requires --tcp-verifier')
    from guided_live_stack import LiveStack
    document = args.markdown.read_text(encoding='utf-8') if args.markdown else None
    solution = ((ROOT / 'llm-security-control-plane' / QUERY).read_text()
                if args.starter else args.source.read_text() if args.source else extract_solution(document))
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    project = 'guided-p18-check-' + uuid.uuid4().hex[:10]
    live = LiveStack(ROOT, project, 'H18', 'http://p18:8000')
    verifier_image = 'localhost/' + project + '-verifier:test'
    compose = ['docker', 'compose', '-p', project,
               '-f', 'tests/e2e/compose.p18-products.yaml',
               '-f', 'tests/e2e/compose.p18-markdown.yaml']
    with tempfile.TemporaryDirectory(prefix='guided-p18-build-') as temporary:
        context = Path(temporary)
        for relative in INPUTS:
            target = context / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / 'llm-security-control-plane' / relative, target)
        (context / QUERY).write_text(solution, encoding='utf-8')
        env = {**os.environ, 'P18_BUILD_CONTEXT': temporary,
               'P18_TEST_IMAGE': 'localhost/' + project + ':test', 'P18_VERIFY_IMAGE': verifier_image}
        try:
            subprocess.run(compose + ['up', '-d', '--build'], cwd=ROOT, env=env, check=True)
            subprocess.run(['docker', 'build', '-f', 'guided-evidence-verifier/Containerfile',
                            '-t', verifier_image, '.'], cwd=ROOT / 'llm-security-control-plane', check=True)
            if args.tcp_verifier:
                live.start_verifier(verifier_image)
            subprocess.run(compose + [
                'run', '--rm', '--user', f'{os.getuid()}:{os.getgid()}',
                '-v', f'{output}:/evidence', '-e', 'P18_EVIDENCE_PATH=/evidence/markdown.json',
                '-e', 'P18_HTTP_VERIFIER_URL=' + ('http://verifier:8000' if args.tcp_verifier else ''),
                '-e', 'P18_EXPECT_COMPLETED=' + ('false' if args.starter else 'true'),
                '-e', 'P18_QUIET=true', 'verify'], cwd=ROOT, env=env, check=True)
            evidence = json.loads((output / 'markdown.json').read_text())
            expected = hashlib.sha256(solution.encode()).hexdigest()
            assert evidence['receipt']['source_digest'] == expected, 'mounted/built query differs from Markdown'
            assert evidence['verification']['task_completed'] is (not args.starter)
            if args.browser_python:
                origin = live.start_browser()
                command = [str(args.browser_python.absolute()), 'tests/browser/check_guided_p18_live.py',
                           origin, str(output / 'browser.json'), '--source-digest', expected]
                if args.starter:
                    command.append('--incomplete')
                subprocess.run(command, cwd=ROOT, check=True)
            proof = {'markdown_sha256': hashlib.sha256(document.encode()).hexdigest() if document else None,
                     'query_sha256': expected, 'suite_id': evidence['receipt']['suite_id'],
                     'project': project, 'runner_inputs': {
                         path: hashlib.sha256((context / path).read_bytes()).hexdigest() for path in INPUTS},
                     'learner_image_id': subprocess.check_output(['docker', 'image', 'inspect',
                         '--format', '{{.Id}}', env['P18_TEST_IMAGE']], text=True).strip(),
                     'live_images': live.images, 'starter': args.starter,
                     'browser': bool(args.browser_python),
                     'scope': 'P18 image + actual products + ' + ('TCP verifier' if args.tcp_verifier else 'verifier TestClient') + '; no AWS'}
            (output / 'markdown-build.json').write_text(json.dumps(proof, indent=2), encoding='utf-8')
            print(json.dumps(proof, ensure_ascii=False), flush=True)
        finally:
            try:
                live.close()
            finally:
                subprocess.run(compose + ['down'], cwd=ROOT, env=env, check=True)


if __name__ == '__main__':
    main()
