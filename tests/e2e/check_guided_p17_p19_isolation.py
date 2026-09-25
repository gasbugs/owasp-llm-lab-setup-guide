"""Run P19 first, then rebuild/break P17 without changing P19 state or grading."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import uuid

from guided_live_stack import LiveStack
from p17_markdown import extract_solution as extract_p17
from check_guided_p19_implementation import extract_solution as extract_p19

ROOT = Path(__file__).resolve().parents[2]
P17 = Path('guided-labs/h17-telemetry')
P19 = Path('guided-labs/h19-incident-investigation')
FILES = {
    P17: ('Containerfile', 'server.py', 'runner.py', 'workflow.py'),
    P19: ('Containerfile', 'server.py', 'workflow.py', 'collection.py', 'execution.py', 'analysis_inputs.py'),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--p17-markdown', type=Path, required=True)
    parser.add_argument('--p19-markdown', type=Path, required=True)
    parser.add_argument('--browser-python', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    project = 'guided-p17-check-' + uuid.uuid4().hex[:10]
    verifier_image = 'localhost/' + project + '-verifier:test'
    compose = ['docker', 'compose', '-p', project]
    for filename in ('compose.p18-products.yaml', 'compose.p17-products.yaml',
                     'compose.p19-products.yaml', 'compose.p19-implementation.yaml'):
        compose += ['-f', 'tests/e2e/' + filename]
    live = LiveStack(ROOT, project, 'H19', 'http://p19:8000', {'H17': 'http://p17:8000'})
    with tempfile.TemporaryDirectory(prefix='guided-p17-p19-isolation-') as temporary:
        context = Path(temporary)
        env = {**os.environ, 'P17_BUILD_CONTEXT': temporary, 'P19_BUILD_CONTEXT': temporary,
               'P17_TEST_IMAGE': 'localhost/' + project + '-p17:test',
               'P19_TEST_IMAGE': 'localhost/' + project + '-p19:test'}

        def compose_run(*arguments, **kwargs):
            return subprocess.run(compose + list(arguments), cwd=ROOT, env=env, **kwargs)

        def prepare(relative, filename, source):
            destination = context / relative
            destination.mkdir(parents=True, exist_ok=True)
            for name in FILES[relative]:
                shutil.copy2(ROOT / 'llm-security-control-plane' / relative / name, destination / name)
            (destination / filename).write_text(source)
            return hashlib.sha256(source.encode()).hexdigest()

        def publisher(command, extra_env=()):
            return subprocess.run(['docker', 'run', '--rm', '--network', project + '_default',
                '--read-only', '--tmpfs', '/tmp', '--user', f'{os.getuid()}:{os.getgid()}',
                '-v', f'{ROOT}:/workspace:ro', '-v', f'{output}:/evidence:rw', '-w', '/workspace',
                *extra_env, '--entrypoint', 'python', verifier_image, '-B', *command],
                cwd=ROOT, check=True)

        def p19_run(phase):
            publisher(['tests/e2e/run_guided_p19_http.py', f'/evidence/{phase}.json', '--expect-complete'],
                      ['-e', 'P19_HTTP_VERIFIER_URL=http://verifier:8000'])
            return json.loads((output / (phase + '.json')).read_text())

        def container_identity(service):
            container = subprocess.check_output(compose + ['ps', '-q', service], cwd=ROOT, env=env, text=True).strip()
            raw = subprocess.check_output(['docker', 'inspect', '--format',
                '{{.Id}} {{.Image}} {{.State.StartedAt}}', container], text=True).strip()
            return raw

        def browser(activity, phase, digest, incomplete=False):
            command = [str(args.browser_python.absolute()), f'tests/browser/check_guided_p{activity}_live.py',
                       origin, str(output / (phase + '-browser.json')), '--source-digest', digest]
            if incomplete:
                command.append('--incomplete')
            subprocess.run(command, cwd=ROOT, check=True)

        proof = {'scope': __doc__ + '; isolated product stack, no AWS or Tenant 02', 'project': project, 'phases': []}
        try:
            # P17 source and image are intentionally absent during the first P19 completion.
            p19_digest = prepare(P19, 'investigation.py', extract_p19(args.p19_markdown.read_text()))
            subprocess.run(['docker', 'build', '-f', 'guided-evidence-verifier/Containerfile',
                            '-t', verifier_image, '.'], cwd=ROOT / 'llm-security-control-plane', check=True)
            compose_run('up', '-d', '--build', 'loki', 'tempo', 'alloy', 'prometheus', 'p19', check=True)
            live.start_verifier(verifier_image)
            origin = live.start_browser()
            initial = p19_run('p19-before-p17')
            baseline = container_identity('p19')
            assert not (context / P17).exists()
            browser('19', 'p19-before-p17', p19_digest)
            proof['phases'].append('P19 completed before P17 existed')

            def preserved(phase):
                assert container_identity('p19') == baseline
                source = context / P19 / 'investigation.py'
                assert hashlib.sha256(source.read_bytes()).hexdigest() == p19_digest
                suite = initial['request']['suite_id']
                # Re-fetch the original receipt after each fault, not a newly generated replacement.
                publisher(['-c',
                    'import httpx,json; from pathlib import Path; '
                    f'r=httpx.get("http://p19:8000/v1/receipts/H19/{suite}", '
                    'headers={"Authorization":"Bearer publisher-test-verifier"},trust_env=False); '
                    'r.raise_for_status(); '
                    f'Path("/evidence/{phase}-preserved.json").write_text(r.text)'])
                assert json.loads((output / (phase + '-preserved.json')).read_text()) == initial['receipt']
                fresh = p19_run(phase)
                assert fresh['build']['source_digest'] == p19_digest
                proof['phases'].append(phase)
                (output / 'isolation.json').write_text(json.dumps(proof, indent=2))

            p17_digest = prepare(P17, 'instrumentation.py', extract_p17(args.p17_markdown.read_text()))
            compose_run('build', 'p17', check=True)
            compose_run('up', '-d', '--no-deps', '--force-recreate', 'p17', check=True)
            browser('17', 'p17-added', p17_digest)
            preserved('p19-after-p17-build')

            broken = 'def observe_request(:\n'
            (context / P17 / 'instrumentation.py').write_text(broken)
            compose_run('build', 'p17', check=True)
            compose_run('up', '-d', '--no-deps', '--force-recreate', 'p17', check=True)
            browser('17', 'p17-syntax-error', hashlib.sha256(broken.encode()).hexdigest(), incomplete=True)
            preserved('p19-with-p17-syntax-error')

            compose_run('stop', 'p17', check=True)
            subprocess.run(['docker', 'restart', project + '-control-center', project + '-verifier'], check=True)
            browser('19', 'p19-after-common-restart', p19_digest)
            preserved('p19-with-p17-stopped')

            containerfile = context / P17 / 'Containerfile'
            containerfile.write_text(containerfile.read_text() + '\nRUN false\n')
            failed_build = compose_run('build', 'p17', capture_output=True, text=True)
            (output / 'intentional-build-failure.txt').write_text(failed_build.stdout + failed_build.stderr)
            assert failed_build.returncode != 0 and 'RUN false' in failed_build.stderr
            preserved('p19-with-p17-build-failure')
            proof.update(p19_container_identity=baseline, p19_source_digest=p19_digest,
                         live_images=live.images, preserved_original_receipt=True)
            (output / 'isolation.json').write_text(json.dumps(proof, indent=2))
            print(json.dumps(proof), flush=True)
        finally:
            try:
                live.close()
            finally:
                compose_run('down', check=True)


if __name__ == '__main__':
    main()
