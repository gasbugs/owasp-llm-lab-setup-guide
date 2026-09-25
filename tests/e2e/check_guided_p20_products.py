"""Build a P20-only product stack; reference answers stay in publisher context."""
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
from p20_deployment import prepare as prepare_deployment
from p20_faults import FAULTS, apply_fault
from p20_markdown import extract_solution

ROOT = Path(__file__).resolve().parents[2]
RELATIVE = Path('guided-labs/h20-alert-dashboard')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--alternative', action='store_true')
    parser.add_argument('--server-run', action='store_true')
    parser.add_argument('--starter', action='store_true')
    parser.add_argument('--tcp-verifier', action='store_true')
    parser.add_argument('--browser-python', type=Path)
    parser.add_argument('--deployment', action='store_true')
    parser.add_argument('--fault', choices=FAULTS)
    parser.add_argument('--markdown', type=Path)
    args = parser.parse_args()
    if args.markdown and (args.starter or args.alternative or args.fault):
        parser.error('--markdown cannot be combined with another source variant')
    if args.fault and (not args.tcp_verifier or args.starter or args.alternative or args.deployment or args.browser_python):
        parser.error('--fault requires --server-run --tcp-verifier without other variants')
    if args.starter and (not args.server_run or args.alternative):
        parser.error('--starter requires --server-run and cannot use --alternative')
    if args.tcp_verifier and not args.server_run:
        parser.error('--tcp-verifier requires --server-run')
    if args.browser_python and not args.tcp_verifier:
        parser.error('--browser-python requires --tcp-verifier')
    if args.deployment and (not args.tcp_verifier or args.browser_python or args.starter):
        parser.error('--deployment requires --tcp-verifier and a complete non-Browser implementation')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    project = 'guided-p20-check-' + uuid.uuid4().hex[:10]
    verifier_files = [ROOT / 'llm-security-control-plane/guided-evidence-verifier' / name
                      for name in ('server.py', 'p20_results.py', 'p20_verification.py', 'p20_binding.py')]
    verifier_digests = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in verifier_files}
    compose = ['docker', 'compose', '-p', project, '-f', 'tests/e2e/compose.p20-products.yaml']
    with tempfile.TemporaryDirectory(prefix='guided-p20-products-') as temp:
        destination = Path(temp) / RELATIVE
        shutil.copytree(ROOT / 'llm-security-control-plane' / RELATIVE, destination)
        dashboard = json.loads((destination / 'dashboard.json').read_text())
        if not args.starter:
            shutil.copy2(ROOT / 'tests/e2e/fixtures/p20/rules.yaml', destination / 'rules.yaml')
            dashboard['panels'][0]['targets'][0]['expr'] = 'sum by (decision) (guided_p20_decisions_total{practice="P20"})'
        if args.alternative:
            rules = destination / 'rules.yaml'
            rules.write_text(rules.read_text().replace('sum(increase(', 'sum(rate('))
            dashboard['panels'][0]['targets'][0]['expr'] = (
                'sum without (instance, job, practice) (guided_p20_decisions_total{practice="P20"})')
        (destination / 'dashboard.json').write_text(json.dumps(dashboard, ensure_ascii=False))
        if args.markdown:
            document = args.markdown.read_text(encoding='utf-8')
            for name, source in extract_solution(document).items():
                (destination / name).write_text(source, encoding='utf-8')
        if args.fault:
            apply_fault(destination, args.fault)
            (output / 'fault-inputs.json').write_text(json.dumps({
                'fault': args.fault,
                'files': {name: (destination / name).read_text()
                          for name in ('rules.yaml', 'dashboard.json', 'alertmanager.yaml')},
                'mutator_sha256': hashlib.sha256(Path(__file__).with_name('p20_faults.py').read_bytes()).hexdigest(),
            }, indent=2))
        env = {**os.environ, 'P20_BUILD_CONTEXT': temp, 'P20_TEST_PREFIX': 'localhost/' + project,
               'GUIDED_H20_WEBHOOK_TOKEN': 'publisher-test-webhook'}
        if args.deployment:
            compose, env = prepare_deployment(ROOT, Path(temp), project)
        def run(*arguments, **kwargs):
            return subprocess.run(compose + list(arguments), cwd=ROOT, env=env, **kwargs)
        live = LiveStack(ROOT, project, 'H20', 'http://p20:8000')
        try:
            run('build', check=True)
            checked = run('run', '--rm', '--entrypoint', '/bin/promtool', 'prometheus',
                          'check', 'rules', '/etc/prometheus/p20-rules.yml', capture_output=True, text=True)
            (output / 'promtool.txt').write_text(checked.stdout + checked.stderr)
            checked.check_returncode()
            run('up', '-d', check=True)
            reader_id = run('ps', '--all', '--quiet', 'reader', check=True, capture_output=True, text=True).stdout.strip()
            reader_exit = subprocess.check_output(['docker', 'wait', reader_id], text=True, timeout=90).strip()
            if reader_exit != '0':
                raise RuntimeError('P20 Grafana Viewer preparation failed')
            run('run', '--rm', '--no-deps', 'reader', check=True, timeout=90)
            subprocess.run(['docker', 'run', '--rm', '--network', project + '_default',
                '--read-only', '--tmpfs', '/tmp', '--user', f'{os.getuid()}:{os.getgid()}',
                '-v', f'{ROOT}:/workspace:ro', '-v', f'{output}:/evidence:rw', '-w', '/workspace',
                '--entrypoint', 'python', 'localhost/guided-practice-tests:check', '-B',
                'tests/e2e/check_p20_reader_permissions.py', '/evidence/reader-permissions.json'], check=True)
            if args.tcp_verifier:
                verifier_image = 'localhost/' + project + '-verifier:test'
                subprocess.run(['docker', 'build', '-f', 'guided-evidence-verifier/Containerfile',
                                '-t', verifier_image, '.'], cwd=ROOT / 'llm-security-control-plane', check=True)
                live.start_verifier(verifier_image, {
                    'GUIDED_P20_PROMETHEUS_URL': 'http://prometheus:9090',
                    'GUIDED_P20_GRAFANA_URL': 'http://grafana:3000',
                    'GUIDED_P20_GRAFANA_USER': 'p20-reader', 'GUIDED_P20_GRAFANA_PASSWORD': 'publisher-test-reader'})
            if args.browser_python:
                origin = live.start_browser()
                artifacts = {name: hashlib.sha256((destination / name).read_bytes()).hexdigest()
                             for name in ('rules.yaml', 'dashboard.json')}
                digest = hashlib.sha256(json.dumps(artifacts, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
                subprocess.run([str(args.browser_python.absolute()), 'tests/browser/check_guided_p20_live.py',
                    origin, str(output / 'browser.json'), '--source-digest', digest,
                    *(['--incomplete'] if args.starter else [])], cwd=ROOT, check=True)
            else:
                subprocess.run(['docker', 'run', '--rm', '--network', project + '_default',
                    '--read-only', '--tmpfs', '/tmp', '--user', f'{os.getuid()}:{os.getgid()}',
                    '-v', f'{ROOT}:/workspace:ro', '-v', f'{output}:/evidence:rw', '-w', '/workspace',
                    '--entrypoint', 'python', 'localhost/guided-practice-tests:check', '-B',
                    'tests/e2e/run_guided_p20_server.py' if args.server_run else 'tests/e2e/run_guided_p20_products.py',
                    '/evidence/products.json', *(['--starter'] if args.starter else []),
                    *(['--fault', args.fault] if args.fault else []),
                    *(['--tcp-verifier'] if args.tcp_verifier else [])], check=True)
            if args.deployment:
                def deployed_instances():
                    instances = {}
                    for name in ('p20', 'prometheus', 'grafana', 'alertmanager'):
                        container_id = run('ps', '--all', '--quiet', name,
                                           check=True, capture_output=True, text=True).stdout.strip()
                        inspected = json.loads(subprocess.check_output(['docker', 'inspect', container_id], text=True))[0]
                        instances[name] = {'id': inspected['Id'],
                            'volumes': {mount['Destination']: mount['Name'] for mount in inspected['Mounts']
                                        if mount['Type'] == 'volume'}}
                    return instances
                previous_instances = deployed_instances()
                run('up', '-d', '--no-deps', '--force-recreate', 'p20', 'prometheus', 'grafana', 'alertmanager', check=True)
                run('run', '--rm', '--no-deps', 'reader', check=True, timeout=90)
                subprocess.run(['docker', 'run', '--rm', '--network', project + '_default',
                    '--read-only', '--tmpfs', '/tmp', '--user', f'{os.getuid()}:{os.getgid()}',
                    '-v', f'{ROOT}:/workspace:ro', '-v', f'{output}:/evidence:rw', '-w', '/workspace',
                    '--entrypoint', 'python', 'localhost/guided-practice-tests:check', '-B',
                    'tests/e2e/check_p20_persisted_state.py', '/evidence'], check=True)
                current_instances = deployed_instances()
                for name in previous_instances:
                    assert previous_instances[name]['id'] != current_instances[name]['id']
                    assert previous_instances[name]['volumes'] == current_instances[name]['volumes']
                (output / 'recreated-containers.json').write_text(json.dumps({
                    'before': previous_instances, 'after': current_instances}, indent=2))
            proof = {'project': project, 'alternative': args.alternative, 'server_run': args.server_run,
                     'starter': args.starter, 'fault': args.fault,
                     'tcp_verifier': args.tcp_verifier, 'live_images': live.images,
                     'verifier_files': verifier_digests,
                     'scope': ('P20 synthetic requests, native products and independent TCP verifier; no Browser/AWS'
                               if args.tcp_verifier else
                               'P20 synthetic requests and actual isolated products; no independent course verifier/Browser/AWS'),
                     'files': {name: hashlib.sha256((destination / name).read_bytes()).hexdigest()
                               for name in ('server.py', 'workflow.py', 'execution.py', 'rules.yaml', 'dashboard.json')},
                     'images': {service: subprocess.check_output(['docker', 'image', 'inspect', '--format', '{{.Id}}',
                                'localhost/' + project + '-' + service + ':test'], text=True).strip()
                                for service in ('app', 'prometheus', 'grafana', 'reader', 'alertmanager')}}
            if args.browser_python:
                proof['scope'] = 'Live Browser/proxy/Control Center/P20/native products/TCP verifier; no AWS'
            if args.markdown:
                proof['markdown_sha256'] = hashlib.sha256(document.encode()).hexdigest()
            if args.deployment:
                proof['scope'] = 'Operating P20 Compose subset, env-file credential, named volumes and recreation; no Browser/AWS'
                proof['deployment_source_sha256'] = hashlib.sha256(
                    (ROOT / 'examples/security-monitoring/compose.guided.yaml').read_bytes()).hexdigest()
            if verifier_digests != {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in verifier_files}:
                raise RuntimeError('verifier source changed during product verification')
            (output / 'build.json').write_text(json.dumps(proof, indent=2))
        except Exception:
            logs = run('logs', '--no-color', capture_output=True, text=True)
            (output / 'failed-product-logs.txt').write_text(logs.stdout + logs.stderr)
            raise
        finally:
            try:
                live.close()
            finally:
                run('down', *(['--volumes'] if args.deployment else []), check=True)


if __name__ == '__main__':
    main()
