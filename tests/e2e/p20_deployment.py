"""Isolate the operating P20 Compose subset without changing storage/security options."""
import copy
import json
import os
from pathlib import Path
import re
import subprocess

NAMES = {'guided-h20-alerts': 'p20', 'guided-h20-prometheus': 'prometheus',
         'guided-h20-alertmanager': 'alertmanager', 'guided-h20-grafana': 'grafana',
         'guided-h20-grafana-reader': 'reader'}


def isolate(document, project, context):
    if not re.fullmatch(r'guided-p20-check-[a-f0-9]{10}', project):
        raise ValueError('only a fresh publisher project is allowed')
    result = {'name': project, 'services': {}, 'volumes': {},
              'networks': {'default': {'internal': True}}}
    for original, name in NAMES.items():
        service = copy.deepcopy(document['services'][original])
        if service.get('secrets'):
            raise ValueError('unexpected secret mount in P20 subset')
        service.pop('container_name', None)
        service.pop('ports', None)
        service['networks'] = {'default': {'aliases': [original]}}
        if 'build' in service:
            service['build']['context'] = str(context)
            service['image'] = 'localhost/' + project + '-' + ('app' if name == 'p20' else name) + ':test'
        if 'depends_on' in service:
            service['depends_on'] = {NAMES[key]: value for key, value in service['depends_on'].items()}
        for mount in service.get('volumes', []):
            if mount['type'] == 'volume':
                source = mount['source']
                if not source.startswith('guided-h20-'):
                    raise ValueError('P20 cannot inherit another activity volume')
                # Drop the rendered global name, assigning a new project-owned Docker volume.
                result['volumes'][source] = {}
            elif mount['type'] != 'bind' or not mount.get('read_only'):
                raise ValueError('unexpected writable host mount')
        result['services'][name] = service
    return result


def prepare(root, temporary, project):
    original = root / 'examples/security-monitoring/compose.guided.yaml'
    readme = (root / 'llm-security-control-plane/README.md').read_text()
    blocks = re.findall(r'cat > llm-security-control-plane/\.state/guided-course\.env <<EOF\n(.*?)\nEOF', readme, re.S)
    if len(blocks) != 1:
        raise ValueError('documented bootstrap env missing')
    names = set(re.findall(r'^([A-Z][A-Z0-9_]*)=', blocks[0], re.M))
    required = set(re.findall(r'\$\{(\w+):\?', original.read_text()))
    if required - names:
        raise ValueError('README is missing Compose environment names')
    values = {name: 'publisher-test-unused' for name in names}
    values.update(GUIDED_CONTROL_H20_TOKEN='publisher-test-control',
                  GUIDED_VERIFIER_H20_TOKEN='publisher-test-verifier',
                  GUIDED_H20_WEBHOOK_TOKEN='publisher-test-webhook',
                  GUIDED_P20_GRAFANA_ADMIN_PASSWORD='publisher-test-grafana',
                  GUIDED_P20_GRAFANA_PASSWORD='publisher-test-reader',
                  LOCAL_UID=str(os.getuid()), LOCAL_GID=str(os.getgid()))
    env_file = temporary / 'deployment.env'
    env_file.write_text(''.join(f'{key}={value}\n' for key, value in sorted(values.items())))
    env_file.chmod(0o600)
    env = {key: value for key, value in os.environ.items() if not key.startswith(('GUIDED_', 'AWS_', 'COMPOSE_'))}
    rendered = subprocess.run(['docker', 'compose', '--env-file', str(env_file), '-f', str(original),
                              'config', '--format', 'json'], env=env, capture_output=True, text=True, timeout=30)
    if rendered.returncode:
        raise ValueError('operating Compose render failed; environment values suppressed')
    document = isolate(json.loads(rendered.stdout), project, temporary)
    compose_file = temporary / 'deployment.json'
    compose_file.write_text(json.dumps(document))
    return ['docker', 'compose', '--env-file', str(env_file), '-p', project, '-f', str(compose_file)], env
