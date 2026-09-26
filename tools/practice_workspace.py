"""Preserve learner files and compare them with a selected running service.

Never builds, starts, grades, replaces learner files, or reads credentials.
Restore means exporting a saved copy into a new directory for manual comparison.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[1]
CONTROL = Path('llm-security-control-plane')
SAVED = CONTROL / '.state/practice-files'
# Public ID -> directory, Compose service, learner-relative file, image path.
ARTIFACTS = {
    'P01': ('h01-bedrock-gateway', 'guided-h01-gateway', [('learner.py', '/app/learner.py')]),
    'P02': ('h02-document-ingestion', 'guided-h02-document-app', [('learner.py', '/app/learner.py')]),
    'P03': ('h03-ingestion-search', 'guided-h03-sync-app', [('learner.py', '/app/learner.py')]),
    'P04': ('h04-bedrock-guardrail', 'guided-h04-guardrail-app', [('learner.py', '/app/learner.py')]),
    'P05': ('h05-nemo-dialog', 'guided-h05-nemo-dialog', [('config/flows.co', '/app/learner/config/flows.co')]),
    'P06': ('h06-nemo-action', 'guided-h06-nemo-action', [('actions.py', '/app/learner/actions.py')]),
    'P07': ('h07-content-safety', 'guided-h07-content-safety', [('config/config.yml', '/app/learner/config/config.yml')]),
    'P08': ('h08-self-check-input', 'guided-h08-self-check-input', [('config/prompts.yml', '/app/learner/config/prompts.yml')]),
    'P09': ('h09-presidio-redaction', 'guided-h09-presidio-redaction', [('policy.py', '/app/learner/policy.py')]),
    'P10': ('h10-self-check-output', 'guided-h10-self-check-output', [('config/prompts.yml', '/app/learner/config/prompts.yml')]),
    'P11': ('h11-rag-provenance', 'guided-h11-rag-provenance', [('policy.py', '/app/learner/policy.py')]),
    'P12': ('h12-application-pipeline', 'guided-h12-application-pipeline', [('pipeline.py', '/app/learner/pipeline.py')]),
    'P13': ('h13-promptfoo', 'guided-h13-promptfoo', [('promptfooconfig.yaml', '/work/promptfooconfig.yaml')]),
    'P14': ('h14-garak', 'guided-h14-garak', [('garak-config.yaml', '/work/garak-config.yaml')]),
    'P15': ('h15-pyrit', 'guided-h15-pyrit', [('attack.py', '/work/attack.py')]),
    'P16': ('h16-policy-promotion', 'guided-h16-policy-promotion', [('policy.py', '/app/policy.py')]),
    'P17': ('h17-telemetry', 'guided-h17-telemetry', [('instrumentation.py', '/app/instrumentation.py')]),
    'P18': ('h18-product-queries', 'guided-h18-queries', [('queries.yaml', '/app/h18.yaml')]),
    'P19': ('h19-incident-investigation', 'guided-h19-investigation', [('investigation.py', '/app/investigation.py')]),
    'P20': ('h20-alert-dashboard', 'guided-h20-alerts', [('rules.yaml', '/app/rules.yaml'), ('dashboard.json', '/app/dashboard.json')]),
    'P21': ('h21-agent-policy', 'guided-h21-host', [('policy.py', '/app/policy.py')]),
    'P22': ('h22-mcp-approval', 'guided-h22-mcp-server', [('server.py', '/app/server.py')]),
}


def bounded_path(root, relative):
    root = root.resolve()
    relative = Path(relative)
    if relative.is_absolute() or '..' in relative.parts:
        raise ValueError('relative path inside the workspace required')
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError('symlink is not a learner file or backup directory')
    return current


def files(problem):
    directory, service, entries = ARTIFACTS[problem]
    return service, [(CONTROL / 'guided-labs' / directory / name, image) for name, image in entries]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def save_copy(root, problem, *, restore=None):
    _, entries = files(problem)
    contents = {}
    if restore:
        if not re.fullmatch(r'[a-f0-9]{32}', restore):
            raise ValueError('use the backup_id printed by backup')
        saved = SAVED / problem / restore
        metadata = json.loads(bounded_path(root, saved / 'manifest.json').read_text())
        expected = {str(path) for path, _ in entries}
        if metadata.get('problem') != problem or not isinstance(metadata.get('files'), dict) or set(metadata['files']) != expected:
            raise ValueError('backup does not match this problem')
        for path, _ in entries:
            data = bounded_path(root, saved / path).read_bytes()
            if digest(data) != metadata['files'][str(path)]:
                raise ValueError('backup file digest mismatch')
            contents[path] = data
    else:
        contents = {path: bounded_path(root, path).read_bytes() for path, _ in entries}
    copy_id = uuid.uuid4().hex
    relative = SAVED / problem / (('restored-' if restore else '') + copy_id)
    destination = bounded_path(root, relative)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination.mkdir(mode=0o700)
    metadata = {'problem': problem, 'files': {str(p): digest(b) for p, b in contents.items()}}
    for path, data in contents.items():
        target = bounded_path(destination, path)
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with target.open('xb') as output:
            output.write(data)
        target.chmod(0o600)
    manifest = destination / 'manifest.json'
    with manifest.open('x') as output:
        json.dump(metadata, output, indent=2)
    manifest.chmod(0o600)
    return {'problem': problem, 'operation': 'restore-copy' if restore else 'backup',
            'backup_id': restore or copy_id, 'directory': str(destination),
            'learner_files_changed': False, 'files': list(metadata['files'])}


def running_status(root, problem, run=subprocess.check_output):
    service, entries = files(problem)
    command = ['docker', 'compose', '--env-file', str(root / CONTROL / '.state/guided-course.env'),
               '--file', str(root / 'examples/security-monitoring/compose.guided.yaml')]
    records = []
    container = None
    try:
        candidate = run(command + ['ps', '-q', service], text=True, stderr=subprocess.DEVNULL, timeout=20).strip()
        if re.fullmatch(r'[a-f0-9]{12,64}', candidate):
            container = candidate
    except (OSError, subprocess.SubprocessError):
        pass
    for path, image_path in entries:
        local = remote = None
        try:
            local = digest(bounded_path(root, path).read_bytes())
            if container:
                output = run(['docker', 'exec', container, 'sha256sum', image_path],
                             text=True, stderr=subprocess.DEVNULL, timeout=20).strip().split()
                if output and re.fullmatch(r'[a-f0-9]{64}', output[0]):
                    remote = output[0]
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
        state = 'unavailable' if local is None or remote is None else 'same' if local == remote else 'different'
        records.append({'file': str(path), 'container_file': image_path,
                        'local_sha256': local, 'running_sha256': remote, 'state': state})
    return {'problem': problem, 'service': service, 'container': container, 'files': records,
            'not_a_grade': True, 'scope': 'learner file bytes only; not loaded policy or application correctness'}


def release_status(root, course, run=subprocess.check_output):
    expected = json.loads(course.read_text()).get('setup_commit')
    if not isinstance(expected, str) or not re.fullmatch(r'[a-f0-9]{40}', expected):
        raise ValueError('course manifest needs an exact setup_commit')
    actual = run(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
    return {'course': str(course), 'expected_setup_commit': expected, 'actual_setup_commit': actual,
            'revision_matches': expected == actual, 'not_a_grade': True,
            'scope': 'Git revision only; learner edits and running images are checked separately'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    sub = parser.add_subparsers(dest='operation', required=True)
    for name in ('backup', 'restore', 'status'):
        child = sub.add_parser(name)
        child.add_argument('problem', choices=ARTIFACTS)
        if name == 'restore':
            child.add_argument('backup_id')
    sub.add_parser('release').add_argument('--course', type=Path, required=True)
    args = parser.parse_args()
    try:
        root = args.root.resolve()
        if args.operation == 'release':
            result = release_status(root, args.course)
        elif args.operation == 'status':
            result = running_status(root, args.problem)
        else:
            result = save_copy(root, args.problem, restore=getattr(args, 'backup_id', None))
        print(json.dumps(result, ensure_ascii=False, indent=2))
        if args.operation == 'status':
            return 3 if any(r['state'] == 'unavailable' for r in result['files']) else 2 if any(r['state'] == 'different' for r in result['files']) else 0
        return 2 if args.operation == 'release' and not result['revision_matches'] else 0
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(json.dumps({'error': type(exc).__name__, 'message': str(exc), 'learner_files_changed': False}))
        return 3


if __name__ == '__main__':
    raise SystemExit(main())
