"""Exercise destructive preparation boundaries without touching real containers."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / 'llm-security-control-plane/deploy/prepare-evaluation-environment.sh'
FAKE_TOOL = r'''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
name=Path(sys.argv[0]).name
args=sys.argv[1:]
with open(os.environ['PREPARATION_CALLS'], 'a') as log:
    log.write(json.dumps([name]+args)+'\n')
if name=='aws':
    if os.environ.get('PREPARATION_FAILURE')=='aws': sys.exit(9)
    if args[:2]==['bedrock-agent','get-knowledge-base']: print('ACTIVE')
if name=='docker':
    if 'build' in args and os.environ.get('PREPARATION_FAILURE')=='build': sys.exit(8)
    if args[:2]==['ps','-aq']: print('owned-container-id')
    if args[:2]==['rm','-f'] and os.environ.get('PREPARATION_FAILURE')=='remove': sys.exit(7)
if name=='curl':
    if 'policy' in args[-1]:
        print(json.dumps({'guard_mode':'audit' if os.environ.get('PREPARATION_FAILURE')=='policy' else 'enforce',
            'assurance_profile':'high-assurance','presidio_failure_mode':'closed',
            'main_task':{'id':'account-security-support-v1'}}))
    else: print('{"ok":true}')
if name=='jq':
    value=json.load(sys.stdin)
    valid=value.get('ok') is True if '.ok == true' in args else (
        value.get('guard_mode')=='enforce' and value.get('assurance_profile')=='high-assurance'
        and value.get('presidio_failure_mode')=='closed'
        and value.get('main_task',{}).get('id')=='account-security-support-v1')
    sys.exit(0 if valid else 1)
'''


class EvaluationPreparationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='evaluation-preparation-')
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.root = self.work / 'setup/llm-security-control-plane'
        (self.root / 'deploy').mkdir(parents=True)
        self.script = self.root / 'deploy/prepare-evaluation-environment.sh'
        shutil.copy2(SCRIPT, self.script)
        (self.root / 'deploy/restore-module08-aws.sh').write_text(
            '#!/usr/bin/env bash\nset -eu\n'
            'test "${PREPARATION_FAILURE:-}" != kb\n'
            'mkdir -p "$MODULE08_AWS_STATE_DIR"\n'
            'printf "MODULE08_KNOWLEDGE_BASE_ID=AUTO123456\\n" > "$MODULE08_AWS_STATE_DIR/module08-aws.env"\n')
        self.home = self.work / 'home'
        (self.home / '.aws').mkdir(parents=True)
        (self.home / '.aws/credentials').write_text('untouched AWS fixture')
        self.bin = self.work / 'bin'
        self.bin.mkdir()
        for name in ('aws', 'docker', 'curl', 'jq'):
            tool=self.bin/name;tool.write_text(FAKE_TOOL);tool.chmod(0o755)
        self.calls = self.work / 'calls.jsonl'
        self.env = os.environ | {'HOME':str(self.home), 'PATH':str(self.bin)+':'+os.environ['PATH'],
            'PREPARATION_CALLS':str(self.calls), 'GUARD_MODE':'off', 'LEGACY_STATIC_TOKEN_MODE':'true',
            'BEDROCK_GATEWAY_TOKEN':'old-ambient-token'}

    def run_script(self, *args, failure=''):
        return subprocess.run(['bash', str(self.script), *args], env=self.env | {'PREPARATION_FAILURE':failure},
            text=True, capture_output=True)

    def records(self):
        return [json.loads(line) for line in self.calls.read_text().splitlines()] if self.calls.exists() else []

    def seed_old_state(self):
        (self.root / '.state/application-auth').mkdir(parents=True, exist_ok=True)
        (self.root / '.state/application-auth/key').write_text('previous signing key')
        (self.root / '.state/module08-compose.env').write_text(f"$(touch '{self.work / 'never-execute-old-env'}')\n")

    def test_first_start_and_restart_rotate_keys_without_exposing_tokens(self):
        first = self.run_script()
        self.assertEqual(first.returncode, 0, first.stderr)
        env_file = self.root / '.state/module08-compose.env'
        old = env_file.read_text()
        self.seed_old_state()
        second = self.run_script()
        self.assertEqual(second.returncode, 0, second.stderr)
        values = dict(line.split('=',1) for line in env_file.read_text().splitlines())
        self.assertEqual(env_file.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(values['BEDROCK_GATEWAY_TOKEN'], first.stdout+second.stdout+second.stderr)
        self.assertNotIn(values['BEDROCK_GATEWAY_TOKEN'], old)
        self.assertEqual(values['GUARD_MODE'], 'enforce')
        self.assertEqual(values['LEGACY_STATIC_TOKEN_MODE'], 'false')
        self.assertEqual(values['MODULE08_KNOWLEDGE_BASE_ID'], 'AUTO123456')
        self.assertEqual(list((self.root / '.state/application-auth').iterdir()), [])
        saved = list((self.root.parent / '.state').glob('control-plane-backup-*'))
        self.assertEqual((saved[0]/'application-auth/key').read_text(), 'previous signing key')
        self.assertEqual((self.home / '.aws/credentials').read_text(), 'untouched AWS fixture')
        self.assertFalse((self.work / 'never-execute-old-env').exists())
        removed = {r[3] for r in self.records() if r[:3]==['docker','rm','-f']}
        self.assertEqual(removed, {'llm-security-application-gateway','llm-security-nemo-hub',
            'llm-security-presidio-spoke','llm-security-bedrock-gateway',
            'llm-security-nemo-dialog-rails','guardrails-presidio-api'})

    def test_preflight_and_build_failure_preserve_old_state_and_containers(self):
        self.seed_old_state()
        for failure in ('aws','build','kb'):
            with self.subTest(failure=failure):
                self.calls.unlink(missing_ok=True)
                result=self.run_script(failure=failure)
                self.assertNotEqual(result.returncode,0)
                self.assertEqual((self.root/'.state/application-auth/key').read_text(),'previous signing key')
                self.assertFalse(any(r[:3]==['docker','rm','-f'] for r in self.records()))
                self.assertNotIn('evaluation-environment=READY',result.stdout)

    def test_remove_failure_does_not_rotate_state(self):
        self.seed_old_state()
        self.assertNotEqual(self.run_script(failure='remove').returncode,0)
        self.assertTrue((self.root/'.state/application-auth/key').exists())

    def test_knowledge_base_argument_does_not_import_old_secrets(self):
        result=self.run_script('--knowledge-base-id','ABCDEF1234')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('MODULE08_KNOWLEDGE_BASE_ID=ABCDEF1234',
            (self.root/'.state/module08-compose.env').read_text())

    def test_invalid_argument_has_no_external_calls(self):
        for args in [('--knowledge-base-id',),('--knowledge-base-id','bad;command'),('--unknown',)]:
            with self.subTest(args=args):
                self.assertEqual(self.run_script(*args).returncode,2)
        self.assertEqual(self.records(),[])

    def test_wrong_policy_never_reports_ready(self):
        result=self.run_script(failure='policy')
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn('evaluation-environment=READY',result.stdout)


if __name__ == '__main__':
    unittest.main()
