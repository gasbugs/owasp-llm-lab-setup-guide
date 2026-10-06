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
if name=='git':
    args=args[2:]
    failure=os.environ.get('PREPARATION_FAILURE')
    marker=Path(os.environ['PREPARATION_GIT_HEAD'])
    if args==['rev-parse','--show-toplevel']: print(os.environ['PREPARATION_SETUP_ROOT'])
    elif args==['symbolic-ref','--quiet','--short','HEAD']:
        if failure=='detached': sys.exit(1)
        print('topic' if failure=='branch' else 'main')
    elif args[:2]==['diff','--quiet'] and failure=='dirty': sys.exit(4)
    elif args==['rev-parse','HEAD']: print('new-head' if marker.exists() else 'old-head')
    elif args[0]=='fetch' and failure=='fetch': sys.exit(5)
    elif args[0]=='merge-base' and failure=='diverged': sys.exit(6)
    elif args[0]=='merge' and failure=='refresh' and not marker.exists():
        marker.touch()
        script=Path(os.environ['PREPARATION_SCRIPT'])
        script.write_text(script.read_text().replace('set -euo pipefail', 'set -euo pipefail\n echo latest-script-executed',1))
if name=='aws':
    if os.environ.get('PREPARATION_FAILURE')=='aws': sys.exit(9)
    if args[:2]==['bedrock-agent','get-knowledge-base']: print('ACTIVE')
if name=='docker':
    if 'build' in args and os.environ.get('PREPARATION_FAILURE')=='build': sys.exit(8)
    if args[:2]==['ps','-aq']:
        if not (os.environ.get('PREPARATION_FAILURE')=='foreign' and 'network=llm-security-control-plane' in args):
            print('owned-container-id')
    if args[:2]==['rm','-f'] and os.environ.get('PREPARATION_FAILURE')=='remove': sys.exit(7)
if name=='curl':
    if any('/.well-known/login' in arg for arg in args):
        print(json.dumps({'expires_in':300 if os.environ.get('PREPARATION_FAILURE')=='ttl' else 3600,
            'token_type':'Bearer','access_token':'test-login-token-never-display'}))
    elif 'policy' in args[-1]:
        print(json.dumps({'guard_mode':'prevent' if os.environ.get('PREPARATION_FAILURE')=='policy' else 'detection',
            'assurance_profile':'high-assurance','presidio_failure_mode':'closed',
            'main_task':{'id':'account-security-support-v1'}}))
    else: print('{"ok":true}')
if name=='jq':
    value=json.load(sys.stdin)
    if any('.expires_in' in arg for arg in args):
        sys.exit(0 if value.get('expires_in')==3600 and value.get('token_type')=='Bearer' and value.get('access_token') else 1)
    valid=value.get('ok') is True if '.ok == true' in args else (
        value.get('guard_mode')=='detection' and value.get('assurance_profile')=='high-assurance'
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
        for name in ('git', 'aws', 'docker', 'curl', 'jq'):
            tool=self.bin/name;tool.write_text(FAKE_TOOL);tool.chmod(0o755)
        self.calls = self.work / 'calls.jsonl'
        self.env = os.environ | {'HOME':str(self.home), 'PATH':str(self.bin)+':'+os.environ['PATH'],
            'PREPARATION_CALLS':str(self.calls), 'PREPARATION_GIT_HEAD':str(self.work/'git-head'),
            'PREPARATION_SETUP_ROOT':str(self.root.parent), 'PREPARATION_SCRIPT':str(self.script), 'GUARD_MODE':'prevent', 'LEGACY_STATIC_TOKEN_MODE':'true',
            'BEDROCK_GATEWAY_TOKEN':'old-ambient-token'}

    def run_script(self, *args, failure='', answer='y\n'):
        return subprocess.run(['bash', str(self.script), *args], env=self.env | {'PREPARATION_FAILURE':failure},
            text=True, capture_output=True, input=answer)

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
        self.assertIn('평가 환경 준비 결과',second.stdout)
        self.assertIn('서비스: 4개 시작 및 health 확인 완료',second.stdout)
        self.assertIn('[8/8]',second.stdout)
        self.assertIn('mode=detection profile=high-assurance', second.stdout)
        self.assertIn('JWT 인증·인가·Bedrock 자체 안전 기능 유지', second.stdout)
        self.assertEqual(values['AUTH_ACCESS_TTL_SECONDS'], '3600')
        self.assertNotIn('test-login-token-never-display', first.stdout+second.stdout+second.stderr)
        self.assertIn('실제 발급 확인 완료', second.stdout)
        self.assertEqual(values['GUARD_MODE'], 'detection')
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
                self.assertIn('[ERR] 준비 중단:',result.stderr)

    def test_remove_failure_does_not_rotate_state(self):
        self.seed_old_state()
        self.assertNotEqual(self.run_script(failure='remove').returncode,0)
        self.assertTrue((self.root/'.state/application-auth/key').exists())

    def test_knowledge_base_argument_does_not_import_old_secrets(self):
        result=self.run_script('--knowledge-base-id','ABCDEF1234')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('MODULE08_KNOWLEDGE_BASE_ID=ABCDEF1234',
            (self.root/'.state/module08-compose.env').read_text())

    def test_foreign_network_name_collision_preserves_every_resource(self):
        self.seed_old_state()
        result=self.run_script(failure='foreign')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('다른 network',result.stderr)
        self.assertTrue((self.root/'.state/application-auth/key').exists())
        self.assertFalse(any(r[:3]==['docker','rm','-f'] or 'build' in r or 'up' in r for r in self.records()))

    def test_confirmation_cancels_before_any_external_call(self):
        self.seed_old_state()
        for answer in ('n\n','\n','Y\n','yes\n',''):
            with self.subTest(answer=answer):
                result=self.run_script(answer=answer)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertIn('취소했습니다',result.stdout)
                self.assertTrue(all(r[0]=='git' for r in self.records()))
                self.assertTrue((self.root/'.state/application-auth/key').exists())

    def test_invalid_argument_has_no_external_calls(self):
        for args in [('--knowledge-base-id',),('--knowledge-base-id','bad;command'),('--unknown',)]:
            with self.subTest(args=args):
                self.assertEqual(self.run_script(*args).returncode,2)
        self.assertEqual(self.records(),[])

    def test_latest_script_reexec_preserves_arguments_and_single_confirmation(self):
        result=self.run_script('--knowledge-base-id','ABCDEF1234',failure='refresh')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('latest-script-executed',result.stdout)
        self.assertEqual(result.stdout.count('계속하려면 y'),1)
        self.assertIn('MODULE08_KNOWLEDGE_BASE_ID=ABCDEF1234',
            (self.root/'.state/module08-compose.env').read_text())
        self.assertIn('Setup 버전: new-head',result.stdout)

    def test_pinned_detached_checkout_can_use_latest_version(self):
        result=self.run_script(failure='detached',answer='n\n')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('최신 setup 확인 완료',result.stdout)
        self.assertIn('취소했습니다',result.stdout)

    def test_update_failures_preserve_resources_before_confirmation(self):
        self.seed_old_state()
        for failure in ('fetch','dirty','diverged','branch'):
            with self.subTest(failure=failure):
                self.calls.unlink(missing_ok=True)
                result=self.run_script(failure=failure)
                self.assertNotEqual(result.returncode,0)
                self.assertNotIn('계속하려면 y',result.stdout)
                self.assertTrue(all(r[0]=='git' for r in self.records()))
                self.assertTrue((self.root/'.state/application-auth/key').exists())

    def test_wrong_token_lifetime_never_reports_ready(self):
        result=self.run_script(failure='ttl')
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn('evaluation-environment=READY',result.stdout)

    def test_wrong_policy_never_reports_ready(self):
        result=self.run_script(failure='policy')
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn('evaluation-environment=READY',result.stdout)


if __name__ == '__main__':
    unittest.main()
