"""Publisher-owned verifier/UI containers attached to one isolated product project."""
from contextlib import ExitStack
import re
import socket
import subprocess


class LiveStack:
    def __init__(self, root, project, activity, learner_url, additional_activities=None):
        if not re.fullmatch(r'guided-p\d+-check-[a-f0-9]{10}', project):
            raise ValueError('only a generated publisher project may be managed')
        if not re.fullmatch(r'H\d{2}', activity):
            raise ValueError('invalid activity')
        self.root, self.project, self.activity = root, project, activity
        self.learner_url = learner_url
        self.activities = {activity: learner_url, **(additional_activities or {})}
        if any(not re.fullmatch(r'H\d{2}', name) for name in self.activities):
            raise ValueError('invalid additional activity')
        self.cleanup = ExitStack()
        self.images = {}

    def close(self):
        self.cleanup.close()

    def required_env(self, role):
        source = (self.root / 'llm-security-control-plane' / f'guided-{role}/server.py').read_text()
        return {name: 'publisher-test-unused' for name in re.findall(r'os.environ\["([A-Z0-9_]+)"\]', source)}

    def launch(self, role, image, env, extra=()):
        name = self.project + '-' + role
        command = ['docker', 'run', '-d', '--name', name, '--network', self.project + '_default',
                   '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                   '--tmpfs', '/tmp:rw,noexec,nosuid,size=32m', *extra]
        for key, value in env.items():
            command += ['-e', key + '=' + value]
        subprocess.run(command + [image], check=True)
        self.cleanup.callback(subprocess.run, ['docker', 'rm', '-f', name], check=True)
        self.images[role] = subprocess.check_output(
            ['docker', 'image', 'inspect', '--format', '{{.Id}}', image], text=True).strip()

    def start_verifier(self, image, extra_env=None):
        env = self.required_env('evidence-verifier')
        env.update(GUIDED_CONTROL_VERIFIER_TOKEN='publisher-test-control')
        for activity, url in self.activities.items():
            env['GUIDED_VERIFIER_' + activity + '_TOKEN'] = 'publisher-test-verifier'
            env['GUIDED_' + activity + '_URL'] = url
        env.update(extra_env or {})
        self.launch('verifier', image, env, ['--network-alias', 'verifier',
                    '--tmpfs', '/state:uid=65532,gid=65532'])

    def start_browser(self, extra_env=None):
        network = self.project + '-browser'
        subprocess.run(['docker', 'network', 'create', network], check=True)
        self.cleanup.callback(subprocess.run, ['docker', 'network', 'rm', network], check=True)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        origin = f'http://127.0.0.1:{port}'
        for role in ('control-center', 'front-proxy'):
            image = 'localhost/' + self.project + '-' + role + ':test'
            subprocess.run(['docker', 'build', '-f', f'guided-{role}/Containerfile', '-t', image, '.'],
                           cwd=self.root / 'llm-security-control-plane', check=True)
            if role == 'control-center':
                env = self.required_env(role)
                env.update(GUIDED_CONTROL_VERIFIER_TOKEN='publisher-test-control',
                           GUIDED_VERIFIER_URL='http://verifier:8000',
                           GUIDED_ALLOWED_HOSTS=f'127.0.0.1:{port}', GUIDED_ALLOWED_ORIGINS=origin)
                for activity, url in self.activities.items():
                    env['GUIDED_CONTROL_' + activity + '_TOKEN'] = 'publisher-test-control'
                    env['GUIDED_' + activity + '_URL'] = url
                env.update(extra_env or {})
                extra = ['--network-alias', 'guided-control-center']
            else:
                env = {}
                # Only the proxy joins a non-internal network for loopback publishing.
                extra = ['--network', network, '-p', f'127.0.0.1:{port}:18097', '--tmpfs',
                         '/var/cache/nginx:rw,noexec,nosuid,size=16m,uid=101,gid=101,mode=0700']
            self.launch(role, image, env, extra)
        return origin
