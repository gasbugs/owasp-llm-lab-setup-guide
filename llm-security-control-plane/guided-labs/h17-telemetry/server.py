"""P17 HTTP boundary. Learner imports and execution never run in this process."""
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid

from fastapi import FastAPI, Header, HTTPException, Response
from pydantic import BaseModel, ConfigDict
import httpx

BASE = Path(__file__).resolve().parent
RUNNER_FILES = ('server.py', 'runner.py', 'workflow.py')


class RunRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    suite_id: str
    started_at: str


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False, allow_nan=False))
    temporary.replace(path)


def execute(source, baseline, timeout=25):
    if source.stat().st_size > 65536:
        return {'closed': False, 'execution_error': 'source_too_large'}
    # The worker may reach the provided collector but receives no service/AWS tokens.
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        process = subprocess.Popen([sys.executable, '-B', str(BASE / 'runner.py')],
            stdin=subprocess.PIPE, stdout=output, stderr=errors, start_new_session=True,
            env={'PATH': '/usr/local/bin:/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE': '1'})
        try:
            process.communicate(json.dumps({'source': str(source), 'baseline': baseline}).encode(), timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
            return {'closed': False, 'execution_error': 'worker_timeout'}
        if process.returncode:
            return {'closed': False, 'execution_error': 'worker_failed'}
        output.seek(0)
        raw = output.read(262145)
        try:
            if len(raw) > 262144:
                raise ValueError('oversized output')
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise ValueError('invalid output')
            return value
        except (ValueError, UnicodeError):
            return {'closed': False, 'execution_error': 'invalid_worker_output'}


def wait_for_scrape(after_ns, timeout=12):
    deadline = time.monotonic() + timeout
    with httpx.Client(timeout=2, trust_env=False) as client:
        while True:
            try:
                response = client.get('http://prometheus:9090/api/v1/query',
                    params={'query': 'timestamp(guided_p17_decisions_total)'})
                response.raise_for_status()
                rows = response.json()['data']['result']
                if (len(rows) == 2 and {r['metric'].get('decision') for r in rows} == {'allow', 'block'}
                        and all(float(r['value'][1]) * 1e9 > after_ns for r in rows)):
                    return time.time_ns()
            except (httpx.HTTPError, ValueError, KeyError, TypeError):
                pass
            if time.monotonic() >= deadline:
                raise TimeoutError('current metric scrape unavailable')
            time.sleep(0.25)


def create_app(control_token=None, verifier_token=None, state=None, source=None, executor=None, sampler=None):
    control = control_token or os.environ['GUIDED_CONTROL_H17_TOKEN']
    verifier = verifier_token or os.environ['GUIDED_VERIFIER_H17_TOKEN']
    state = Path(state or '/state')
    source = Path(source or BASE / 'instrumentation.py')
    executor = executor or execute
    sampler = sampler or wait_for_scrape
    state.mkdir(parents=True, exist_ok=True)
    lock = threading.Lock()
    app = FastAPI(docs_url=None, redoc_url=None)

    def auth(value, expected):
        if not hmac.compare_digest(value or '', f'Bearer {expected}'):
            raise HTTPException(401, 'invalid credential')

    def canonical(value):
        try:
            if str(uuid.UUID(value)) == value:
                return value
        except ValueError:
            pass
        raise HTTPException(422, 'invalid suite ID')

    @app.get('/readyz')
    def ready():
        return {'status': 'ready', 'activity_id': 'P17'}

    @app.get('/metrics')
    def metrics():
        path = state / 'metrics.json'
        value = json.loads(path.read_text())['text'] if path.is_file() else (
            '# HELP guided_p17_decisions_total P17 business decisions\n'
            '# TYPE guided_p17_decisions_total counter\n'
            'guided_p17_decisions_total{decision="allow"} 0\n'
            'guided_p17_decisions_total{decision="block"} 0\n')
        return Response(value, media_type='text/plain; version=0.0.4')

    @app.get('/v1/h17/build-info')
    def build_info(authorization: str | None = Header(None)):
        auth(authorization, verifier)
        return {'source_digest': digest(source),
                'runner_digests': {name: digest(BASE / name) for name in RUNNER_FILES}}

    @app.post('/v1/run/H17')
    def run(body: RunRequest, authorization: str | None = Header(None)):
        auth(authorization, control)
        suite = canonical(body.suite_id)
        try:
            started = datetime.fromisoformat(body.started_at)
            if started.tzinfo is None or not 0 <= (datetime.now(timezone.utc)-started).total_seconds() <= 180:
                raise ValueError('stale suite')
        except ValueError:
            raise HTTPException(422, 'invalid start time')
        if not lock.acquire(blocking=False):
            raise HTTPException(409, 'P17 suite already running')
        try:
            ledger_path = state / f'H17-{suite}-ledger.json'
            try:
                with ledger_path.open('x') as stream:
                    json.dump({'suite_id': suite, 'closed': False}, stream)
            except FileExistsError:
                raise HTTPException(409, 'suite already exists')
            metrics_path = state / 'metrics.json'
            baseline = json.loads(metrics_path.read_text())['values'] if metrics_path.is_file() else {'allow': 0, 'block': 0}
            receipt = {'activity_id': 'P17', 'internal_activity_id': 'H17', 'contract_version': 2,
                       'suite_id': suite, 'started_at': body.started_at,
                       'source_digest': digest(source), 'query_start_ns': time.time_ns(),
                       'counter_before': baseline, 'provider_mode': 'synthetic-notice-store'}
            executed = {'closed': False, 'execution_error': 'not_started'}
            try:
                receipt['query_start_ns'] = sampler(time.time_ns())
                executed = executor(source, baseline)
                if 'counter_values' in executed and 'metrics' in executed:
                    save(metrics_path, {'values': executed['counter_values'], 'text': executed['metrics']})
                    receipt['query_end_ns'] = sampler(time.time_ns())
            except (httpx.HTTPError, TimeoutError, ValueError, OSError) as exc:
                receipt['execution_error'] = type(exc).__name__
            receipt['execution'] = executed
            receipt.setdefault('query_end_ns', time.time_ns())
            save(ledger_path, {'suite_id': suite, 'started_at': body.started_at,
                              'closed': executed.get('closed', False),
                              'cases': [case['ledger'] for case in executed.get('cases', [])]})
            save(state / f'H17-{suite}.json', receipt)
            return receipt
        finally:
            lock.release()

    def read(path):
        if not path.is_file():
            raise HTTPException(404, 'execution not found')
        return json.loads(path.read_text())

    @app.get('/v1/receipts/H17/{suite}')
    def receipt(suite: str, authorization: str | None = Header(None)):
        auth(authorization, verifier)
        return read(state / f'H17-{canonical(suite)}.json')

    @app.get('/v1/h17/ledger/{suite}')
    def ledger(suite: str, authorization: str | None = Header(None)):
        auth(authorization, verifier)
        return read(state / f'H17-{canonical(suite)}-ledger.json')

    return app
