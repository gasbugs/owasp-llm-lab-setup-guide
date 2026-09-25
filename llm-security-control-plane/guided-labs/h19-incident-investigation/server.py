"""P19 execution service. Receipts are evidence, never course verdicts."""
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
import threading
import uuid

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict
import httpx

import analysis_inputs
import collection
import execution
import workflow

BASE = Path(__file__).resolve().parent
RUNNER_FILES = ('server.py', 'analysis_inputs.py', 'collection.py', 'execution.py', 'workflow.py')


class RunRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    suite_id: str
    started_at: str


class Signals:
    def __init__(self):
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
        from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
        from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
        resource = Resource.create({'service.name': 'guided-h19-investigation'})
        self.trace_provider = TracerProvider(resource=resource)
        self.trace_provider.add_span_processor(SimpleSpanProcessor(OTLPSpanExporter(endpoint='http://alloy:4318/v1/traces')))
        self.log_provider = LoggerProvider(resource=resource)
        self.log_provider.add_log_record_processor(BatchLogRecordProcessor(OTLPLogExporter(endpoint='http://alloy:4318/v1/logs')))
        self.tracer = self.trace_provider.get_tracer('p19')
        self.logger = logging.Logger('p19-decisions', level=logging.INFO)
        self.logger.addHandler(LoggingHandler(logger_provider=self.log_provider))

    def flush(self):
        return self.trace_provider.force_flush() and self.log_provider.force_flush()

    def close(self):
        self.trace_provider.shutdown()
        self.log_provider.shutdown()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False, allow_nan=False))
    temporary.replace(path)


def create_app(control_token=None, verifier_token=None, state=None, source=None, signals=None):
    control = control_token or os.environ['GUIDED_CONTROL_H19_TOKEN']
    verifier = verifier_token or os.environ['GUIDED_VERIFIER_H19_TOKEN']
    state = Path(state or '/state')
    source = Path(source or BASE / 'investigation.py')
    state.mkdir(parents=True, exist_ok=True)
    lock = threading.Lock()
    signals = signals or Signals()

    @asynccontextmanager
    async def lifespan(app):
        yield
        signals.close()

    app = FastAPI(docs_url=None, redoc_url=None, lifespan=lifespan)

    def auth(value, expected):
        if not hmac.compare_digest(value or '', f'Bearer {expected}'):
            raise HTTPException(401, 'invalid credential')

    def canonical_id(value):
        try:
            if str(uuid.UUID(value)) == value:
                return value
        except ValueError:
            pass
        raise HTTPException(422, 'invalid suite ID')

    @app.get('/readyz')
    def ready():
        return {'status': 'ready', 'activity_id': 'P19'}

    @app.get('/v1/h19/build-info')
    def build_info(authorization: str | None = Header(None)):
        auth(authorization, verifier)
        return {'source_digest': sha(source), 'runner_digests': {name: sha(BASE / name) for name in RUNNER_FILES}}

    @app.post('/v1/run/H19')
    def run(body: RunRequest, authorization: str | None = Header(None)):
        auth(authorization, control)
        suite_id = canonical_id(body.suite_id)
        try:
            started = datetime.fromisoformat(body.started_at)
            if started.tzinfo is None or not 0 <= (datetime.now(timezone.utc) - started).total_seconds() <= 180:
                raise ValueError('stale suite')
        except ValueError:
            raise HTTPException(422, 'invalid start time')
        if not lock.acquire(blocking=False):
            raise HTTPException(409, 'P19 suite already running')
        ledger_path = state / f'H19-{suite_id}-ledger.json'
        try:
            try:
                with ledger_path.open('x') as stream:
                    json.dump({'suite_id': suite_id, 'started_at': body.started_at, 'closed': False}, stream)
            except FileExistsError:
                raise HTTPException(409, 'suite already exists')
            receipt = {'activity_id': 'P19', 'internal_activity_id': 'H19', 'contract_version': 2,
                       'suite_id': suite_id, 'started_at': body.started_at, 'source_digest': sha(source),
                       'provider_mode': 'synthetic-notice-store', 'analysis_executions': []}
            try:
                store = workflow.NoticeStore()
                cases = workflow.run_requests(signals.tracer, signals.logger, store)
                ledger = {'suite_id': suite_id, 'started_at': body.started_at, 'closed': True,
                          'cases': cases, 'downstream_calls': store.calls}
                save(ledger_path, ledger)
                receipt['cases'] = cases
                if not signals.flush():
                    raise TimeoutError('signal export incomplete')
                observed = collection.collect(cases, store.calls)
                receipt.update(observed)
                for case in analysis_inputs.build_inputs(observed['bundle'], [case['request_id'] for case in cases]):
                    result = execution.execute(source, case['bundle'], case['request_id'])
                    receipt['analysis_executions'].append({key: value for key, value in case.items() if key != 'bundle'} | result)
            except (httpx.HTTPError, TimeoutError, ValueError, KeyError, TypeError, OSError, RuntimeError) as exc:
                receipt['execution_error'] = type(exc).__name__
            save(state / f'H19-{suite_id}.json', receipt)
            return receipt
        finally:
            lock.release()

    @app.get('/v1/receipts/H19/{suite_id}')
    def receipt(suite_id: str, authorization: str | None = Header(None)):
        auth(authorization, verifier)
        return read(state / f'H19-{canonical_id(suite_id)}.json')

    @app.get('/v1/h19/ledger/{suite_id}')
    def ledger(suite_id: str, authorization: str | None = Header(None)):
        auth(authorization, verifier)
        return read(state / f'H19-{canonical_id(suite_id)}-ledger.json')

    def read(path):
        if not path.is_file():
            raise HTTPException(404, 'current execution not found')
        return json.loads(path.read_text())

    return app
