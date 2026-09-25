"""P20-only request fixture and authenticated notification evidence receiver."""
import hmac
import json
import os
import threading
from pathlib import Path
from typing import Literal
import httpx

from fastapi import FastAPI, Header, HTTPException, Request, Response
from prometheus_client import CollectorRegistry, CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel, ConfigDict
from workflow import Conflict, Workflow


class ExecutionRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    suite_id: str
    started_at: str


class PhaseRequest(ExecutionRequest):
    phase: Literal['prepare', 'normal', 'risk', 'recovery']


class CheckpointRequest(ExecutionRequest):
    name: Literal['normal', 'after_requests']


def create_app(database, control, verifier, webhook, observe_products=None, run_executor=None):
    workflow = Workflow(database, observe_products=observe_products)
    registry = CollectorRegistry()
    registry.register(workflow)
    app = FastAPI(docs_url=None, redoc_url=None)
    run_lock = threading.Lock()

    def auth(actual, expected):
        if not expected or not hmac.compare_digest(actual or '', 'Bearer ' + expected):
            raise HTTPException(401, 'invalid credential')

    @app.get('/readyz')
    def ready():
        return {'status': 'ready'}

    @app.get('/metrics')
    def metrics():
        return Response(generate_latest(registry), media_type=CONTENT_TYPE_LATEST)

    @app.post('/v1/run/H20')
    def run(body: ExecutionRequest, authorization: str | None = Header(None)):
        auth(authorization, control)
        if run_executor is None:
            raise HTTPException(503, 'P20 executor unavailable')
        if not run_lock.acquire(blocking=False):
            raise HTTPException(409, 'P20 run already active')
        try:
            try:
                workflow.claim_run(body.suite_id, body.started_at)
            except Conflict as exc:
                raise HTTPException(409, str(exc))
            except (ValueError, TypeError):
                raise HTTPException(422, 'invalid execution metadata')
            try:
                run_executor(workflow, body.suite_id, body.started_at)
                workflow.finish_run(body.suite_id)
            except (httpx.HTTPError, HTTPException, TimeoutError, ValueError, KeyError, TypeError, OSError, RuntimeError) as exc:
                workflow.finish_run(body.suite_id, type(exc).__name__)
            return workflow.receipt(body.suite_id)
        finally:
            run_lock.release()

    @app.get('/v1/buildinfo')
    def buildinfo(authorization: str | None = Header(None)):
        auth(authorization, verifier)
        return workflow.buildinfo()

    @app.get('/v1/artifacts/{name}')
    def artifact(name: str, authorization: str | None = Header(None)):
        auth(authorization, verifier)
        if name not in ('rules.yaml', 'dashboard.json'):
            raise HTTPException(404, 'unknown learner artifact')
        path = workflow.artifact_dir / name
        if path.stat().st_size > 65536:
            raise HTTPException(413, 'learner artifact too large')
        return Response(path.read_bytes(), media_type='application/octet-stream')

    @app.post('/v1/scenarios')
    def scenario(body: PhaseRequest, authorization: str | None = Header(None)):
        auth(authorization, control)
        try:
            return workflow.run_phase(body.suite_id, body.started_at, body.phase)
        except Conflict as exc:
            raise HTTPException(409, str(exc))
        except (ValueError, TypeError):
            raise HTTPException(422, 'invalid execution metadata')

    @app.get('/v1/receipts/H20/{suite_id}')
    def receipt(suite_id: str, authorization: str | None = Header(None)):
        auth(authorization, verifier)
        try:
            return workflow.receipt(suite_id)
        except KeyError:
            raise HTTPException(404, 'receipt not found')
        except ValueError:
            raise HTTPException(422, 'invalid suite ID')

    @app.post('/v1/observations/close')
    def close(body: ExecutionRequest, authorization: str | None = Header(None)):
        auth(authorization, control)
        try:
            return workflow.close_observation(body.suite_id, body.started_at)
        except Conflict as exc:
            raise HTTPException(409, str(exc))
        except (ValueError, TypeError):
            raise HTTPException(422, 'invalid execution metadata')

    @app.post('/v1/observations/checkpoint')
    def checkpoint(body: CheckpointRequest, authorization: str | None = Header(None)):
        auth(authorization, control)
        try:
            return workflow.mark_checkpoint(body.suite_id, body.started_at, body.name)
        except Conflict as exc:
            raise HTTPException(409, str(exc))
        except (ValueError, TypeError):
            raise HTTPException(422, 'invalid checkpoint metadata')

    @app.post('/v1/notifications')
    async def notification(request: Request, authorization: str | None = Header(None)):
        auth(authorization, webhook)
        raw = bytearray()
        async for chunk in request.stream():
            raw.extend(chunk)
            if len(raw) > 65536:
                raise HTTPException(413, 'notification too large')
        import json
        try:
            workflow.notification(json.loads(raw))
        except (ValueError, TypeError):
            raise HTTPException(422, 'invalid notification')
        return {'stored': True}

    @app.get('/v1/notifications')
    def notifications(start_ns: int, end_ns: int, authorization: str | None = Header(None)):
        auth(authorization, verifier)
        try:
            return workflow.notifications(start_ns, end_ns)
        except ValueError:
            raise HTTPException(422, 'invalid observation window')

    return app


def product_observer(prometheus_url, grafana_url, grafana_auth):
    def observe():
        try:
            result = {}
            with httpx.Client(timeout=3, trust_env=False, follow_redirects=False) as client:
                for key, url, auth in (
                    ('rules', prometheus_url + '/api/v1/rules', None),
                    ('dashboard', grafana_url + '/api/dashboards/uid/guided-p20', grafana_auth),
                ):
                    with client.stream('GET', url, auth=auth) as response:
                        response.raise_for_status()
                        raw = bytearray()
                        for chunk in response.iter_bytes():
                            raw.extend(chunk)
                            if len(raw) > 131072:
                                raise ValueError('product response too large')
                    result[key] = json.loads(raw)
            return result
        except (httpx.HTTPError, ValueError):
            raise HTTPException(503, 'P20 product configuration unavailable') from None
    return observe


def configured_app():
    from functools import partial
    from execution import execute
    return create_app(Path(os.getenv('GUIDED_P20_DATABASE', '/state/p20.sqlite3')),
                      os.environ['GUIDED_CONTROL_H20_TOKEN'], os.environ['GUIDED_VERIFIER_H20_TOKEN'],
                      os.environ['GUIDED_H20_WEBHOOK_TOKEN'], product_observer(
                          os.environ['GUIDED_P20_PROMETHEUS_URL'], os.environ['GUIDED_P20_GRAFANA_URL'],
                          (os.environ['GUIDED_P20_GRAFANA_USER'], os.environ['GUIDED_P20_GRAFANA_PASSWORD'])),
                      partial(execute, prometheus_url=os.environ['GUIDED_P20_PROMETHEUS_URL'],
                              alertmanager_url=os.environ['GUIDED_P20_ALERTMANAGER_URL']))
