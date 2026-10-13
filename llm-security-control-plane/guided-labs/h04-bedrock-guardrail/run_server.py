"""P04 durable suite runner; records attempts and never assigns a course verdict.

Workflow.prepare_suite must use the control-only Gateway boundary. It receives
only case/execution mappings, not learner-provided policy IDs, case bodies or resource settings.
"""
from copy import deepcopy
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import sqlite3
import threading
import time
from uuid import UUID, uuid4

from fastapi import FastAPI, Header, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from cases import CONTRACT_VERSION, cases as default_cases

RUNNER_FILES = ("cases.py", "execution.py", "service_client.py", "workflow.py", "run_server.py", "requirements.txt", "Containerfile")


class Run(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suite_id: UUID


class Chat(BaseModel):
    model_config = ConfigDict(extra="forbid")
    message: str = Field(min_length=1, max_length=1000)


class Step(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suite_id: UUID
    index: int = Field(ge=0, le=26)


class Finish(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suite_id: UUID
    stopped: bool = False


def create_app(*, workflow, tokens, database, source_root=None, now=time.time):
    if (set(tokens) != {"control", "verifier"} or len(set(tokens.values())) != 2
            or any(not isinstance(value, str) or len(value) < 32 or not value.isascii() for value in tokens.values())):
        raise ValueError("distinct runner credentials required")
    tokens = dict(tokens)
    cases = default_cases()
    contract_digest = hashlib.sha256(json.dumps(cases, ensure_ascii=False, sort_keys=True, allow_nan=False).encode()).hexdigest()
    root = Path(source_root or Path(__file__).parent)
    path = Path(database)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = threading.Lock()

    def connect():
        db = sqlite3.connect(path, timeout=10)
        db.row_factory = sqlite3.Row
        return db

    with connect() as db:
        db.execute("CREATE TABLE IF NOT EXISTS p04_runs (suite_id TEXT PRIMARY KEY, receipt TEXT NOT NULL)")

    def build():
        with (root / "learner.py").open("rb") as source:
            raw = source.read(65537)
        if len(raw) > 65536:
            raise ValueError("source size limit")
        files = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in RUNNER_FILES}
        return {"source_digest": hashlib.sha256(raw).hexdigest(), "runner_files": files,
                "runner_digest": hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest(),
                "contract_digest": contract_digest}

    def require(role, authorization):
        scheme, _, value = (authorization or "").partition(" ")
        if scheme.lower() != "bearer" or not value.isascii() or not hmac.compare_digest(value, tokens[role]):
            raise HTTPException(401, "invalid runner credential")

    def stamp():
        value = now()
        if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
            raise ValueError("invalid clock")
        return value

    def save(receipt):
        raw = json.dumps(receipt, ensure_ascii=False, allow_nan=False)
        with connect() as db:
            db.execute("UPDATE p04_runs SET receipt=? WHERE suite_id=?", (raw, receipt["suite_id"]))

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(_request, _error):
        return JSONResponse(status_code=422, content={"detail": "invalid P04 run request"})

    @app.get("/livez")
    def livez():
        return {"status": "alive"}

    @app.get("/readyz")
    def readyz():
        with connect() as db:
            db.execute("SELECT 1")
        return {"status": "ready", "provider_check": "not-run"}

    @app.get("/v1/build-info")
    def build_info(authorization: str | None = Header(default=None)):
        require("verifier", authorization)
        try:
            return build()
        except (OSError, ValueError):
            raise HTTPException(503, "P04 build unavailable") from None

    @app.get("/v1/receipts/{suite_id}")
    def receipt(suite_id: str, authorization: str | None = Header(default=None)):
        require("verifier", authorization)
        with connect() as db:
            row = db.execute("SELECT receipt FROM p04_runs WHERE suite_id=?", (suite_id,)).fetchone()
        if row is None:
            raise HTTPException(404, "P04 execution not found")
        return json.loads(row["receipt"])

    @app.post("/v1/chat")
    def chat(request: Chat, authorization: str | None = Header(default=None)):
        require("control", authorization)
        if not request.message.strip():
            raise HTTPException(422, "질문을 입력하세요.")
        if not lock.acquire(blocking=False):
            raise HTTPException(409, "다른 질문 또는 채점이 진행 중입니다.")
        try:
            baseline, suite, execution_id = build(), str(uuid4()), str(uuid4())
            workflow.prepare_direct(suite_id=suite, execution_id=execution_id, text=request.message)
            execution = workflow.run_case(root / "learner.py", suite_id=suite, execution_id=execution_id,
                runner_digest=baseline["runner_digest"], timeout=75)
            return {"practice_id":"P04", "graded":False, "message":request.message, "execution":execution}
        except Exception as error:
            if getattr(error, "status", None) == 409:
                raise HTTPException(409, "모델 호출 미실행 — AWS Guardrail 준비를 완료하세요.") from None
            raise HTTPException(502, "모델 호출 준비에 실패했습니다. Guardrail 상태를 확인하세요.") from None
        finally:
            lock.release()

    def stored(suite):
        with connect() as db:
            row = db.execute("SELECT receipt FROM p04_runs WHERE suite_id=?", (suite,)).fetchone()
        if row is None:
            raise HTTPException(404, "P04 suite not found")
        return json.loads(row[0])

    @app.post("/v1/start")
    def start(request: Run, authorization: str | None = Header(default=None)):
        require("control", authorization)
        if not lock.acquire(blocking=False):
            raise HTTPException(409, "P04 execution already running")
        try:
            suite, baseline, started = str(request.suite_id), build(), stamp()
            rows = [{"case_id":case["case_id"], "execution_id":str(uuid4()), "execution":None} for case in cases]
            result = {"practice_id":"P04", "activity_id":"H04", "contract_version":CONTRACT_VERSION,
                      "suite_id":suite, "started_at":started, "finished_at":None, "run_state":"running",
                      "build":baseline, "cases":rows}
            with connect() as db:
                for prior in db.execute("SELECT receipt FROM p04_runs"):
                    previous = json.loads(prior[0])
                    if previous["run_state"] == "running" and 0 <= started - previous["started_at"] < 180:
                        raise HTTPException(409,"P04 execution already running")
                db.execute("INSERT INTO p04_runs VALUES(?,?)", (suite,json.dumps(result)))
            try:
                workflow.prepare_suite(suite_id=suite,
                    executions=[{key:row[key] for key in ("case_id","execution_id")} for row in rows],timeout=30)
            except Exception:
                result.update(run_state="error", finished_at=stamp(), final_build=build());save(result)
                raise HTTPException(503,"P04 suite preparation failed") from None
            return {"suite_id":suite, "started_at":started, "cases":[{"case_id":row["case_id"]} for row in rows]}
        finally:
            lock.release()

    @app.post("/v1/step")
    def step(request: Step, authorization: str | None = Header(default=None)):
        require("control",authorization)
        if not lock.acquire(blocking=False):
            raise HTTPException(409,"P04 execution already running")
        try:
            suite = str(request.suite_id); result=stored(suite)
            pending=next((index for index,row in enumerate(result["cases"]) if row["execution"] is None),None)
            remaining=180-(stamp()-result["started_at"])
            if result["run_state"] != "running" or request.index != pending or remaining <= 0 or build() != result["build"]:
                raise HTTPException(409,"P04 next case or build mismatch")
            row=result["cases"][request.index]
            row["execution"]=workflow.run_case(root/"learner.py",suite_id=suite,
                execution_id=row["execution_id"],runner_digest=result["build"]["runner_digest"],timeout=min(75,remaining))
            save(result)
            return {"suite_id":suite,"index":request.index,"case_id":row["case_id"]}
        finally:
            lock.release()

    @app.post("/v1/finish")
    def finish(request: Finish, authorization: str | None = Header(default=None)):
        require("control",authorization)
        if not lock.acquire(blocking=False):
            raise HTTPException(409,"P04 execution already running")
        try:
            suite=str(request.suite_id); result=stored(suite)
            if result["run_state"] != "running":
                raise HTTPException(409,"P04 suite already closed")
            complete=all(row["execution"] is not None for row in result["cases"])
            result.update(run_state="finished" if complete and not request.stopped else "error",
                          finished_at=stamp(),final_build=build())
            save(result)
            return {"suite_id":suite,"run_state":result["run_state"]}
        finally:
            lock.release()

    @app.post("/v1/run")
    def run(request: Run, authorization: str | None = Header(default=None)):
        require("control", authorization)
        if not lock.acquire(blocking=False):
            raise HTTPException(409, "P04 execution already running")
        try:
            suite = str(request.suite_id)
            try:
                baseline, started = build(), stamp()
            except (OSError, ValueError):
                raise HTTPException(503, "P04 build unavailable") from None
            rows = [{"case_id": case["case_id"], "execution_id": str(uuid4()), "execution": None} for case in cases]
            result = {"practice_id": "P04", "activity_id": "H04", "contract_version": CONTRACT_VERSION,
                      "suite_id": suite, "started_at": started, "finished_at": None, "run_state": "running",
                      "build": baseline, "cases": rows}
            try:
                with connect() as db:
                    db.execute("INSERT INTO p04_runs VALUES(?,?)", (suite, json.dumps(result)))
            except sqlite3.IntegrityError:
                raise HTTPException(409, "P04 suite already exists") from None
            deadline = time.monotonic() + 180
            try:
                mapping = [{key: row[key] for key in ("case_id", "execution_id")} for row in rows]
                workflow.prepare_suite(suite_id=suite, executions=deepcopy(mapping), timeout=30)
                for row in rows:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or build() != baseline:
                        raise ValueError("deadline or build changed")
                    row["execution"] = workflow.run_case(root / "learner.py", suite_id=suite,
                        execution_id=row["execution_id"], runner_digest=baseline["runner_digest"], timeout=min(75, remaining))
                    save(result)
                if time.monotonic() >= deadline or build() != baseline:
                    raise ValueError("build changed")
                result["run_state"] = "finished"
            except Exception:
                result["run_state"] = "error"
            try:
                result["finished_at"] = stamp()
                result["final_build"] = build()
                if result["finished_at"] < started:
                    raise ValueError("clock moved backwards")
            except (OSError, ValueError):
                result["final_build"] = None
                result["run_state"] = "error"
            save(result)
            return result
        finally:
            lock.release()

    return app


def configured_app():
    from workflow import Workflow
    return create_app(
        workflow=Workflow(
            os.getenv("GUIDED_BEDROCK_GATEWAY_URL", "http://guided-bedrock-gateway:8080"),
            os.environ["GUIDED_H04_GATEWAY_TOKEN"],
        ),
        tokens={"control": os.environ["GUIDED_CONTROL_LAB04_TOKEN"],
                "verifier": os.environ["GUIDED_VERIFIER_LAB04_TOKEN"]},
        database=os.getenv("GUIDED_H04_DATABASE", "/tmp/p04-receipts.sqlite3"),
    )
