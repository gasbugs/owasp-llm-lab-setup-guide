"""P03 durable suite runner; records attempts and never assigns a course verdict.

Workflow.prepare_suite must use the control-only Gateway boundary. It receives
only case/execution mappings, not learner-provided job IDs or resource settings.
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
from pydantic import BaseModel, ConfigDict, Field

from cases import CONTRACT_VERSION, cases as default_cases
from workflow import LifecycleError

RUNNER_FILES = ("aws_auth.py", "native_runtime.py", "cases.py", "execution.py", "service_client.py", "workflow.py", "run_server.py", "requirements.txt", "Containerfile")


class Run(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suite_id: UUID


class Search(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: str = Field(min_length=1, max_length=1000)


def create_app(*, workflow, tokens, database, source_root=None, now=time.time):
    if (set(tokens) != {"control", "verifier"} or len(set(tokens.values())) != 2
            or any(not isinstance(value, str) or not value or not value.isascii() for value in tokens.values())):
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
        db.execute("CREATE TABLE IF NOT EXISTS p03_runs (suite_id TEXT PRIMARY KEY, receipt TEXT NOT NULL)")

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
            db.execute("UPDATE p03_runs SET receipt=? WHERE suite_id=?", (raw, receipt["suite_id"]))

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

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
            raise HTTPException(503, "P03 build unavailable") from None

    @app.get("/v1/receipts/{suite_id}")
    def receipt(suite_id: str, authorization: str | None = Header(default=None)):
        require("verifier", authorization)
        with connect() as db:
            row = db.execute("SELECT receipt FROM p03_runs WHERE suite_id=?", (suite_id,)).fetchone()
        if row is None:
            raise HTTPException(404, "P03 execution not found")
        return json.loads(row["receipt"])

    @app.post("/v1/search")
    def search(request: Search, authorization: str | None = Header(default=None)):
        require("control", authorization)
        if not request.query.strip():
            raise HTTPException(422, "검색어를 입력하세요.")
        if not lock.acquire(blocking=False):
            raise HTTPException(409, "P03 execution already running")
        try:
            baseline, suite = build(), str(uuid4())
            mapping = [{"case_id": case["case_id"], "execution_id": str(uuid4())} for case in cases]
            workflow.prepare_suite(suite_id=suite, executions=deepcopy(mapping), timeout=30)
            execution = workflow.run_case(root / "learner.py", suite_id=suite,
                execution_id=mapping[0]["execution_id"], runner_digest=baseline["runner_digest"],
                timeout=75, query=request.query.strip())
            return {"practice_id": "P03", "graded": False, "query": request.query.strip(), "execution": execution}
        except LifecycleError as exc:
            if exc.status == 409:
                raise HTTPException(409, "검색 미실행 — AWS 자원의 준비 기록이 없습니다. AWS 자원 준비를 완료한 뒤 다시 검색하세요.") from None
            raise HTTPException(502, "검색 준비 단계에서 실패했습니다. Gateway 연결과 자원 상태를 확인하세요.") from None
        finally:
            lock.release()

    @app.post("/v1/run")
    def run(request: Run, authorization: str | None = Header(default=None)):
        require("control", authorization)
        if not lock.acquire(blocking=False):
            raise HTTPException(409, "P03 execution already running")
        try:
            suite = str(request.suite_id)
            try:
                baseline, started = build(), stamp()
            except (OSError, ValueError):
                raise HTTPException(503, "P03 build unavailable") from None
            rows = [{"case_id": case["case_id"], "execution_id": str(uuid4()), "execution": None} for case in cases]
            result = {"practice_id": "P03", "activity_id": "H03", "contract_version": CONTRACT_VERSION,
                      "suite_id": suite, "started_at": started, "finished_at": None, "run_state": "running",
                      "build": baseline, "cases": rows}
            try:
                with connect() as db:
                    db.execute("INSERT INTO p03_runs VALUES(?,?)", (suite, json.dumps(result)))
            except sqlite3.IntegrityError:
                raise HTTPException(409, "P03 suite already exists") from None
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
                if build() != baseline:
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
            os.environ["GUIDED_H03_GATEWAY_TOKEN"], native_sdk=True,
        ),
        tokens={"control": os.environ["GUIDED_CONTROL_LAB03_TOKEN"],
                "verifier": os.environ["GUIDED_VERIFIER_LAB03_TOKEN"]},
        database=os.getenv("GUIDED_H03_DATABASE", "/tmp/p03-receipts.sqlite3"),
    )
