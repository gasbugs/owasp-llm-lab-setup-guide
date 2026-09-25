"""P02 HTTP runner and durable suite receipts. Learner source is never imported here."""
from copy import deepcopy
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import threading
import time
from uuid import UUID, uuid4

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict

from cases import CONTRACT_VERSION, cases as default_cases

RUNNER_FILES = ("cases.py", "execution.py", "service_client.py", "workflow.py", "run_server.py", "requirements.txt", "Containerfile")


class Run(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suite_id: UUID


def create_app(*, workflow, tokens, database, source_root=None, cases=None, now=time.time):
    if (set(tokens) != {"control", "verifier"} or len(set(tokens.values())) != 2
            or any(not isinstance(v, str) or not v or not v.isascii() for v in tokens.values())):
        raise ValueError("distinct runner credentials required")
    tokens = dict(tokens)
    cases = deepcopy(default_cases() if cases is None else cases)
    if (not isinstance(cases, list) or not 1 <= len(cases) <= 32
            or any(set(case) != {"case_id", "valid", "body"} or not isinstance(case["case_id"], str)
                   or not case["case_id"] or type(case["valid"]) is not bool for case in cases)
            or len({case["case_id"] for case in cases}) != len(cases)):
        raise ValueError("bounded server-owned contract required")
    contract_raw = json.dumps(cases, ensure_ascii=False, sort_keys=True, allow_nan=False).encode()
    if len(contract_raw) > 131072:
        raise ValueError("contract size limit")
    contract_digest = hashlib.sha256(contract_raw).hexdigest()
    root = Path(source_root or Path(__file__).parent)
    path = Path(database)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = threading.Lock()

    def connect():
        db = sqlite3.connect(path, timeout=10)
        db.row_factory = sqlite3.Row
        return db

    with connect() as db:
        db.execute("CREATE TABLE IF NOT EXISTS p02_runs (suite_id TEXT PRIMARY KEY, receipt TEXT NOT NULL)")

    def build():
        files = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in RUNNER_FILES}
        return {"source_digest": hashlib.sha256((root / "learner.py").read_bytes()).hexdigest(),
                "runner_digest": hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest(),
                "runner_files": files, "contract_digest": contract_digest}

    def require(role, authorization):
        scheme, _, value = (authorization or "").partition(" ")
        if scheme.lower() != "bearer" or not value.isascii() or not hmac.compare_digest(value, tokens[role]):
            raise HTTPException(401, "invalid runner credential")

    def save(receipt):
        raw = json.dumps(receipt, ensure_ascii=False, allow_nan=False)
        with connect() as db:
            db.execute("UPDATE p02_runs SET receipt=? WHERE suite_id=?", (raw, receipt["suite_id"]))

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
        return build()

    @app.get("/v1/receipts/{suite_id}")
    def receipt(suite_id: str, authorization: str | None = Header(default=None)):
        require("verifier", authorization)
        with connect() as db:
            row = db.execute("SELECT receipt FROM p02_runs WHERE suite_id=?", (suite_id,)).fetchone()
        if row is None:
            raise HTTPException(404, "P02 execution not found")
        return json.loads(row["receipt"])

    @app.post("/v1/run")
    def run(request: Run, authorization: str | None = Header(default=None)):
        require("control", authorization)
        if not lock.acquire(blocking=False):
            raise HTTPException(409, "P02 execution already running")
        try:
            suite = str(request.suite_id)
            baseline = build()
            rows = [{"case_id": case["case_id"], "execution_id": str(uuid4()), "execution": None} for case in cases]
            result = {"practice_id": "P02", "activity_id": "H02", "contract_version": CONTRACT_VERSION,
                      "suite_id": suite, "started_at": now(), "finished_at": None, "run_state": "running",
                      "build": baseline, "cases": rows}
            try:
                with connect() as db:
                    db.execute("INSERT INTO p02_runs VALUES(?,?)", (suite, json.dumps(result)))
            except sqlite3.IntegrityError:
                raise HTTPException(409, "P02 suite already exists") from None
            try:
                deadline = time.monotonic() + 180
                for case, row in zip(cases, rows):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("suite deadline")
                    if build() != baseline:
                        raise ValueError("source changed")
                    row["execution"] = workflow.run_case(root / "learner.py", deepcopy(case["body"]),
                        suite_id=suite, execution_id=row["execution_id"], runner_digest=baseline["runner_digest"],
                        timeout=min(75, remaining))
                    save(result)
                if build() != baseline:
                    raise ValueError("source changed")
                result["run_state"] = "finished"
            except Exception:
                result["run_state"] = "error"
            result["finished_at"] = now()
            try:
                result["final_build"] = build()
            except Exception:
                result["final_build"] = None
                result["run_state"] = "error"
            save(result)
            return result
        finally:
            lock.release()

    return app


def configured_app():
    from workflow import Workflow
    return create_app(workflow=Workflow(os.getenv("GUIDED_GATEWAY_URL", "http://guided-bedrock-gateway:8080"),
                                       os.environ["GUIDED_H02_GATEWAY_TOKEN"]),
                      tokens={"control": os.environ["GUIDED_CONTROL_LAB02_TOKEN"],
                              "verifier": os.environ["GUIDED_VERIFIER_LAB02_TOKEN"]},
                      database=os.getenv("GUIDED_H02_DATABASE", "/tmp/h02-receipts.sqlite3"))
