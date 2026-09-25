"""P12 trusted HTTP runner and durable receipts; never imports learner code."""
from copy import deepcopy
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sqlite3
import threading
import time
from uuid import UUID, uuid4

from fastapi import FastAPI, Header, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

FILES = ("Containerfile", "pipeline.py", "execution.py", "service_client.py", "workflow.py", "run_server.py")


class Run(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suite_id: UUID


def create_app(*, workflow, cases, documents, tokens, database, source_root=None, now=time.time):
    if set(tokens) != {"control", "verifier"} or len(set(tokens.values())) != 2:
        raise ValueError("distinct runner credentials required")
    if any(not isinstance(token, str) or not token or not token.isascii() for token in tokens.values()):
        raise ValueError("invalid runner credential")
    if not isinstance(cases, list) or not 1 <= len(cases) <= 32:
        raise ValueError("bounded server-owned cases required")
    ids = []
    for case in cases:
        if (set(case) != {"case_id", "identity", "tenant", "message"}
                or not isinstance(case["case_id"], str) or not re.fullmatch(r"[a-z0-9-]{1,64}", case["case_id"])
                or case["identity"] not in {"reader", "visitor", "invalid"}
                or not isinstance(case["tenant"], str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", case["tenant"])
                or not isinstance(case["message"], str) or not case["message"].strip() or len(case["message"]) > 16000):
            raise ValueError("invalid server-owned case")
        ids.append(case["case_id"])
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate server-owned case")
    cases, documents = deepcopy(cases), deepcopy(documents)
    contract = json.dumps({"cases": cases, "documents": documents}, sort_keys=True, ensure_ascii=False, allow_nan=False)
    if len(contract.encode()) > 131072:
        raise ValueError("oversized case contract")
    contract_digest = hashlib.sha256(contract.encode()).hexdigest()
    root = Path(source_root or Path(__file__).parent)
    path = Path(database)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = threading.Lock()

    def connect():
        db = sqlite3.connect(path, timeout=10)
        db.row_factory = sqlite3.Row
        return db

    with connect() as db:
        db.execute("CREATE TABLE IF NOT EXISTS p12_runs (suite_id TEXT PRIMARY KEY, receipt TEXT NOT NULL)")

    def build():
        files = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in FILES}
        return {"files": files, "source_digest": hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest(),
                "contract_digest": contract_digest}

    baseline = build()

    def unchanged():
        if build() != baseline:
            raise ValueError("runner or learner source changed")

    def require(role, authorization):
        scheme, _, value = (authorization or "").partition(" ")
        if scheme.lower() != "bearer" or not hmac.compare_digest(value.encode(), tokens[role].encode()):
            raise HTTPException(401, "invalid runner credential")

    def save(receipt):
        raw = json.dumps(receipt, ensure_ascii=False, allow_nan=False)
        if len(raw.encode()) > 2 * 1024 * 1024:
            raise ValueError("receipt size limit")
        with connect() as db:
            db.execute("UPDATE p12_runs SET receipt=? WHERE suite_id=?", (raw, receipt["suite_id"]))

    app = FastAPI(title="P12 pipeline runner", docs_url=None, redoc_url=None, openapi_url=None)

    @app.exception_handler(RequestValidationError)
    async def invalid(_request, _exc):
        return JSONResponse(status_code=422, content={"detail": "invalid request fields"})

    @app.get("/readyz")
    def ready():
        return {"status": "ready", "component": "p12-runner"}

    @app.get("/v1/build-info")
    def build_info(authorization: str | None = Header(default=None)):
        require("verifier", authorization)
        return {"practice_id": "P12", "contract_version": 2, "build": baseline, "current_build": build(), "case_ids": ids}

    @app.get("/v1/receipts/{suite_id}")
    def read_receipt(suite_id: UUID, authorization: str | None = Header(default=None)):
        require("verifier", authorization)
        with connect() as db:
            row = db.execute("SELECT receipt FROM p12_runs WHERE suite_id=?", (str(suite_id),)).fetchone()
        if not row:
            raise HTTPException(404, "receipt not found")
        return json.loads(row["receipt"])

    @app.post("/v1/run")
    def run(body: Run, authorization: str | None = Header(default=None)):
        require("control", authorization)
        if not lock.acquire(blocking=False):
            raise HTTPException(409, "another P12 run is active")
        try:
            try:
                unchanged()
            except Exception:
                raise HTTPException(503, "execution source changed") from None
            receipt = {"practice_id": "P12", "execution_id": "H12", "contract_version": 2,
                       "suite_id": str(body.suite_id), "started_at": now(), "finished_at": None,
                       "run_state": "running", "build": baseline, "cases": []}
            try:
                with connect() as db:
                    db.execute("INSERT INTO p12_runs VALUES(?,?)", (receipt["suite_id"], json.dumps(receipt)))
            except sqlite3.IntegrityError:
                raise HTTPException(409, "suite already recorded") from None
            try:
                deadline = time.monotonic() + 600
                for case in cases:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("suite time budget reached")
                    unchanged()
                    attempt = {"case_id": case["case_id"], "suite_id": str(uuid4()), "execution_id": str(uuid4()),
                               "started_at": now(), "finished_at": None, "lifecycle": None}
                    receipt["cases"].append(attempt)
                    save(receipt)  # Persist IDs before any downstream side effect.
                    attempt["lifecycle"] = workflow.run_case(root / "pipeline.py", suite_id=attempt["suite_id"],
                        execution_id=attempt["execution_id"], documents=deepcopy(documents),
                        **{key: case[key] for key in ("identity", "tenant", "message")})
                    attempt["finished_at"] = now()
                    save(receipt)
                    unchanged()
                    lifecycle = attempt["lifecycle"]
                    if (lifecycle["suite_id"] != attempt["suite_id"] or lifecycle["execution_id"] != attempt["execution_id"]
                            or lifecycle["lifecycle_status"] != "finished"):
                        raise ValueError("lifecycle incomplete")
                    execution = lifecycle["execution"]
                    if execution["source_digest"] != baseline["files"]["pipeline.py"]:
                        raise ValueError("executed source mismatch")
                receipt["run_state"] = "finished"
            except Exception:
                receipt["run_state"] = "error"
            receipt["finished_at"] = now()
            save(receipt)
            return {key: receipt[key] for key in ("suite_id", "run_state", "started_at", "finished_at")}
        finally:
            lock.release()

    return app


def configured_app(*, environment=None, contract_path="/app/contracts/p12.json"):
    """Production factory: fixed packaged cases, problem-owned service credentials."""
    from workflow import Workflow

    env = dict(os.environ if environment is None else environment)
    raw = Path(contract_path).read_bytes()
    if len(raw) > 131072:
        raise ValueError("oversized P12 contract")
    contract = json.loads(raw)
    if (contract.get("format") != "CUSTOM FILE" or contract.get("practice_id") != "P12"
            or contract.get("execution_id") != "H12" or contract.get("contract_version") != 2):
        raise ValueError("invalid packaged P12 contract")
    specifications = contract["specifications"]
    if not isinstance(specifications, list) or not 8 <= len(specifications) <= 32:
        raise ValueError("incomplete packaged P12 contract")
    origins = {name: env.get(f"GUIDED_P12_{name.upper()}_URL", default) for name, default in {
        "context": "http://guided-p12-context:8000", "privacy": "http://guided-p12-privacy:8000",
        "nemo": "http://guided-p12-nemo:8000", "gateway": "http://guided-bedrock-gateway:8080"}.items()}
    credentials = {name: {role: env.get(f"GUIDED_P12_{name.upper()}_{role.upper()}_TOKEN", "")
        for role in (("control",) if name == "gateway" else ("control", "service"))} for name in origins}
    workflow = Workflow(origins, credentials)
    return create_app(workflow=workflow, cases=[item["input"] for item in specifications],
        documents=contract["documents"], tokens={"control": env.get("GUIDED_CONTROL_LAB12_TOKEN", ""),
        "verifier": env.get("GUIDED_VERIFIER_LAB12_TOKEN", "")},
        database=env.get("GUIDED_H12_DATABASE", "/state/receipts.sqlite3"))
