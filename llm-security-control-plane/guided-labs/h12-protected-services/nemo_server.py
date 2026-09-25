"""P12 NeMo HTTP boundary; model_factory comes from the trusted entrypoint.

No default model, caller-selected provider, or synthetic production fallback exists.
"""
import asyncio
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import time
from typing import Literal
from uuid import UUID

from fastapi import FastAPI, Header, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator


class Register(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suite_id: UUID
    execution_ids: list[UUID] = Field(min_length=1, max_length=32)

    @field_validator("execution_ids")
    @classmethod
    def unique(cls, value):
        if len(set(value)) != len(value):
            raise ValueError("duplicate executions")
        return value


class Process(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suite_id: UUID
    execution_id: UUID
    stage: Literal["input_rail", "retrieval_rail", "output_rail"]
    text: str = Field(min_length=1, max_length=16000)
    capability: str = Field(min_length=40, max_length=256, repr=False)

    @field_validator("text")
    @classmethod
    def nonblank(cls, value):
        if not value.strip():
            raise ValueError("empty text")
        return value


class Close(BaseModel):
    model_config = ConfigDict(extra="forbid")


def create_app(*, model_factory, database=None, tokens=None, now=time.time, timeout=90):
    if tokens is None:
        tokens = {role: os.environ[f"GUIDED_P12_NEMO_{role.upper()}_TOKEN"]
                  for role in ("control", "service", "verifier")}
    if set(tokens) != {"control", "service", "verifier"} or any(not isinstance(value, str) or not value or not value.isascii() for value in tokens.values()) or len(set(tokens.values())) != 3:
        raise ValueError("three distinct nonempty credentials are required")
    if not callable(model_factory) or not 0 < timeout <= 90:
        raise ValueError("a trusted model factory and bounded timeout are required")
    from nemo import check_text
    from retrieval import check_retrieved_text

    root = Path(__file__).parent
    def source_digest():
        digest = hashlib.sha256()
        for name in ("nemo_server.py", "nemo.py", "retrieval.py", "gateway_model.py"):
            digest.update(name.encode())
            digest.update((root / name).read_bytes())
        return digest.hexdigest()
    build_digest = source_digest()
    path = Path(database or os.environ.get("GUIDED_P12_NEMO_DATABASE", "/state/nemo.sqlite3"))
    path.parent.mkdir(parents=True, exist_ok=True)

    def connect():
        db = sqlite3.connect(path, timeout=10)
        db.row_factory = sqlite3.Row
        return db

    with connect() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS suites (
                suite_id TEXT PRIMARY KEY, created REAL NOT NULL, closed REAL,
                execution_ids TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS calls (
                suite_id TEXT NOT NULL, execution_id TEXT NOT NULL, stage TEXT NOT NULL,
                started REAL NOT NULL, finished REAL, state TEXT NOT NULL,
                input_digest TEXT NOT NULL, evidence TEXT,
                PRIMARY KEY(suite_id, execution_id, stage));
            CREATE TABLE IF NOT EXISTS suite_builds (
                suite_id TEXT PRIMARY KEY, source_digest TEXT NOT NULL);
        """)

    def require(role, authorization):
        scheme, _, token = (authorization or "").partition(" ")
        if scheme.lower() != "bearer" or not hmac.compare_digest(token.encode(), tokens[role].encode()):
            raise HTTPException(401, "invalid service credential")

    app = FastAPI(title="P12 NeMo", docs_url=None, redoc_url=None, openapi_url=None)

    @app.exception_handler(RequestValidationError)
    async def validation_error(_request, _exc):
        return JSONResponse(status_code=422, content={"detail": "invalid request fields"})

    @app.get("/readyz")
    def ready():
        return {"status": "ready", "component": "p12-nemo"}

    @app.get("/v1/build-info")
    def build_info(authorization: str | None = Header(default=None)):
        require("verifier", authorization)
        return {"component": "p12-nemo", "source_digest": build_digest,
                "current_source_digest": source_digest()}

    @app.post("/v1/suites")
    def register(body: Register, authorization: str | None = Header(default=None)):
        require("control", authorization)
        if source_digest() != build_digest:
            raise HTTPException(503, "service source changed")
        created = now()
        try:
            with connect() as db:
                db.execute("INSERT INTO suites VALUES(?,?,NULL,?)", (
                    str(body.suite_id), created, json.dumps([str(value) for value in body.execution_ids])))
                db.execute("INSERT INTO suite_builds VALUES(?,?)", (str(body.suite_id), build_digest))
        except sqlite3.IntegrityError:
            raise HTTPException(409, "suite already exists") from None
        return {"suite_id": str(body.suite_id), "created_at": created, "expires_at": created + 180}

    @app.post("/v1/process")
    async def process(body: Process, authorization: str | None = Header(default=None)):
        require("service", authorization)
        key = (str(body.suite_id), str(body.execution_id), body.stage)
        digest = hashlib.sha256(body.text.encode()).hexdigest()
        with connect() as db:
            db.execute("BEGIN IMMEDIATE")
            suite = db.execute("SELECT * FROM suites WHERE suite_id=?", (key[0],)).fetchone()
            registered_build = db.execute("SELECT source_digest FROM suite_builds WHERE suite_id=?", (key[0],)).fetchone()
            if not suite or key[1] not in json.loads(suite["execution_ids"]):
                raise HTTPException(404, "registered execution not found")
            if suite["closed"] is not None or not 0 <= now() - suite["created"] < 180:
                raise HTTPException(409, "suite closed or expired")
            try:
                db.execute("INSERT INTO calls VALUES(?,?,?,?,NULL,'pending',?,NULL)", (*key, now(), digest))
            except sqlite3.IntegrityError:
                raise HTTPException(409, "stage already attempted") from None
        try:
            if (not registered_build or registered_build["source_digest"] != build_digest
                    or source_digest() != build_digest):
                raise ValueError("service source changed")
            async def inspect():
                model = model_factory(key[0], key[1], body.stage, body.capability)
                if body.stage == "retrieval_rail":
                    result = await check_retrieved_text(body.text, model)
                else:
                    result = await check_text(body.stage, body.text, model)
                if hasattr(model, "gateway_evidence"):
                    if not model.gateway_evidence:
                        raise ValueError("Gateway evidence missing")
                    result["evidence"]["gateway"] = model.gateway_evidence
                return result
            result = await asyncio.wait_for(inspect(), timeout=timeout)
            if source_digest() != build_digest:
                raise ValueError("service source changed during processing")
            evidence = result["evidence"]
            if (type(result["allowed"]) is not bool or evidence["input_digest"] != digest
                or evidence["stage"] != body.stage or evidence["version"] != "0.22.0"
                or evidence["classifier_answer"] not in {"Yes", "No"}
                or result["allowed"] != (evidence["classifier_answer"] == "No")
                or evidence["native_stop"] is not (not result["allowed"])):
                raise ValueError("invalid product evidence")
            evidence = {**evidence, "service_digest": build_digest}
            result = {"allowed": result["allowed"], "evidence": evidence}
        except Exception:
            with connect() as db:
                db.execute("UPDATE calls SET finished=?,state='error' WHERE suite_id=? AND execution_id=? AND stage=?", (now(), *key))
            raise HTTPException(503, "rail processing failed") from None
        with connect() as db:
            db.execute("UPDATE calls SET finished=?,state='completed',evidence=? WHERE suite_id=? AND execution_id=? AND stage=?",
                       (now(), json.dumps(evidence), *key))
        return {"suite_id": key[0], "execution_id": key[1], **result}

    @app.post("/v1/suites/{suite_id}/close")
    def close(suite_id: UUID, body: Close, authorization: str | None = Header(default=None)):
        require("control", authorization)
        with connect() as db:
            db.execute("BEGIN IMMEDIATE")
            suite = db.execute("SELECT * FROM suites WHERE suite_id=?", (str(suite_id),)).fetchone()
            if not suite:
                raise HTTPException(404, "suite not found")
            if db.execute("SELECT 1 FROM calls WHERE suite_id=? AND state='pending'", (str(suite_id),)).fetchone():
                raise HTTPException(409, "processing remains in progress")
            closed = suite["closed"] if suite["closed"] is not None else now()
            db.execute("UPDATE suites SET closed=? WHERE suite_id=?", (closed, str(suite_id)))
        return {"suite_id": str(suite_id), "closed_at": closed}

    @app.get("/v1/suites/{suite_id}/ledger")
    def ledger(suite_id: UUID, authorization: str | None = Header(default=None)):
        require("verifier", authorization)
        with connect() as db:
            suite = db.execute("SELECT * FROM suites WHERE suite_id=?", (str(suite_id),)).fetchone()
            calls = db.execute("SELECT * FROM calls WHERE suite_id=? ORDER BY started,execution_id,stage", (str(suite_id),)).fetchall()
            build = db.execute("SELECT source_digest FROM suite_builds WHERE suite_id=?", (str(suite_id),)).fetchone()
        if not suite:
            raise HTTPException(404, "suite not found")
        return {"practice_id": "P12", "contract_version": 2, "suite_id": str(suite_id), "component": "p12-nemo",
                "service_digest": build["source_digest"] if build else None,
                "created_at": suite["created"], "closed_at": suite["closed"],
                "execution_ids": json.loads(suite["execution_ids"]),
                "calls": [{**dict(row), "evidence": json.loads(row["evidence"]) if row["evidence"] else None} for row in calls]}

    return app


def create_service():
    """Production entrypoint: only the configured P12 Gateway may supply models."""
    from gateway_model import GatewayModel
    origin = os.environ["GUIDED_P12_GATEWAY_URL"]

    def model_factory(suite_id, execution_id, role, capability):
        return GatewayModel(origin, suite_id, execution_id, role, capability)

    return create_app(model_factory=model_factory)
