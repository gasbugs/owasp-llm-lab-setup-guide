"""H09 delivery boundary with one-time capabilities and an append-only ledger."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field


CONTROL_TOKEN = os.environ["GUIDED_H09_SINK_CONTROL_TOKEN"]
VERIFIER_TOKEN = os.environ["GUIDED_H09_SINK_VERIFIER_TOKEN"]
CAPABILITY_SECRET = os.environ["GUIDED_H09_CAPABILITY_SECRET"].encode()
DATABASE_PATH = Path(os.getenv("GUIDED_H09_SINK_DATABASE", "/state/ledger.sqlite3"))
CAPABILITY_TTL_SECONDS = 900
CASE_ORDER = ("clean", "input-email", "input-kr-rrn", "output-email")
RAW_MARKERS = {
    "clean": None,
    "input-email": "learner@example.com",
    "input-kr-rrn": "900101-1234568",
    "output-email": "security-team@example.com",
}
if len(CAPABILITY_SECRET) < 32:
    raise RuntimeError("GUIDED_H09_CAPABILITY_SECRET must be at least 32 bytes")

DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)


def now() -> datetime:
    return datetime.now(timezone.utc)


def connect() -> sqlite3.Connection:
    database = sqlite3.connect(DATABASE_PATH, timeout=10, isolation_level=None)
    database.row_factory = sqlite3.Row
    database.execute("PRAGMA foreign_keys=ON")
    return database


with connect() as database:
    database.executescript(
        """
        CREATE TABLE IF NOT EXISTS suites (
          suite_id TEXT PRIMARY KEY,
          started_at TEXT NOT NULL,
          created_at TEXT NOT NULL,
          closed_at TEXT
        );
        CREATE TABLE IF NOT EXISTS capabilities (
          capability_digest TEXT PRIMARY KEY,
          suite_id TEXT NOT NULL,
          execution_id TEXT NOT NULL UNIQUE,
          case_id TEXT NOT NULL,
          nonce TEXT NOT NULL UNIQUE,
          issued_at TEXT NOT NULL,
          expires_at TEXT NOT NULL,
          status TEXT NOT NULL,
          consumed_at TEXT,
          FOREIGN KEY(suite_id) REFERENCES suites(suite_id)
        );
        CREATE TABLE IF NOT EXISTS deliveries (
          delivery_id TEXT PRIMARY KEY,
          capability_digest TEXT NOT NULL UNIQUE,
          suite_id TEXT NOT NULL,
          execution_id TEXT NOT NULL UNIQUE,
          case_id TEXT NOT NULL,
          delivered_digest TEXT NOT NULL,
          delivered_bytes INTEGER NOT NULL,
          raw_marker_observed INTEGER NOT NULL,
          observed_at TEXT NOT NULL,
          FOREIGN KEY(capability_digest) REFERENCES capabilities(capability_digest)
        );
        """
    )


CaseId = Literal["clean", "input-email", "input-kr-rrn", "output-email"]


class Execution(BaseModel):
    model_config = ConfigDict(extra="forbid")
    case_id: CaseId
    execution_id: str = Field(pattern=r"^[0-9a-f-]{36}$")


class SuiteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suite_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    started_at: str = Field(min_length=20, max_length=64)
    executions: list[Execution] = Field(min_length=4, max_length=4)


class DeliveryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suite_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    execution_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    case_id: CaseId
    text: str = Field(min_length=1, max_length=5000)


def bearer(expected: str, authorization: str | None) -> None:
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="invalid service credential")


def require_control(authorization: str | None = Header(default=None)) -> None:
    bearer(CONTROL_TOKEN, authorization)


def require_verifier(authorization: str | None = Header(default=None)) -> None:
    bearer(VERIFIER_TOKEN, authorization)


def encode_part(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def decode_part(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def digest_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def issue_capability(*, suite_id: str, execution_id: str, case_id: str) -> tuple[str, dict]:
    issued_at = now()
    expires_at = issued_at + timedelta(seconds=CAPABILITY_TTL_SECONDS)
    payload = {
        "v": 1,
        "suite_id": suite_id,
        "execution_id": execution_id,
        "case_id": case_id,
        "nonce": secrets.token_urlsafe(18),
        "expires_at": int(expires_at.timestamp()),
    }
    encoded = encode_part(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
    signature = encode_part(hmac.new(CAPABILITY_SECRET, encoded.encode(), hashlib.sha256).digest())
    token = f"{encoded}.{signature}"
    return token, {
        **payload,
        "capability_digest": digest_token(token),
        "issued_at": issued_at.isoformat(),
        "expires_at": expires_at.isoformat(),
    }


def verify_capability(token: str) -> dict:
    encoded, separator, signature = token.partition(".")
    expected = encode_part(hmac.new(CAPABILITY_SECRET, encoded.encode(), hashlib.sha256).digest())
    if not separator or not hmac.compare_digest(signature, expected):
        raise HTTPException(status_code=401, detail="invalid delivery capability")
    try:
        payload = json.loads(decode_part(encoded))
    except (ValueError, json.JSONDecodeError) as error:
        raise HTTPException(status_code=401, detail="invalid delivery capability") from error
    required = {"v", "suite_id", "execution_id", "case_id", "nonce", "expires_at"}
    if set(payload) != required or payload["v"] != 1:
        raise HTTPException(status_code=401, detail="invalid delivery capability")
    if payload["case_id"] not in CASE_ORDER or not isinstance(payload["expires_at"], int):
        raise HTTPException(status_code=401, detail="invalid delivery capability")
    if now().timestamp() >= payload["expires_at"]:
        raise HTTPException(status_code=401, detail="delivery capability expired")
    return payload


app = FastAPI(title="Tenant 03 H09 Delivery Sink", docs_url=None, redoc_url=None)


@app.get("/livez")
def livez() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/readyz")
def readyz() -> dict[str, str]:
    return {"status": "ready", "runtime": "h09-delivery-ledger"}


@app.post("/v1/suites")
def create_suite(
    request: SuiteRequest,
    _authorized: None = Depends(require_control),
) -> dict:
    if tuple(item.case_id for item in request.executions) != CASE_ORDER:
        raise HTTPException(status_code=422, detail="suite does not match fixed H09 cases")
    if len({item.execution_id for item in request.executions}) != 4:
        raise HTTPException(status_code=422, detail="execution IDs must be unique")
    created_at = now().isoformat()
    grants = [
        (execution, *issue_capability(
            suite_id=request.suite_id,
            execution_id=execution.execution_id,
            case_id=execution.case_id,
        ))
        for execution in request.executions
    ]
    try:
        with connect() as database:
            database.execute("BEGIN IMMEDIATE")
            database.execute(
                "INSERT INTO suites VALUES(?,?,?,NULL)",
                (request.suite_id, request.started_at, created_at),
            )
            for execution, _token, metadata in grants:
                database.execute(
                    "INSERT INTO capabilities VALUES(?,?,?,?,?,?,?,'issued',NULL)",
                    (
                        metadata["capability_digest"],
                        request.suite_id,
                        execution.execution_id,
                        execution.case_id,
                        metadata["nonce"],
                        metadata["issued_at"],
                        metadata["expires_at"],
                    ),
                )
            database.execute("COMMIT")
    except sqlite3.IntegrityError as error:
        raise HTTPException(status_code=409, detail="suite already exists") from error
    return {
        "suite_id": request.suite_id,
        "started_at": request.started_at,
        "created_at": created_at,
        "cases": [
            {
                "case_id": execution.case_id,
                "execution_id": execution.execution_id,
                "capability": token,
                "capability_digest": metadata["capability_digest"],
                "expires_at": metadata["expires_at"],
            }
            for execution, token, metadata in grants
        ],
    }


@app.post("/v1/deliver")
def deliver(
    request: DeliveryRequest,
    authorization: str | None = Header(default=None),
) -> dict:
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="delivery capability required")
    payload = verify_capability(token)
    if any(
        (
            payload["suite_id"] != request.suite_id,
            payload["execution_id"] != request.execution_id,
            payload["case_id"] != request.case_id,
        )
    ):
        raise HTTPException(status_code=403, detail="delivery capability scope mismatch")
    capability_digest = digest_token(token)
    delivered_digest = hashlib.sha256(request.text.encode()).hexdigest()
    observed_at = now().isoformat()
    delivery_id = str(uuid.uuid4())
    raw_marker = RAW_MARKERS[request.case_id]
    raw_marker_observed = raw_marker in request.text if raw_marker else False
    with connect() as database:
        try:
            database.execute("BEGIN IMMEDIATE")
            suite = database.execute(
                "SELECT closed_at FROM suites WHERE suite_id=?", (request.suite_id,)
            ).fetchone()
            capability = database.execute(
                "SELECT * FROM capabilities WHERE capability_digest=?",
                (capability_digest,),
            ).fetchone()
            if suite is None or capability is None:
                raise HTTPException(status_code=401, detail="unknown delivery capability")
            if suite["closed_at"] is not None or capability["status"] != "issued":
                raise HTTPException(status_code=409, detail="delivery capability already used or closed")
            if any(
                (
                    capability["suite_id"] != request.suite_id,
                    capability["execution_id"] != request.execution_id,
                    capability["case_id"] != request.case_id,
                    capability["nonce"] != payload["nonce"],
                )
            ):
                raise HTTPException(status_code=403, detail="delivery capability ledger mismatch")
            database.execute(
                "INSERT INTO deliveries VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    delivery_id,
                    capability_digest,
                    request.suite_id,
                    request.execution_id,
                    request.case_id,
                    delivered_digest,
                    len(request.text.encode()),
                    int(raw_marker_observed),
                    observed_at,
                ),
            )
            database.execute(
                "UPDATE capabilities SET status='completed', consumed_at=? "
                "WHERE capability_digest=?",
                (observed_at, capability_digest),
            )
            database.execute("COMMIT")
        except HTTPException:
            database.execute("ROLLBACK")
            raise
        except sqlite3.IntegrityError as error:
            database.execute("ROLLBACK")
            raise HTTPException(status_code=409, detail="delivery evidence already exists") from error
    return {
        "delivery_id": delivery_id,
        "execution_id": request.execution_id,
        "case_id": request.case_id,
        "delivered_digest": delivered_digest,
        "delivered_bytes": len(request.text.encode()),
        "raw_marker_observed": raw_marker_observed,
        "observed_at": observed_at,
    }


@app.post("/v1/suites/{suite_id}/close")
def close_suite(suite_id: str, _authorized: None = Depends(require_control)) -> dict:
    closed_at = now().isoformat()
    with connect() as database:
        database.execute("BEGIN IMMEDIATE")
        suite = database.execute(
            "SELECT closed_at FROM suites WHERE suite_id=?", (suite_id,)
        ).fetchone()
        if suite is None:
            database.execute("ROLLBACK")
            raise HTTPException(status_code=404, detail="suite not found")
        if suite["closed_at"] is None:
            database.execute(
                "UPDATE suites SET closed_at=? WHERE suite_id=?", (closed_at, suite_id)
            )
            database.execute(
                "UPDATE capabilities SET status='closed_unused' "
                "WHERE suite_id=? AND status='issued'",
                (suite_id,),
            )
        else:
            closed_at = suite["closed_at"]
        database.execute("COMMIT")
    return {"suite_id": suite_id, "closed_at": closed_at}


@app.get("/v1/suites/{suite_id}/ledger")
def ledger(suite_id: str, _authorized: None = Depends(require_verifier)) -> dict:
    with connect() as database:
        suite = database.execute(
            "SELECT * FROM suites WHERE suite_id=?", (suite_id,)
        ).fetchone()
        capabilities = database.execute(
            "SELECT capability_digest,suite_id,execution_id,case_id,issued_at,expires_at,"
            "status,consumed_at FROM capabilities WHERE suite_id=? ORDER BY rowid",
            (suite_id,),
        ).fetchall()
        deliveries = database.execute(
            "SELECT delivery_id,capability_digest,suite_id,execution_id,case_id,"
            "delivered_digest,delivered_bytes,raw_marker_observed,observed_at "
            "FROM deliveries WHERE suite_id=? ORDER BY rowid",
            (suite_id,),
        ).fetchall()
    if suite is None:
        raise HTTPException(status_code=404, detail="suite not found")
    return {
        "suite_id": suite["suite_id"],
        "started_at": suite["started_at"],
        "created_at": suite["created_at"],
        "closed_at": suite["closed_at"],
        "capabilities": [dict(item) for item in capabilities],
        "deliveries": [
            {**dict(item), "raw_marker_observed": bool(item["raw_marker_observed"])}
            for item in deliveries
        ],
    }
