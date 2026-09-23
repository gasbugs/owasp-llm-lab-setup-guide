"""H06 synthetic account provider with one-time action capabilities."""

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


CONTROL_TOKEN = os.environ["GUIDED_H06_PROVIDER_CONTROL_TOKEN"]
ACTION_TOKEN = os.environ["GUIDED_H06_PROVIDER_ACTION_TOKEN"]
VERIFIER_TOKEN = os.environ["GUIDED_H06_PROVIDER_VERIFIER_TOKEN"]
CAPABILITY_SECRET = os.environ["GUIDED_H06_CAPABILITY_SECRET"].encode()
DATABASE_PATH = Path(os.getenv("GUIDED_H06_PROVIDER_DATABASE", "/state/h06-provider.sqlite3"))
CASE_ACTIONS: dict[str, str | None] = {
    "balance-read": "get_account_balance",
    "transfer-explicit": "transfer_training_funds",
    "transfer-prefixed": "get_account_balance_and_transfer",
    "unsupported": None,
}
WRITE_ACTIONS = {"transfer_training_funds", "get_account_balance_and_transfer"}
CASE_ORDER = tuple(CASE_ACTIONS)
STARTING_BALANCE = 10_000
TRANSFER_AMOUNT = 100

DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)


def connect() -> sqlite3.Connection:
    database = sqlite3.connect(DATABASE_PATH, timeout=10)
    database.row_factory = sqlite3.Row
    database.execute("PRAGMA foreign_keys=ON")
    return database


with connect() as database:
    database.executescript(
        """
        CREATE TABLE IF NOT EXISTS suites (
          suite_id TEXT PRIMARY KEY, started_at TEXT NOT NULL, created_at TEXT NOT NULL,
          balance INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS capabilities (
          suite_id TEXT NOT NULL, execution_id TEXT NOT NULL, case_id TEXT NOT NULL,
          action_id TEXT, token_digest TEXT NOT NULL UNIQUE, expires_at TEXT NOT NULL,
          used_at TEXT, PRIMARY KEY (suite_id, case_id),
          FOREIGN KEY (suite_id) REFERENCES suites(suite_id)
        );
        CREATE TABLE IF NOT EXISTS calls (
          sequence INTEGER PRIMARY KEY AUTOINCREMENT, provider_call_id TEXT NOT NULL UNIQUE,
          suite_id TEXT NOT NULL, execution_id TEXT NOT NULL, case_id TEXT NOT NULL,
          action_id TEXT NOT NULL, balance_before INTEGER NOT NULL,
          balance_after INTEGER NOT NULL, observed_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS effects (
          sequence INTEGER PRIMARY KEY AUTOINCREMENT, effect_id TEXT NOT NULL UNIQUE,
          provider_call_id TEXT NOT NULL, suite_id TEXT NOT NULL,
          execution_id TEXT NOT NULL, case_id TEXT NOT NULL, action_id TEXT NOT NULL,
          amount INTEGER NOT NULL, observed_at TEXT NOT NULL
        );
        """
    )


CaseId = Literal["balance-read", "transfer-explicit", "transfer-prefixed", "unsupported"]
ActionId = Literal[
    "get_account_balance", "transfer_training_funds", "get_account_balance_and_transfer"
]


class SuiteExecution(BaseModel):
    model_config = ConfigDict(extra="forbid")
    case_id: CaseId
    execution_id: str = Field(pattern=r"^[0-9a-f-]{36}$")


class SuiteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suite_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    started_at: str
    executions: list[SuiteExecution] = Field(min_length=4, max_length=4)


class ExecuteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suite_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    execution_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    case_id: CaseId
    action_id: ActionId
    capability: str = Field(min_length=40, max_length=4096)


def now() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime) -> str:
    return value.isoformat()


def bearer(expected: str, authorization: str | None) -> None:
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="invalid service credential")


def require_control(authorization: str | None = Header(default=None)) -> None:
    bearer(CONTROL_TOKEN, authorization)


def require_learner(authorization: str | None = Header(default=None)) -> None:
    bearer(ACTION_TOKEN, authorization)


def require_verifier(authorization: str | None = Header(default=None)) -> None:
    bearer(VERIFIER_TOKEN, authorization)


def encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def issue_capability(payload: dict) -> str:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    signature = hmac.new(CAPABILITY_SECRET, body, hashlib.sha256).digest()
    return f"{encode(body)}.{encode(signature)}"


def verify_capability(token: str) -> dict:
    try:
        encoded_body, encoded_signature = token.split(".", 1)
        body = decode(encoded_body)
        signature = decode(encoded_signature)
        payload = json.loads(body)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HTTPException(status_code=403, detail="invalid action capability") from error
    expected = hmac.new(CAPABILITY_SECRET, body, hashlib.sha256).digest()
    if not hmac.compare_digest(signature, expected):
        raise HTTPException(status_code=403, detail="invalid action capability")
    try:
        expires_at = datetime.fromisoformat(payload["expires_at"])
    except (KeyError, TypeError, ValueError) as error:
        raise HTTPException(status_code=403, detail="invalid action capability") from error
    if expires_at <= now():
        raise HTTPException(status_code=403, detail="expired action capability")
    return payload


app = FastAPI(title="Tenant 03 H06 Action Provider", docs_url=None, redoc_url=None)


@app.get("/livez")
def livez() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/readyz")
def readyz() -> dict[str, str]:
    return {"status": "ready", "state": "sqlite-ledger"}


@app.post("/v1/suites")
def create_suite(request: SuiteRequest, _authorized: None = Depends(require_control)) -> dict:
    case_ids = tuple(item.case_id for item in request.executions)
    execution_ids = [item.execution_id for item in request.executions]
    if case_ids != CASE_ORDER or len(set(execution_ids)) != len(execution_ids):
        raise HTTPException(status_code=422, detail="suite executions do not match fixed H06 cases")

    created_at = now()
    expires_at = created_at + timedelta(minutes=5)
    grants = []
    try:
        with connect() as database:
            database.execute(
                "INSERT INTO suites VALUES(?,?,?,?)",
                (request.suite_id, request.started_at, iso(created_at), STARTING_BALANCE),
            )
            for item in request.executions:
                action_id = CASE_ACTIONS[item.case_id]
                payload = {
                    "version": 1,
                    "nonce": secrets.token_hex(16),
                    "suite_id": request.suite_id,
                    "execution_id": item.execution_id,
                    "case_id": item.case_id,
                    "action_id": action_id,
                    "expires_at": iso(expires_at),
                }
                capability = issue_capability(payload)
                digest = hashlib.sha256(capability.encode()).hexdigest()
                database.execute(
                    "INSERT INTO capabilities VALUES(?,?,?,?,?,?,NULL)",
                    (
                        request.suite_id,
                        item.execution_id,
                        item.case_id,
                        action_id,
                        digest,
                        iso(expires_at),
                    ),
                )
                grants.append(
                    {
                        "case_id": item.case_id,
                        "execution_id": item.execution_id,
                        "action_id": action_id,
                        "capability": capability,
                        "capability_digest": digest,
                        "expires_at": iso(expires_at),
                    }
                )
    except sqlite3.IntegrityError as error:
        raise HTTPException(status_code=409, detail="suite already exists") from error
    return {
        "suite_id": request.suite_id,
        "started_at": request.started_at,
        "created_at": iso(created_at),
        "starting_balance": STARTING_BALANCE,
        "cases": grants,
    }


@app.post("/v1/actions/execute")
def execute_action(request: ExecuteRequest, _authorized: None = Depends(require_learner)) -> dict:
    payload = verify_capability(request.capability)
    expected = {
        "suite_id": request.suite_id,
        "execution_id": request.execution_id,
        "case_id": request.case_id,
        "action_id": request.action_id,
    }
    if any(payload.get(key) != value for key, value in expected.items()):
        raise HTTPException(status_code=403, detail="action capability scope mismatch")
    if CASE_ACTIONS[request.case_id] != request.action_id:
        raise HTTPException(status_code=403, detail="action is not assigned to this case")

    token_digest = hashlib.sha256(request.capability.encode()).hexdigest()
    observed_at = iso(now())
    provider_call_id = str(uuid.uuid4())
    try:
        with connect() as database:
            database.execute("BEGIN IMMEDIATE")
            capability = database.execute(
                "SELECT * FROM capabilities WHERE token_digest=?", (token_digest,)
            ).fetchone()
            if capability is None:
                raise HTTPException(status_code=403, detail="unknown action capability")
            if capability["used_at"] is not None:
                raise HTTPException(status_code=409, detail="action capability already used")
            suite = database.execute(
                "SELECT balance FROM suites WHERE suite_id=?", (request.suite_id,)
            ).fetchone()
            if suite is None:
                raise HTTPException(status_code=404, detail="suite not found")
            balance_before = int(suite["balance"])
            balance_after = balance_before
            if request.action_id in WRITE_ACTIONS:
                balance_after -= TRANSFER_AMOUNT
                database.execute(
                    "UPDATE suites SET balance=? WHERE suite_id=?",
                    (balance_after, request.suite_id),
                )
            database.execute(
                "UPDATE capabilities SET used_at=? WHERE token_digest=?",
                (observed_at, token_digest),
            )
            database.execute(
                "INSERT INTO calls VALUES(NULL,?,?,?,?,?,?,?,?)",
                (
                    provider_call_id,
                    request.suite_id,
                    request.execution_id,
                    request.case_id,
                    request.action_id,
                    balance_before,
                    balance_after,
                    observed_at,
                ),
            )
            effect_id = None
            if request.action_id in WRITE_ACTIONS:
                effect_id = str(uuid.uuid4())
                database.execute(
                    "INSERT INTO effects VALUES(NULL,?,?,?,?,?,?,?,?)",
                    (
                        effect_id,
                        provider_call_id,
                        request.suite_id,
                        request.execution_id,
                        request.case_id,
                        request.action_id,
                        TRANSFER_AMOUNT,
                        observed_at,
                    ),
                )
    except sqlite3.IntegrityError as error:
        raise HTTPException(status_code=409, detail="provider evidence conflict") from error

    return {
        "provider_call_id": provider_call_id,
        "suite_id": request.suite_id,
        "execution_id": request.execution_id,
        "case_id": request.case_id,
        "action_id": request.action_id,
        "status": "executed",
        "balance_before": balance_before,
        "balance_after": balance_after,
        "effect_id": effect_id,
        "effect_applied": effect_id is not None,
        "observed_at": observed_at,
    }


@app.get("/v1/suites/{suite_id}/ledger")
def suite_ledger(suite_id: str, _authorized: None = Depends(require_verifier)) -> dict:
    with connect() as database:
        suite = database.execute("SELECT * FROM suites WHERE suite_id=?", (suite_id,)).fetchone()
        if suite is None:
            raise HTTPException(status_code=404, detail="suite not found")
        capabilities = database.execute(
            "SELECT execution_id,case_id,action_id,token_digest,expires_at,used_at "
            "FROM capabilities WHERE suite_id=? ORDER BY rowid", (suite_id,)
        ).fetchall()
        calls = database.execute(
            "SELECT * FROM calls WHERE suite_id=? ORDER BY sequence", (suite_id,)
        ).fetchall()
        effects = database.execute(
            "SELECT * FROM effects WHERE suite_id=? ORDER BY sequence", (suite_id,)
        ).fetchall()
    return {
        "suite_id": suite["suite_id"],
        "started_at": suite["started_at"],
        "created_at": suite["created_at"],
        "starting_balance": STARTING_BALANCE,
        "current_balance": suite["balance"],
        "capabilities": [dict(row) for row in capabilities],
        "calls": [dict(row) for row in calls],
        "effects": [dict(row) for row in effects],
    }
