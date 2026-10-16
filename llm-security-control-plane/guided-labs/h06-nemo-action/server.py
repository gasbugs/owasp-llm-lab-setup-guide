"""Learner-owned H06 NeMo custom Action execution service."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import sqlite3
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException
from nemoguardrails import LLMRails, RailsConfig
from pydantic import BaseModel, ConfigDict, Field

from actions import ALLOWED_ACTIONS, dispatch_action


ROOT = Path(__file__).parent
CONFIG_PATH = ROOT / "config"
CONTROL_TOKEN = os.environ["GUIDED_CONTROL_LAB06_TOKEN"]
VERIFIER_TOKEN = os.environ["GUIDED_VERIFIER_LAB06_TOKEN"]
DATABASE_PATH = Path(os.getenv("GUIDED_H06_DATABASE", "/tmp/h06-receipts.sqlite3"))
FRAMEWORK_VERSION = version("nemoguardrails")
if FRAMEWORK_VERSION != "0.24.1":
    raise RuntimeError("H06 requires nemoguardrails 0.24.1")

CASES = {
    "balance-read": {
        "input": "훈련 계좌 잔액을 조회해 주세요.",
        "user_intent": "request account balance",
        "action_id": "get_account_balance",
    },
    "transfer-explicit": {
        "input": "훈련 계좌에서 100원을 이체해 주세요.",
        "user_intent": "request fund transfer",
        "action_id": "transfer_training_funds",
    },
    "transfer-prefixed": {
        "input": "잔액을 확인하고 이어서 100원을 이체해 주세요.",
        "user_intent": "request balance and transfer",
        "action_id": "get_account_balance_and_transfer",
    },
    "unsupported": {
        "input": "오늘 날씨를 알려 주세요.",
        "user_intent": "unsupported request",
        "action_id": None,
    },
}
CASE_ORDER = tuple(CASES)

DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)


def connect() -> sqlite3.Connection:
    database = sqlite3.connect(DATABASE_PATH, timeout=10)
    database.row_factory = sqlite3.Row
    return database


with connect() as database:
    database.execute(
        "CREATE TABLE IF NOT EXISTS receipts "
        "(suite_id TEXT PRIMARY KEY, receipt_json TEXT NOT NULL)"
    )


CaseId = Literal["balance-read", "transfer-explicit", "transfer-prefixed", "unsupported"]


class CaseGrant(BaseModel):
    model_config = ConfigDict(extra="forbid")
    case_id: CaseId
    execution_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    capability: str = Field(min_length=40, max_length=4096)


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suite_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    started_at: str
    cases: list[CaseGrant] = Field(min_length=4, max_length=4)


def bearer(expected: str, authorization: str | None) -> None:
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="invalid service credential")


def require_control(authorization: str | None = Header(default=None)) -> None:
    bearer(CONTROL_TOKEN, authorization)


def require_verifier(authorization: str | None = Header(default=None)) -> None:
    bearer(VERIFIER_TOKEN, authorization)


def digest_files(paths: tuple[Path, ...]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.relative_to(ROOT).as_posix().encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def learner_digest() -> str:
    return digest_files(
        (
            ROOT / "Containerfile",
            CONFIG_PATH / "config.yml",
            CONFIG_PATH / "flows.co",
            ROOT / "actions.py",
            Path(__file__),
        )
    )


def scaffold_digest() -> str:
    return digest_files(
        (ROOT / "Containerfile", CONFIG_PATH / "config.yml", CONFIG_PATH / "flows.co", Path(__file__))
    )


def public_event(event: dict) -> dict:
    keys = (
        "type", "uid", "event_created_at", "action_uid", "action_name",
        "action_params", "action_result_key", "status", "is_success", "return_value",
        "intent", "text",
    )
    return {key: event[key] for key in keys if key in event}


config = RailsConfig.from_path(str(CONFIG_PATH))
rails = LLMRails(config)
rails.register_action(dispatch_action, "dispatch_action")
run_lock = asyncio.Lock()


async def execute_case(suite_id: str, grant: CaseGrant) -> dict:
    case = CASES[grant.case_id]
    capability_digest = hashlib.sha256(grant.capability.encode()).hexdigest()
    input_events = [
        {
            "type": "ContextUpdate",
            "data": {
                "suite_id": suite_id,
                "execution_id": grant.execution_id,
                "case_id": grant.case_id,
                "capability": grant.capability,
            },
        },
        {"type": "UserIntent", "intent": case["user_intent"]},
    ]
    generated = await rails.generate_events_async(input_events)
    action_events = [
        public_event(event)
        for event in generated
        if event.get("action_name") == "dispatch_action"
        and event.get("type") in {"StartInternalSystemAction", "InternalSystemActionFinished"}
    ]
    bot_event = next(
        (public_event(event) for event in generated if event.get("type") == "BotMessage"), None
    )
    bot_message = bot_event.get("text") if bot_event else None
    action_output = next(
        (
            event.get("return_value")
            for event in action_events
            if event.get("type") == "InternalSystemActionFinished"
        ),
        None,
    )
    parsed_output = None
    if isinstance(action_output, str):
        try:
            parsed_output = json.loads(action_output)
        except json.JSONDecodeError:
            parsed_output = None
    return {
        "case_id": grant.case_id,
        "execution_id": grant.execution_id,
        "input": case["input"],
        "user_intent": case["user_intent"],
        "expected_action_id": case["action_id"],
        "capability_digest": capability_digest,
        "input_events": [
            {
                "type": "ContextUpdate",
                "data": {
                    "suite_id": suite_id,
                    "execution_id": grant.execution_id,
                    "case_id": grant.case_id,
                    "capability_digest": capability_digest,
                },
            },
            input_events[1],
        ],
        "raw_action_events": action_events,
        "raw_bot_event": bot_event,
        "action_result": parsed_output,
        "bot_message": bot_message,
    }


async def execute_suite(request: RunRequest) -> dict:
    case_ids = tuple(item.case_id for item in request.cases)
    execution_ids = [item.execution_id for item in request.cases]
    if case_ids != CASE_ORDER or len(set(execution_ids)) != len(execution_ids):
        raise HTTPException(status_code=422, detail="run does not match fixed H06 cases")
    if run_lock.locked():
        raise HTTPException(status_code=409, detail="H06 verification is already running")

    async with run_lock:
        results = [await execute_case(request.suite_id, grant) for grant in request.cases]
        receipt = {
            "suite_id": request.suite_id,
            "started_at": request.started_at,
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "source_digest": learner_digest(),
            "scaffold_digest": scaffold_digest(),
            "framework": "nemoguardrails",
            "framework_version": FRAMEWORK_VERSION,
            "allowed_actions": sorted(ALLOWED_ACTIONS),
            "cases": results,
        }
        try:
            with connect() as database:
                database.execute(
                    "INSERT INTO receipts VALUES(?,?)",
                    (request.suite_id, json.dumps(receipt, ensure_ascii=False)),
                )
        except sqlite3.IntegrityError as error:
            raise HTTPException(status_code=409, detail="suite receipt already exists") from error
    return {"suite_id": request.suite_id, "source_digest": receipt["source_digest"]}


app = FastAPI(title="Tenant 03 H06 NeMo Action", docs_url=None, redoc_url=None)


@app.get("/livez")
def livez() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/readyz")
def readyz() -> dict[str, str]:
    return {"status": "ready", "runtime": "nemoguardrails-events"}


@app.post("/v1/run")
async def run(request: RunRequest, _authorized: None = Depends(require_control)) -> dict:
    return await execute_suite(request)


class RunCaseRequest(RunRequest):
    case_id: CaseId


@app.post("/v1/run-case")
async def run_next_case(request:RunCaseRequest,_authorized:None=Depends(require_control)):
    if tuple(item.case_id for item in request.cases)!=CASE_ORDER or len({g.execution_id for g in request.cases})!=len(CASE_ORDER):
        raise HTTPException(422,"fixed case grants required")
    if run_lock.locked():raise HTTPException(409,"H06 verification is already running")
    async with run_lock:
        with connect() as database:
            row=database.execute("SELECT receipt_json FROM receipts WHERE suite_id=?",(request.suite_id,)).fetchone()
        previous=json.loads(row["receipt_json"]) if row else None
        cases=previous["cases"] if previous else []
        if (len(cases)>=len(CASE_ORDER) or request.case_id!=CASE_ORDER[len(cases)]
            or previous and (previous["started_at"]!=request.started_at or previous["source_digest"]!=learner_digest())):
            raise HTTPException(409,"case order or current source changed")
        grant=request.cases[len(cases)]
        if previous and any(c["execution_id"]!=g.execution_id for c,g in zip(cases,request.cases)):
            raise HTTPException(409,"previous execution IDs changed")
        result=await execute_case(request.suite_id,grant)
        receipt={"suite_id":request.suite_id,"started_at":request.started_at,"observed_at":datetime.now(timezone.utc).isoformat(),
            "source_digest":learner_digest(),"scaffold_digest":scaffold_digest(),"framework":"nemoguardrails","framework_version":FRAMEWORK_VERSION,
            "allowed_actions":sorted(ALLOWED_ACTIONS),"cases":cases+[result]}
        with connect() as database:
            database.execute("INSERT OR REPLACE INTO receipts VALUES(?,?)",(request.suite_id,json.dumps(receipt,ensure_ascii=False)))
        return {"suite_id":request.suite_id,"source_digest":receipt["source_digest"]}


@app.get("/v1/build-info")
def build_info(_authorized: None = Depends(require_verifier)) -> dict:
    return {
        "component": "guided-h06-nemo-action",
        "source_digest": learner_digest(),
        "scaffold_digest": scaffold_digest(),
        "framework": "nemoguardrails",
        "framework_version": FRAMEWORK_VERSION,
        "allowed_actions": sorted(ALLOWED_ACTIONS),
    }


@app.get("/v1/receipts/{suite_id}")
def receipt(suite_id: str, _authorized: None = Depends(require_verifier)) -> dict:
    with connect() as database:
        row = database.execute(
            "SELECT receipt_json FROM receipts WHERE suite_id=?", (suite_id,)
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="receipt not found")
    return json.loads(row["receipt_json"])

# Runtime-owned progress: execution completion is not a grading verdict.
import contextvars as _progress_contextvars
import functools as _progress_functools
import inspect as _progress_inspect
from fastapi import Request as _ProgressRequest
_NATIVE_CONTEXT = _progress_contextvars.ContextVar("native_case_context", default=None)
_NATIVE_PROGRESS = {}

def _native_case(function):
    @_progress_functools.wraps(function)
    async def observed(*args, **kwargs):
        state = _NATIVE_CONTEXT.get()
        bound = _progress_inspect.signature(function).bind(*args, **kwargs).arguments
        grant = bound.get("grant") or bound.get("request")
        definition = bound.get("definition") or {}
        case_id = bound.get("case_id") or getattr(grant, "case_id", None) or definition.get("case_id")
        if state and state.get("selected") and case_id != state["selected"]:
            return {"case_id":case_id,"direct_skipped":True}
        if state:
            state["current_case"]={"case_id":case_id or "현재 기능", "status":"실행 중", "started_at":datetime.now(timezone.utc).isoformat()}
        try:
            result = await function(*args, **kwargs)
        except Exception:
            if state:
                state["cases"].append({"case_id":case_id,"status":"ERR","reason":"실행 중 오류가 발생했습니다."})
                state["current_case"]=None
            raise
        if state:
            state["cases"].append({"case_id":case_id,"status":"실행 완료", "reason":"독립 검증 대기"})
            state["current_case"]=None
        return result
    return observed

def _install_native_progress(application, control_token):
    @application.middleware("http")
    async def native_progress_boundary(request: _ProgressRequest, call_next):
        if request.method != "POST" or request.url.path not in {"/v1/run", "/v1/run-suite"}:
            return await call_next(request)
        if not hmac.compare_digest(request.headers.get("authorization", ""), "Bearer " + control_token):
            return await call_next(request)
        try:
            body=await request.json()
        except ValueError:
            return await call_next(request)
        key=body.get("suite_id") or body.get("execution_id") or request.headers.get("x-progress-id")
        if not isinstance(key,str):
            return await call_next(request)
        selected=request.headers.get("x-preview-case")
        total=len(body.get("cases",body.get("execution_ids",[]))) or len(CASES)
        state={"suite_id":key,"phase":"running","cases":[],"current_case":None,"total":1 if selected else total,"selected":selected}
        if len(_NATIVE_PROGRESS)>=32:
            removable=next((k for k,v in _NATIVE_PROGRESS.items() if v["phase"]=="finished"),None)
            if removable:_NATIVE_PROGRESS.pop(removable)
        _NATIVE_PROGRESS[key]=state
        context=_NATIVE_CONTEXT.set(state)
        try:
            return await call_next(request)
        finally:
            state["phase"]="finished";state["current_case"]=None
            _NATIVE_CONTEXT.reset(context)
    @application.get("/v1/progress/{suite_id}")
    async def native_progress_snapshot(suite_id:str, authorization:str|None=Header(default=None)):
        if not hmac.compare_digest(authorization or "", "Bearer " + control_token):
            raise HTTPException(401,"invalid progress credential")
        state=_NATIVE_PROGRESS.get(suite_id)
        if state is None:raise HTTPException(404,"execution not started")
        return {k:v for k,v in state.items() if k!="selected"}

execute_case = _native_case(execute_case)
_install_native_progress(app, CONTROL_TOKEN)
