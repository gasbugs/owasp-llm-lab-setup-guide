"""Authenticated, fail-closed text API for the file-backed guardrail proxy."""

import asyncio
from collections import deque
import hashlib
import hmac
import json
import os
import re
from pathlib import Path
import time
from uuid import uuid4

from fastapi import FastAPI, Header, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator
import yaml

from gateway_model import CallTracker, GatewayModel, MODEL_ID
from native_rails import check_text


ROOT = Path("/app")
POLICY_FILES = ("policy.yaml", "nemo-policy/config.yml", "nemo-policy/prompts.yml")
digest = hashlib.sha256()
for filename in POLICY_FILES:
    digest.update(filename.encode() + b"\0" + (ROOT / filename).read_bytes())
POLICY_DIGEST = digest.hexdigest()
POLICY = yaml.safe_load((ROOT / "policy.yaml").read_text())
if (not isinstance(POLICY, dict) or POLICY.get("model_id") != MODEL_ID
        or POLICY.get("pii_input_action") != "redact"
        or POLICY.get("pii_output_action") != "redact"
        or POLICY.get("default_error_action") != "deny"
        or type(POLICY.get("max_input_chars")) is not int
        or not 1 <= POLICY["max_input_chars"] <= 4000
        or type(POLICY.get("max_output_chars")) is not int
        or not 1 <= POLICY["max_output_chars"] <= 8000
        or type(POLICY.get("max_concurrent_requests")) is not int
        or not 1 <= POLICY["max_concurrent_requests"] <= 8):
    raise ValueError("invalid active policy")
CALLER_TOKEN = os.environ["PROXY_CALLER_TOKEN"]
if (len(CALLER_TOKEN) < 40 or len({CALLER_TOKEN, os.environ["PROXY_GATEWAY_TOKEN"],
                                  os.environ["PROXY_PRIVACY_TOKEN"]}) != 3):
    raise ValueError("distinct caller and service tokens required")

LIMIT = asyncio.Semaphore(POLICY["max_concurrent_requests"])
REQUESTS = deque(maxlen=200)
app = FastAPI(title="Guardrail Proxy", docs_url=None, redoc_url=None)
app.mount("/console", StaticFiles(directory=ROOT / "ui", html=True), name="console")


@app.get("/")
def console_home():
    return RedirectResponse("/console/")


@app.middleware("http")
async def authenticate_before_parsing(request, call_next):
    if request.url.path.startswith("/v1/"):
        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() != "bearer" or not hmac.compare_digest(token, CALLER_TOKEN):
            return JSONResponse(status_code=401, content={"error": "caller authorization required"})
    return await call_next(request)


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    message: str = Field(min_length=1, max_length=POLICY["max_input_chars"])

    @field_validator("message")
    @classmethod
    def nonblank(cls, value):
        if not value.strip():
            raise ValueError("empty message")
        return value


@app.exception_handler(RequestValidationError)
async def validation_error(_request, _exc):
    return JSONResponse(status_code=422, content={"error": "invalid request shape or length"})


def require_caller(authorization):
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(token, CALLER_TOKEN):
        raise HTTPException(status_code=401, detail="caller authorization required")


async def privacy_scan(stage, text, request_id):
    async with httpx.AsyncClient(timeout=30, trust_env=False) as client:
        response = await client.post(
            os.environ["PRIVACY_URL"] + "/api/analyze",
            headers={"Authorization": "Bearer " + os.environ["PROXY_PRIVACY_TOKEN"]},
            json={"stage": stage, "text": text, "request_id": request_id},
        )
    if response.status_code != 200:
        raise ValueError(f"privacy status {response.status_code}")
    result = response.json()
    if (not isinstance(result, dict) or result.get("request_id") != request_id
            or result.get("stage") != stage or result.get("spoke") != "presidio-privacy"):
        raise ValueError("invalid privacy response identity")
    candidate = result.get("sanitized_candidate")
    entities = result.get("entity_types")
    detections = result.get("detections")
    valid = result.get("valid")
    if (not isinstance(candidate, str) or len(candidate) > 8000
            or not isinstance(entities, list) or not isinstance(detections, list)
            or type(valid) is not bool or valid != (len(detections) == 0)):
        raise ValueError("invalid privacy response shape")
    if not all(isinstance(entity, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{1,63}", entity)
               for entity in entities):
        raise ValueError("invalid privacy entity type")
    detected_types = set()
    for finding in detections:
        if not isinstance(finding, dict):
            raise ValueError("invalid privacy detection")
        entity = finding.get("entity_type")
        start, end = finding.get("start"), finding.get("end")
        if (entity not in entities or type(start) is not int or type(end) is not int
                or not 0 <= start < end <= len(text)):
            raise ValueError("invalid privacy detection")
        detected_types.add(entity)
        if text[start:end] in candidate:
            raise ValueError("detected text remains in privacy candidate")
    if detected_types != set(entities) or (not detections and candidate != text):
        raise ValueError("privacy decision and candidate disagree")
    return candidate, entities


def record(result):
    summary = {key: result[key] for key in (
        "request_id", "policy_digest", "decision", "stopped_at", "upstream_called", "stages")}
    summary["model_roles"] = [item["role"] for item in result["model_calls"]]
    REQUESTS.appendleft(summary)
    print(json.dumps({"event": "proxy_decision", **summary}, ensure_ascii=False,
                     separators=(",", ":")), flush=True)


@app.get("/healthz")
def healthz():
    return {"ok": True, "service": "guardrail-proxy", "policy_digest": POLICY_DIGEST}


@app.get("/v1/policy")
def active_policy(authorization: str | None = Header(default=None)):
    require_caller(authorization)
    return {"policy_id": POLICY["policy_id"], "name": POLICY["name"],
            "version": POLICY["version"], "digest": POLICY_DIGEST,
            "model_id": MODEL_ID, "stages": ["presidio_input", "nemo_input", "main",
                                            "nemo_output", "presidio_output"],
            "read_only": True}


@app.get("/v1/requests")
def recent_requests(authorization: str | None = Header(default=None)):
    require_caller(authorization)
    return {"policy_digest": POLICY_DIGEST, "requests": list(REQUESTS)}


@app.post("/v1/chat")
async def chat(body: ChatRequest, authorization: str | None = Header(default=None)):
    require_caller(authorization)
    try:
        await asyncio.wait_for(LIMIT.acquire(), timeout=2)
    except asyncio.TimeoutError:
        raise HTTPException(status_code=429, detail="request capacity reached") from None
    request_id = str(uuid4())
    tracker = CallTracker()
    stages = []
    current = "presidio_input"
    started = time.perf_counter()

    async def execute():
        nonlocal current
        text, entities = await privacy_scan("input", body.message, request_id)
        stages.append({"name": current, "result": "redacted" if entities else "passed",
                       "entities": entities})
        current = "nemo_input"
        input_rail = await check_text("input_rail", text, GatewayModel("input_rail", tracker))
        stages.append({"name": current, "result": "passed" if input_rail["allowed"] else "blocked",
                       "rail": input_rail["evidence"]["rail"]})
        if not input_rail["allowed"]:
            return "block", None
        current = "main"
        main = await GatewayModel("main", tracker).generate_async(
            "Give one short, safe account-recovery guidance answer to this request: " + text
        )
        stages.append({"name": current, "result": "called"})
        current = "nemo_output"
        output_rail = await check_text("output_rail", main.content,
                                       GatewayModel("output_rail", tracker))
        stages.append({"name": current, "result": "passed" if output_rail["allowed"] else "blocked",
                       "rail": output_rail["evidence"]["rail"]})
        if not output_rail["allowed"]:
            return "block", None
        current = "presidio_output"
        answer, entities = await privacy_scan("output", main.content, request_id)
        if len(answer) > POLICY["max_output_chars"]:
            raise ValueError("output exceeds policy limit")
        stages.append({"name": current, "result": "redacted" if entities else "passed",
                       "entities": entities})
        return "allow", answer

    try:
        decision, answer = await asyncio.wait_for(execute(), timeout=180)
        result = {"request_id": request_id, "policy_digest": POLICY_DIGEST,
                  "decision": decision, "answer": answer, "stopped_at": current,
                  "upstream_called": tracker.main_attempted, "stages": stages,
                  "model_calls": tracker.calls,
                  "elapsed_ms": round((time.perf_counter() - started) * 1000)}
        record(result)
        return result
    except Exception as exc:
        result = {"request_id": request_id, "policy_digest": POLICY_DIGEST,
                  "decision": "ERR", "stopped_at": current,
                  "upstream_called": tracker.main_attempted, "stages": stages,
                  "model_calls": tracker.calls,
                  "elapsed_ms": round((time.perf_counter() - started) * 1000)}
        record(result)
        return JSONResponse(status_code=502, content={**result, "error_type": type(exc).__name__})
    finally:
        LIMIT.release()
