#!/usr/bin/env python3
"""Loopback-oriented HTTP integration API for NeMo Guardrails."""

from __future__ import annotations

import json
import hmac
import os
import time
import uuid

import httpx
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from nemo_core import (
    DEFAULT_MODEL,
    FRAMEWORK,
    FRAMEWORK_VERSION,
    run_input_only,
    run_dialog,
    run_main_only,
    run_output_only,
    run_retrieval,
    run_retrieval_details,
    run_suite,
)


def env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


GUARD_MODE = os.getenv("GUARD_MODE", "enforce").strip().lower()
if GUARD_MODE not in {"off", "audit", "enforce"}:
    raise RuntimeError("GUARD_MODE must be off, audit, or enforce")
GUARD_ENGINE = os.getenv("GUARD_ENGINE", "nemo").strip().lower()
if GUARD_ENGINE not in {"nemo", "off"}:
    raise RuntimeError("NeMo image supports GUARD_ENGINE=nemo or off")
ENABLE_LAB_ENDPOINTS = env_bool("ENABLE_LAB_ENDPOINTS", False)
BEDROCK_MODEL_ID = os.getenv("BEDROCK_MODEL_ID", DEFAULT_MODEL)
MODEL_GATEWAY_URL = os.getenv(
    "MODEL_GATEWAY_URL", "http://llm-security-bedrock-gateway:8080"
).rstrip("/")
SECURITY_MONITOR_URL = os.getenv("SECURITY_MONITOR_URL", "").rstrip("/")
TELEMETRY_INGEST_TOKEN = os.getenv(
    "TELEMETRY_INGEST_TOKEN", "module08-telemetry-ingest"
)
CLASSIFIED_RAG_INTERNAL_TOKEN = os.getenv(
    "CLASSIFIED_RAG_INTERNAL_TOKEN",
    "day7-classified-rag-internal",
)

app = FastAPI(title="Day 6 NeMo Guardrails integration API")


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scanner: str = "input-rail"
    text: str = Field(min_length=1, max_length=20000)


class OutputScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    prompt: str = Field(min_length=1, max_length=20000)
    model_output: str = Field(min_length=1, max_length=50000)


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    message: str = Field(min_length=1, max_length=20000)


class DialogRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    message: str = Field(min_length=1, max_length=20000)


class RetrievalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    chunks: list[str] = Field(min_length=1, max_length=20)


class ClassifiedRetrievalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    chunks: list[str] = Field(min_length=1, max_length=20)
    classification: str = Field(pattern="^(public|restricted)$")
    handling_policy: str = Field(
        pattern="^allow-exact-after-application-authorization$"
    )


def emit(event: dict) -> None:
    print(json.dumps(event, ensure_ascii=False, separators=(",", ":")), flush=True)
    if not SECURITY_MONITOR_URL:
        return
    try:
        httpx.post(
            f"{SECURITY_MONITOR_URL}/api/events/guardrail",
            headers={"X-Telemetry-Token": TELEMETRY_INGEST_TOKEN},
            json=event,
            timeout=2.0,
        ).raise_for_status()
    except httpx.HTTPError as exc:
        print(
            json.dumps(
                {
                    "event": "security_monitor_forward_failed",
                    "error": type(exc).__name__,
                },
                separators=(",", ":"),
            ),
            flush=True,
        )


def require_lab_endpoint() -> None:
    if not ENABLE_LAB_ENDPOINTS:
        raise HTTPException(status_code=404, detail="lab endpoint disabled")


def guardrail_record(
    *, decision: str, input_checks: list[dict], output_checks: list[dict],
    upstream_called: bool, duration_ms: float, blocking_reason: str | None,
    guard_model_calls: int,
) -> dict:
    return {
        "engine": "nemo" if GUARD_ENGINE != "off" else "off",
        "framework": FRAMEWORK,
        "framework_version": FRAMEWORK_VERSION,
        "mode": GUARD_MODE,
        "decision": decision,
        "input_checks": input_checks,
        "output_checks": output_checks,
        "upstream_called": upstream_called,
        "guard_model_calls": guard_model_calls,
        "duration_ms": duration_ms,
        "blocking_reason": blocking_reason,
    }


@app.get("/healthz")
async def healthz() -> dict:
    return {
        "ok": True,
        "guard_engine": "nemo" if GUARD_ENGINE != "off" else "off",
        "guard_mode": GUARD_MODE,
        "lab_endpoints": ENABLE_LAB_ENDPOINTS,
        "bedrock_model": BEDROCK_MODEL_ID,
        "security_monitoring": bool(SECURITY_MONITOR_URL),
    }


@app.get("/api/guardrails/policy")
async def policy() -> dict:
    return {
        "guard_engine": "nemo",
        "guard_mode": GUARD_MODE,
        "canonical_sources": [
            "/app/config/integrated/config.yml",
            "/app/config/dialog/flows.co",
            "/app/config/dialog/config.py",
            "/app/config/retrieval/flows.co",
            "/app/config/retrieval/config.py",
            "/app/nemo_core.py",
        ],
        "runtime_activation": "/app/server.py:chat",
        "apply_change": "recreate the container after changing YAML or environment values",
        "rollback": "recreate the previous image and environment set",
        "lab_endpoints": ENABLE_LAB_ENDPOINTS,
        "security_monitoring": {
            "enabled": bool(SECURITY_MONITOR_URL),
            "endpoint": "/api/events/guardrail" if SECURITY_MONITOR_URL else None,
            "failure_mode": "guardrail enforcement continues when forwarding fails",
        },
        "model": BEDROCK_MODEL_ID,
        "provider": "amazon-bedrock",
        "model_gateway_url": MODEL_GATEWAY_URL,
        "rails": {
            "input": ["self check input"],
            "dialog": ["Colang topic flow", "get_security_contact"],
            "retrieval": [
                "mask retrieval with Presidio",
                "detect without redaction after Application authorization",
            ],
            "output": ["self check output"],
        },
    }


@app.post("/api/scan")
async def scan(request: ScanRequest) -> dict:
    if request.scanner.strip().lower() not in {"input", "input-rail", "self-check-input"}:
        raise HTTPException(status_code=422, detail="scanner must select the NeMo input rail")
    started = time.perf_counter()
    reply, records, blocked_stage, metrics = await run_input_only(request.text)
    result = {
        "event": "guard_scan",
        "guard_engine": "nemo",
        "guard_mode": GUARD_MODE,
        "rail": "self check input",
        "original_text": request.text,
        "sanitized_text": request.text if not blocked_stage else reply,
        "valid": blocked_stage is None,
        "risk_score": None,
        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        "application_decision": "allow" if blocked_stage is None else "block",
        "activated_rails": records,
        "metrics": metrics,
        "blocking_reason": None if blocked_stage is None else "input:self check input",
    }
    emit(result)
    return result


@app.post("/api/scan-output")
async def scan_output(request: OutputScanRequest) -> dict:
    require_lab_endpoint()
    started = time.perf_counter()
    reply, records, blocked_stage, metrics = await run_output_only(
        request.prompt, request.model_output,
    )
    result = {
        "event": "guard_scan",
        "guard_engine": "nemo",
        "guard_mode": GUARD_MODE,
        "rail": "self check output",
        "input_prompt": request.prompt,
        "original_text": request.model_output,
        "sanitized_text": reply,
        "valid": blocked_stage is None,
        "risk_score": None,
        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        "application_decision": "allow" if blocked_stage is None else "block",
        "activated_rails": records,
        "metrics": metrics,
        "blocking_reason": None if blocked_stage is None else "output:self check output",
    }
    emit(result)
    return result


@app.post("/api/labs/suite")
async def labs_suite() -> dict:
    require_lab_endpoint()
    results, summary = await run_suite()
    for result in results:
        emit(result)
    emit(summary)
    return {"results": results, "summary": summary}


@app.post("/api/labs/dialog")
async def labs_dialog(request: DialogRequest) -> dict:
    """Exercise a Colang flow and a read-only custom action."""

    require_lab_endpoint()
    started = time.perf_counter()
    reply, activated, metrics = await run_dialog(request.message)
    result = {
        "event": "guard_dialog",
        "guard_engine": "nemo",
        "rail_type": "dialog",
        "reply": reply,
        "activated_rails": activated,
        "metrics": metrics,
        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
    }
    emit(result)
    return result


@app.post("/api/labs/retrieval")
async def labs_retrieval(request: RetrievalRequest) -> dict:
    """Mask PII in RAG chunks before they enter the generation prompt."""

    require_lab_endpoint()
    started = time.perf_counter()
    source = "\n\n".join(request.chunks)
    sanitized, activated, metrics = await run_retrieval(source)
    result = {
        "event": "guard_retrieval",
        "guard_engine": "nemo",
        "rail_type": "retrieval",
        "provider": "microsoft-presidio-http-action",
        "chunk_count": len(request.chunks),
        "sanitized_context": sanitized,
        "pii_removed": sanitized != source,
        "activated_rails": activated,
        "metrics": metrics,
        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
    }
    emit({key: value for key, value in result.items() if key != "sanitized_context"})
    return result


@app.post("/api/labs/retrieval-classified")
async def labs_retrieval_classified(
    request: ClassifiedRetrievalRequest,
    x_classified_rag_token: str | None = Header(default=None),
) -> dict:
    """Inspect chunks already selected and authorized by the Application."""

    require_lab_endpoint()
    if x_classified_rag_token is None or not hmac.compare_digest(
        x_classified_rag_token,
        CLASSIFIED_RAG_INTERNAL_TOKEN,
    ):
        raise HTTPException(status_code=401, detail="internal application token required")

    started = time.perf_counter()
    source = "\n\n".join(request.chunks)
    inspected = await run_retrieval_details(
        source,
        handling_policy=request.handling_policy,
    )
    result = {
        "event": "guard_retrieval_classified",
        "guard_engine": "nemo",
        "rail_type": "retrieval",
        "provider": "microsoft-presidio-http-action",
        "classification": request.classification,
        "handling_policy": request.handling_policy,
        "chunk_count": len(request.chunks),
        **inspected,
        "upstream_model_called": False,
        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
    }
    emit({key: value for key, value in result.items() if key != "context"})
    return result


@app.post("/api/chat")
async def chat(request: ChatRequest) -> dict:
    request_id = str(uuid.uuid4())
    started = time.perf_counter()
    input_checks: list[dict] = []
    output_checks: list[dict] = []
    guard_model_calls = 0
    guard_enabled = GUARD_ENGINE != "off" and GUARD_MODE != "off"
    upstream_called = False

    try:
        if guard_enabled:
            _, input_checks, input_blocked, input_metrics = await run_input_only(
                request.message,
            )
            guard_model_calls += int(input_metrics["llm_calls_count"])
            if input_blocked and GUARD_MODE == "enforce":
                duration = round((time.perf_counter() - started) * 1000, 2)
                guardrail = guardrail_record(
                    decision="block",
                    input_checks=input_checks,
                    output_checks=[],
                    upstream_called=False,
                    duration_ms=duration,
                    blocking_reason="input:self check input",
                    guard_model_calls=guard_model_calls,
                )
                emit({"event": "guardrail_chat", "request_id": request_id, **guardrail})
                return {
                    "reply": "요청이 NeMo input rail 정책에 의해 차단되었습니다.",
                    "guardrail": guardrail,
                }

        upstream_called = True
        reply, _main_metrics = await run_main_only(request.message)

        decision = "allow"
        blocking_reason = None
        if guard_enabled:
            checked_reply, output_checks, output_blocked, output_metrics = await run_output_only(
                request.message, reply,
            )
            guard_model_calls += int(output_metrics["llm_calls_count"])
            if output_blocked and GUARD_MODE == "enforce":
                decision = "block"
                blocking_reason = "output:self check output"
                reply = checked_reply

        duration = round((time.perf_counter() - started) * 1000, 2)
        guardrail = guardrail_record(
            decision=decision,
            input_checks=input_checks,
            output_checks=output_checks,
            upstream_called=upstream_called,
            duration_ms=duration,
            blocking_reason=blocking_reason,
            guard_model_calls=guard_model_calls,
        )
        guardrail["stage_order"] = ["input_rail", "bedrock_main", "output_rail"]
        emit({"event": "guardrail_chat", "request_id": request_id, **guardrail})
        return {"reply": reply, "guardrail": guardrail}
    except Exception as exc:
        duration = round((time.perf_counter() - started) * 1000, 2)
        guardrail = guardrail_record(
            decision="infra",
            input_checks=input_checks,
            output_checks=output_checks,
            upstream_called=upstream_called,
            duration_ms=duration,
            blocking_reason=f"rail_or_upstream_error:{type(exc).__name__}",
            guard_model_calls=guard_model_calls,
        )
        emit({"event": "guardrail_chat", "request_id": request_id, **guardrail})
        return {"reply": "guardrail infrastructure unavailable", "guardrail": guardrail}
