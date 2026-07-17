#!/usr/bin/env python3
"""Loopback-oriented HTTP integration API for NeMo Guardrails."""

from __future__ import annotations

import json
import os
import time
import uuid

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from nemo_core import (
    DEFAULT_MODEL,
    FRAMEWORK,
    FRAMEWORK_VERSION,
    run_input_only,
    run_main_only,
    run_output_only,
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
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://host.containers.internal:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", DEFAULT_MODEL)

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


def emit(event: dict) -> None:
    print(json.dumps(event, ensure_ascii=False, separators=(",", ":")), flush=True)


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
        "ollama_model": OLLAMA_MODEL,
    }


@app.get("/api/guardrails/policy")
async def policy() -> dict:
    return {
        "guard_engine": "nemo",
        "guard_mode": GUARD_MODE,
        "canonical_sources": [
            "/app/config/integrated/config.yml",
            "/app/nemo_core.py",
        ],
        "runtime_activation": "/app/server.py:chat",
        "apply_change": "recreate the container after changing YAML or environment values",
        "rollback": "recreate the previous image and environment set",
        "lab_endpoints": ENABLE_LAB_ENDPOINTS,
        "model": OLLAMA_MODEL,
        "ollama_url": OLLAMA_URL,
        "rails": {"input": ["self check input"], "output": ["self check output"]},
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
        guardrail["stage_order"] = ["input_rail", "ollama_main", "output_rail"]
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
