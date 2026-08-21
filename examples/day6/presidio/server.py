#!/usr/bin/env python3
"""Loopback HTTP integration API for Presidio around NeMo or Ollama."""

from __future__ import annotations

import json
import hashlib
import os
import time
import uuid

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from presidio_core import FRAMEWORK, FRAMEWORK_VERSION, PresidioCore, env_bool
from secure_coding import select_personal_data_policy


# Mode는 탐지 결과를 실제 응답에 집행할지 결정한다. 잘못된 값은 시작 시 거부한다.
GUARD_MODE = os.getenv("GUARD_MODE", "enforce").strip().lower()
if GUARD_MODE not in {"off", "audit", "enforce"}:
    raise RuntimeError("GUARD_MODE must be off, audit, or enforce")
GUARD_ENGINE = os.getenv("GUARD_ENGINE", "presidio").strip().lower()
if GUARD_ENGINE not in {"presidio", "off"}:
    raise RuntimeError("Presidio image supports GUARD_ENGINE=presidio or off")
ENABLE_LAB_ENDPOINTS = env_bool("ENABLE_LAB_ENDPOINTS", False)
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://host.containers.internal:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1:8b-instruct-q4_K_M")
NEMO_GUARD_URL = os.getenv("NEMO_GUARD_URL", "").rstrip("/")
SECURITY_MONITOR_URL = os.getenv("SECURITY_MONITOR_URL", "").rstrip("/")
TELEMETRY_INGEST_TOKEN = os.getenv(
    "TELEMETRY_INGEST_TOKEN", "module08-telemetry-ingest"
)
POLICY_VERSION = os.getenv("GUARD_POLICY_VERSION", "day7-guardrails-v1")
TEST_CORPUS_VERSION = os.getenv("GUARD_TEST_CORPUS_VERSION", "day7-regression-v1")
MODEL_DIGEST = os.getenv("OLLAMA_MODEL_DIGEST", "runtime-query-required")
SYSTEM_PROMPT = (
    "You are a concise privacy training assistant. "
    "Never invent personal data or credentials."
)
SYSTEM_PROMPT_SHA256 = hashlib.sha256(SYSTEM_PROMPT.encode("utf-8")).hexdigest()
CORE = PresidioCore()

app = FastAPI(title="Day 6 Microsoft Presidio integration API")


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(min_length=1, max_length=20000)
    entities: list[str] | None = None


class OutputScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    prompt: str = Field(min_length=1, max_length=20000)
    model_output: str = Field(min_length=1, max_length=50000)
    entities: list[str] | None = None


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    message: str = Field(min_length=1, max_length=20000)


class SupportActionCandidate(BaseModel):
    """The only structured output shape accepted by the workshop application."""

    model_config = ConfigDict(extra="forbid")
    answer: str = Field(min_length=1, max_length=2000)
    links: list[str] = Field(default_factory=list, max_length=5)


class OutputContractRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    model_output: dict


# 사용자·모델 원문은 구조화 로그와 Module 08 전달 이벤트에서 제거한다.
LOG_CONTENT_FIELDS = {
    "input",
    "input_prompt",
    "message",
    "model_output",
    "original_text",
    "prompt",
    "reply",
    "sanitized_text",
}


def metadata_only(value):
    """Recursively remove user and model content before logging or forwarding."""
    if isinstance(value, dict):
        return {
            key: metadata_only(item)
            for key, item in value.items()
            if key not in LOG_CONTENT_FIELDS
        }
    if isinstance(value, list):
        return [metadata_only(item) for item in value]
    return value


def scan_metadata(result: dict) -> dict:
    """Return chat-safe scan evidence without raw or sanitized content."""
    return metadata_only(result)


def emit(event: dict) -> None:
    # 로컬 로그와 원격 모니터링에 동일한 metadata-only 사건을 전달한다.
    # 모니터링 장애는 로그로 남기되 이미 수행 중인 가드레일 집행을 약화시키지 않는다.
    safe_event = metadata_only(event)
    print(json.dumps(safe_event, ensure_ascii=False, separators=(",", ":")), flush=True)
    if not SECURITY_MONITOR_URL:
        return
    try:
        httpx.post(
            f"{SECURITY_MONITOR_URL}/api/events/guardrail",
            headers={"X-Telemetry-Token": TELEMETRY_INGEST_TOKEN},
            json=safe_event,
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


async def call_ollama(message: str) -> str:
    # Presidio 검사를 통과한 문자열만 Main Model 요청의 user content로 사용한다.
    async with httpx.AsyncClient(timeout=httpx.Timeout(180.0)) as client:
        response = await client.post(
            f"{OLLAMA_URL}/api/chat",
            json={
                "model": OLLAMA_MODEL,
                "stream": False,
                "options": {"num_predict": 160},
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            SYSTEM_PROMPT
                        ),
                    },
                    {"role": "user", "content": message},
                ],
            },
        )
        response.raise_for_status()
        return str(response.json()["message"]["content"])


async def call_model_path(message: str) -> tuple[str, dict | None, list[str]]:
    """Send sanitized input through NeMo when its URL is configured."""
    # NeMo URL이 없을 때만 Ollama를 직접 호출한다. URL이 있으면 NeMo 계약과
    # infra 판정을 검증하고 Main Model이 실제 호출된 stage만 기록한다.
    if not NEMO_GUARD_URL:
        return await call_ollama(message), None, ["ollama_main"]

    async with httpx.AsyncClient(timeout=httpx.Timeout(240.0)) as client:
        response = await client.post(
            f"{NEMO_GUARD_URL}/api/chat",
            json={"message": message},
        )
        response.raise_for_status()
        payload = response.json()
    guardrail = payload.get("guardrail")
    if not isinstance(payload.get("reply"), str) or not isinstance(guardrail, dict):
        raise ValueError("NeMo guardrail returned an invalid contract")
    if guardrail.get("decision") == "infra":
        raise RuntimeError("NeMo guardrail failed closed")
    model_stages = ["nemo_input"]
    if guardrail.get("upstream_called") is True:
        model_stages.extend(["ollama_main", "nemo_output"])
    return str(payload["reply"]), guardrail, model_stages


def base_guardrail(*, decision: str, upstream_called: bool, duration_ms: float) -> dict:
    return {
        "engine": "presidio" if GUARD_ENGINE != "off" else "off",
        "framework": FRAMEWORK,
        "framework_version": FRAMEWORK_VERSION,
        "mode": GUARD_MODE,
        "decision": decision,
        "input_checks": [],
        "output_checks": [],
        "upstream_called": upstream_called,
        "duration_ms": duration_ms,
        "blocking_reason": None,
        "policy_version": POLICY_VERSION,
        "test_corpus_version": TEST_CORPUS_VERSION,
        "model": OLLAMA_MODEL,
        "model_digest": MODEL_DIGEST,
        "system_prompt_sha256": SYSTEM_PROMPT_SHA256,
    }


@app.get("/healthz")
async def healthz() -> dict:
    return {
        "ok": True,
        "guard_engine": "presidio" if GUARD_ENGINE != "off" else "off",
        "guard_mode": GUARD_MODE,
        "lab_endpoints": ENABLE_LAB_ENDPOINTS,
        "ollama_model": OLLAMA_MODEL,
        "upstream_path": "nemo>ollama" if NEMO_GUARD_URL else "ollama",
        "nemo_guard_url": NEMO_GUARD_URL or None,
        "security_monitoring": bool(SECURITY_MONITOR_URL),
        "policy_version": POLICY_VERSION,
    }


@app.get("/api/guardrails/policy")
async def policy() -> dict:
    settings = CORE.settings.as_public_dict()
    return {
        "guard_engine": "presidio",
        "framework": FRAMEWORK,
        "framework_version": FRAMEWORK_VERSION,
        "guard_mode": GUARD_MODE,
        "policy_version": POLICY_VERSION,
        "test_corpus_version": TEST_CORPUS_VERSION,
        "runtime_identity": {
            "model": OLLAMA_MODEL,
            "model_digest": MODEL_DIGEST,
            "system_prompt_sha256": SYSTEM_PROMPT_SHA256,
        },
        "output_contract": {
            "source": "examples/day6/presidio/server.py:SupportActionCandidate",
            "additional_properties": False,
            "required": ["answer"],
            "optional": ["links"],
        },
        "canonical_source": "examples/day6/presidio/presidio_core.py",
        "container_source": "/app/presidio_core.py",
        "runtime_activation": "/app/server.py:chat",
        "apply_change": "rebuild the image after source changes or recreate it for environment changes",
        "rollback": "recreate the previous image and environment set",
        "lab_endpoints": ENABLE_LAB_ENDPOINTS,
        "security_monitoring": {
            "enabled": bool(SECURITY_MONITOR_URL),
            "endpoint": "/api/events/guardrail" if SECURITY_MONITOR_URL else None,
            "failure_mode": "guardrail enforcement continues when forwarding fails",
        },
        "entities": settings["analyzer"]["entities"],
        "score_threshold": settings["analyzer"]["score_threshold"],
        "settings": settings,
        "upstream_path": "nemo>ollama" if NEMO_GUARD_URL else "ollama",
    }


@app.post("/api/scan")
async def scan(request: ScanRequest) -> dict:
    # 임의 입력을 검사하는 독립 API다. 이 endpoint 자체는 Model을 호출하지 않는다.
    try:
        result = CORE.scan_input(request.text, request.entities)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    result.update(
        {
            "scanner": "PresidioAnalyzer+Anonymizer",
            "guard_engine": "presidio",
            "guard_mode": GUARD_MODE,
            "upstream_called": False,
            "blocking_reason": None if result["valid"] else "input:pii_detected",
        }
    )
    emit(result)
    return result


@app.post("/api/labs/secure-coding/scan")
async def secure_coding_scan(request: ScanRequest) -> dict:
    # 취약·안전 호출을 전환해 같은 입력의 raw passthrough와 redaction을 비교한다.
    require_lab_endpoint()

    result = select_personal_data_policy(request.text, CORE.scan_input)

    emit(result)
    return result


@app.post("/api/scan-output")
async def scan_output(request: OutputScanRequest) -> dict:
    # 이미 생성됐다고 가정한 Model 출력 후보를 Browser 전달 전에 별도로 검사한다.
    require_lab_endpoint()
    try:
        result = CORE.scan_output(
            request.prompt,
            request.model_output,
            request.entities,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    result.update(
        {
            "scanner": "PresidioAnalyzer+Anonymizer",
            "guard_engine": "presidio",
            "guard_mode": GUARD_MODE,
            "upstream_called": False,
            "blocking_reason": None if result["valid"] else "output:pii_detected",
        }
    )
    emit(result)
    return result


@app.post("/api/labs/validate-output-contract")
async def validate_output_contract(request: OutputContractRequest) -> dict:
    """Apply the server-owned structured output contract without calling a model."""

    require_lab_endpoint()
    started = time.perf_counter()
    try:
        accepted = SupportActionCandidate.model_validate(request.model_output)
    except Exception as exc:
        result = {
            "event": "output_contract_validation",
            "guard_engine": "python-pydantic",
            "policy_version": POLICY_VERSION,
            "valid": False,
            "application_decision": "block",
            "blocking_reason": "output-contract-invalid",
            "upstream_called": False,
            "duration_ms": round((time.perf_counter() - started) * 1000, 2),
            "error": type(exc).__name__,
        }
        emit(result)
        return result
    result = {
        "event": "output_contract_validation",
        "guard_engine": "python-pydantic",
        "policy_version": POLICY_VERSION,
        "valid": True,
        "application_decision": "allow",
        "blocking_reason": None,
        "upstream_called": False,
        "sanitized_output": accepted.model_dump(),
        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
    }
    emit(result)
    return result


@app.post("/api/labs/suite")
async def labs_suite() -> dict:
    require_lab_endpoint()
    results, summary = CORE.run_suite()
    for result in results:
        emit(result)
    emit(summary)
    return {**summary, "results": results, "summary": summary}


@app.post("/api/chat")
async def chat(request: ChatRequest) -> dict:
    request_id = str(uuid.uuid4())
    started = time.perf_counter()
    guard_enabled = GUARD_ENGINE != "off" and GUARD_MODE != "off"
    input_checks: list[dict] = []
    effective_message = request.message

    # 1) 입력 Rail: Enforce에서는 원문 대신 sanitized_text만 다음 계층으로 전달한다.
    if guard_enabled and CORE.settings.input_enabled:
        try:
            input_result = CORE.scan_input(request.message)
            input_checks.append(scan_metadata(input_result))
            if GUARD_MODE == "enforce":
                effective_message = str(input_result["sanitized_text"])
        except Exception as exc:
            # Analyzer 장애를 원문 통과로 처리하지 않는다. Enforce에서는 Model 호출 전에 닫는다.
            duration = round((time.perf_counter() - started) * 1000, 2)
            guardrail = base_guardrail(
                decision="infra",
                upstream_called=False,
                duration_ms=duration,
            )
            guardrail.update(
                {
                    "input_checks": [
                        {
                            "direction": "input",
                            "engine": "PresidioAnalyzer",
                            "application_decision": "infra",
                            "error": type(exc).__name__,
                        }
                    ],
                    "blocking_reason": f"analyzer_error:{type(exc).__name__}",
                }
            )
            emit({"event": "guardrail_chat", "request_id": request_id, **guardrail})
            if GUARD_MODE == "enforce":
                return {"reply": "privacy guardrail infrastructure unavailable", "guardrail": guardrail}

    # 2) Model 경로: 입력 검사가 완료된 effective_message만 NeMo 또는 Ollama에 전달한다.
    try:
        reply, inner_guardrail, model_stages = await call_model_path(effective_message)
    except Exception as exc:
        duration = round((time.perf_counter() - started) * 1000, 2)
        guardrail = base_guardrail(
            decision="infra",
            upstream_called=True,
            duration_ms=duration,
        )
        guardrail.update(
            {
                "input_checks": input_checks,
                "blocking_reason": f"upstream_error:{type(exc).__name__}",
            }
        )
        emit({"event": "guardrail_chat", "request_id": request_id, **guardrail})
        return {"reply": "upstream model unavailable", "guardrail": guardrail}

    output_checks: list[dict] = []
    # 3) 출력 Rail: Model 응답도 신뢰하지 않고 사용자에게 반환하기 전에 다시 검사한다.
    if guard_enabled and CORE.settings.output_enabled:
        try:
            output_result = CORE.scan_output(effective_message, reply)
            output_checks.append(scan_metadata(output_result))
            if GUARD_MODE == "enforce":
                reply = str(output_result["sanitized_text"])
        except Exception as exc:
            # 출력 검사가 실패하면 검사되지 않은 Model 원문을 사용자에게 보내지 않는다.
            duration = round((time.perf_counter() - started) * 1000, 2)
            guardrail = base_guardrail(
                decision="infra",
                upstream_called=True,
                duration_ms=duration,
            )
            guardrail.update(
                {
                    "input_checks": input_checks,
                    "output_checks": [
                        {
                            "direction": "output",
                            "engine": "PresidioAnalyzer",
                            "application_decision": "infra",
                            "error": type(exc).__name__,
                        }
                    ],
                    "blocking_reason": f"output_analyzer_error:{type(exc).__name__}",
                }
            )
            emit({"event": "guardrail_chat", "request_id": request_id, **guardrail})
            if GUARD_MODE == "enforce":
                return {"reply": "privacy output could not be inspected", "guardrail": guardrail}

    # 4) 최종 집행: 입력·출력 중 하나라도 PII를 찾으면 Enforce 판정은 redact다.
    pii_detected = any(not item.get("valid", True) for item in [*input_checks, *output_checks])
    decision = "redact" if pii_detected and GUARD_MODE == "enforce" else "allow"
    duration = round((time.perf_counter() - started) * 1000, 2)
    guardrail = base_guardrail(
        decision=decision,
        upstream_called=True,
        duration_ms=duration,
    )
    guardrail.update(
        {
            "input_checks": input_checks,
            "output_checks": output_checks,
            "blocking_reason": "pii_detected" if pii_detected else None,
            "stage_order": ["presidio_input", *model_stages, "presidio_output"],
            "path": "presidio>nemo>ollama>presidio" if NEMO_GUARD_URL else "presidio>ollama>presidio",
            "inner_guardrail": inner_guardrail,
        }
    )
    emit({"event": "guardrail_chat", "request_id": request_id, **guardrail})
    return {"reply": reply, "guardrail": guardrail}
