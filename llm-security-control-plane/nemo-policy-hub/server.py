"""NeMo policy hub HTTP API.

Authentication and RAG authorization remain Application responsibilities.
The hub owns guardrail ordering, model calls, and guardrail enforcement.
"""

from __future__ import annotations

import hmac
import json
import os
import time
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from hub_core import (
    LLAMA_GUARD_DIGEST,
    LLAMA_GUARD_MODEL,
    MAIN_DIGEST,
    MAIN_MODEL,
    POLICY,
    call_main_model,
    run_input_rails,
    run_output_rails,
    verify_model_lock,
)
from telemetry import configure_telemetry


def env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    return default if value is None else value.strip().lower() in {"1", "true", "yes", "on"}


GUARD_MODE = os.getenv("GUARD_MODE", "enforce").strip().lower()
if GUARD_MODE not in {"off", "audit", "enforce"}:
    raise RuntimeError("GUARD_MODE must be off, audit, or enforce")
ASSURANCE_PROFILE = os.getenv("ASSURANCE_PROFILE", "high-assurance").strip().lower()
if ASSURANCE_PROFILE not in POLICY["profiles"]:
    raise RuntimeError("ASSURANCE_PROFILE must be standard or high-assurance")
APPLICATION_INTERNAL_TOKEN = os.getenv("APPLICATION_INTERNAL_TOKEN", "")
PRESIDIO_INTERNAL_TOKEN = os.getenv("PRESIDIO_INTERNAL_TOKEN", "")
if not APPLICATION_INTERNAL_TOKEN or not PRESIDIO_INTERNAL_TOKEN:
    raise RuntimeError("both internal service tokens are required")
PRESIDIO_URL = os.getenv("PRESIDIO_URL", "http://10.0.2.2:18093").rstrip("/")
ENABLE_LAB_ENDPOINTS = env_bool("ENABLE_LAB_ENDPOINTS", False)
RELEASE_VERSION = os.getenv("RELEASE_VERSION", "1.0.0")
PROHIBITED_ENTITIES = set(POLICY["prohibited_entities"])
RUNTIME = {"model_lock": {"valid": False, "error": "startup-not-complete"}}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    try:
        RUNTIME["model_lock"] = await verify_model_lock()
    except Exception as exc:
        RUNTIME["model_lock"] = {"valid": False, "error": type(exc).__name__}
    yield


app = FastAPI(
    title="NeMo policy hub",
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)
configure_telemetry(app, "llm-security-nemo-hub")


class Principal(BaseModel):
    model_config = ConfigDict(extra="forbid")
    subject: str = Field(min_length=1, max_length=100)
    roles: list[str] = Field(min_length=1, max_length=10)


class RetrievalContext(BaseModel):
    model_config = ConfigDict(extra="forbid")
    classification: str = Field(pattern="^(public|internal|restricted)$")
    purpose: str = Field(min_length=1, max_length=100)
    chunks: list[str] = Field(min_length=1, max_length=10)
    exact_value_required: bool = False
    authorized_by: str = Field(pattern="^application-policy$")


class HubChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    message: str = Field(min_length=1, max_length=20000)
    request_id: str = Field(min_length=8, max_length=128)
    principal: Principal
    retrieval: RetrievalContext | None = None


class OutputCandidateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    prompt: str = Field(min_length=1, max_length=20000)
    model_output: str = Field(min_length=1, max_length=50000)
    request_id: str = Field(min_length=8, max_length=128)


def require_internal_token(authorization: str | None) -> None:
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(token, APPLICATION_INTERNAL_TOKEN):
        raise HTTPException(status_code=401, detail="application service token required")


def require_ready() -> None:
    if not RUNTIME["model_lock"].get("valid"):
        raise HTTPException(status_code=503, detail="Ollama model digest lock mismatch")


def emit_metadata(event: dict) -> None:
    print(json.dumps(event, ensure_ascii=False, separators=(",", ":")), flush=True)


async def analyze_privacy(stage: str, text: str, request_id: str) -> dict:
    last_error: Exception | None = None
    for _attempt in range(int(POLICY["execution"]["spoke_read_retry_count"]) + 1):
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as client:
                response = await client.post(
                    f"{PRESIDIO_URL}/api/analyze",
                    headers={"Authorization": f"Bearer {PRESIDIO_INTERNAL_TOKEN}"},
                    json={"stage": stage, "text": text, "request_id": request_id},
                )
                response.raise_for_status()
                result = response.json()
            if (
                not isinstance(result, dict)
                or result.get("request_id") != request_id
                or result.get("stage") != stage
                or not isinstance(result.get("sanitized_candidate"), str)
                or not isinstance(result.get("entity_types"), list)
            ):
                raise ValueError("invalid Presidio spoke contract")
            return result
        except (httpx.HTTPError, ValueError) as exc:
            last_error = exc
    raise RuntimeError("Presidio spoke failed closed") from last_error


def stage_record(stage: str, engine: str, decision: str, **extra) -> dict:
    return {"stage": stage, "engine": engine, "decision": decision, **extra}


def result_record(
    *,
    request_id: str,
    reply: str,
    decision: str,
    blocking_reason: str | None,
    upstream_called: bool,
    stages: list[dict],
    started: float,
) -> dict:
    guard_model_calls = sum(
        int(stage.get("metrics", {}).get("llm_calls_count", 0)) for stage in stages
    )
    return {
        "request_id": request_id,
        "reply": reply,
        "guardrail": {
            "engine": "nemo-policy-hub",
            "mode": GUARD_MODE,
            "assurance_profile": ASSURANCE_PROFILE,
            "decision": decision,
            "blocking_reason": blocking_reason,
            "upstream_called": upstream_called,
            "guard_model_calls": guard_model_calls,
            "stage_order": [stage["stage"] for stage in stages],
            "stages": stages,
            "policy_id": POLICY["policy_id"],
            "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        },
    }


async def evaluate_output(
    prompt: str,
    candidate: str,
    request_id: str,
    allowed_exact_sources: list[str] | None = None,
) -> tuple[str, list[dict], str | None]:
    stages: list[dict] = []
    output_rails = await run_output_rails(prompt, candidate, ASSURANCE_PROFILE)
    stages.append(
        stage_record(
            "nemo_output_rails",
            "llama-guard+self-check" if ASSURANCE_PROFILE == "high-assurance" else "llama-guard",
            "allow" if output_rails["valid"] else "block",
            activated_rails=output_rails["activated_rails"],
            metrics=output_rails["metrics"],
        )
    )
    if not output_rails["valid"]:
        return candidate, stages, f"output:{output_rails['blocking_rail']}"

    privacy = await analyze_privacy("output", candidate, request_id)
    exact_sources = allowed_exact_sources or []
    detected_values = [
        candidate[item["start"]:item["end"]]
        for item in privacy["detections"]
    ]
    all_detections_are_authorized = bool(detected_values) and all(
        any(value in source for source in exact_sources)
        for value in detected_values
    )
    if all_detections_are_authorized:
        privacy_decision = "allow_unredacted"
        checked_candidate = candidate
    elif privacy["entity_types"]:
        privacy_decision = "redact"
        checked_candidate = privacy["sanitized_candidate"]
    else:
        privacy_decision = "allow"
        checked_candidate = candidate
    stages.append(
        stage_record(
            "presidio_output",
            "presidio-privacy-spoke",
            privacy_decision,
            entity_types=privacy["entity_types"],
            detection_count=len(privacy["detections"]),
        )
    )
    return checked_candidate, stages, None


@app.get("/healthz")
async def healthz() -> dict:
    return {
        "ok": bool(RUNTIME["model_lock"].get("valid")),
        "service": "nemo-policy-hub",
        "version": RELEASE_VERSION,
        "guard_mode": GUARD_MODE,
        "assurance_profile": ASSURANCE_PROFILE,
        "model_lock_valid": bool(RUNTIME["model_lock"].get("valid")),
    }


@app.get("/api/guardrails/policy")
async def policy() -> dict:
    return {
        "service": "nemo-policy-hub",
        "version": RELEASE_VERSION,
        "guard_mode": GUARD_MODE,
        "assurance_profile": ASSURANCE_PROFILE,
        "canonical_source": "llm-security-control-plane/policies/nemo-policy.yaml",
        "runtime_source": "llm-security-control-plane/nemo-policy-hub/hub_core.py",
        "profiles": POLICY["profiles"],
        "execution": POLICY["execution"],
        "stages": POLICY["stages"],
        "models": {
            "main": {"tag": MAIN_MODEL, "digest": MAIN_DIGEST},
            "llama_guard": {"tag": LLAMA_GUARD_MODEL, "digest": LLAMA_GUARD_DIGEST},
        },
        "runtime_model_lock": RUNTIME["model_lock"],
        "lab_endpoints": ENABLE_LAB_ENDPOINTS,
    }


@app.post("/api/chat")
async def chat(
    request: HubChatRequest,
    authorization: str | None = Header(default=None),
) -> dict:
    require_internal_token(authorization)
    require_ready()
    started = time.perf_counter()
    stages: list[dict] = []
    upstream_called = False
    allowed_exact_sources: list[str] = []

    try:
        message_for_model = request.message
        context_for_model = None

        if GUARD_MODE != "off":
            privacy_input = await analyze_privacy("input", request.message, request.request_id)
            input_entities = set(privacy_input["entity_types"])
            prohibited = sorted(input_entities & PROHIBITED_ENTITIES)
            input_decision = "block" if prohibited else ("redact" if input_entities else "allow")
            stages.append(
                stage_record(
                    "presidio_input",
                    "presidio-privacy-spoke",
                    input_decision,
                    entity_types=privacy_input["entity_types"],
                    detection_count=len(privacy_input["detections"]),
                )
            )
            if prohibited and GUARD_MODE == "enforce":
                result = result_record(
                    request_id=request.request_id,
                    reply="금지된 자격 증명 또는 고위험 식별자가 탐지되어 차단되었습니다.",
                    decision="block",
                    blocking_reason=f"input:prohibited:{','.join(prohibited)}",
                    upstream_called=False,
                    stages=stages,
                    started=started,
                )
                emit_metadata({"event": "hub_chat", **result["guardrail"], "request_id": request.request_id})
                return result
            if GUARD_MODE == "enforce":
                message_for_model = privacy_input["sanitized_candidate"]

            input_rails = await run_input_rails(message_for_model, ASSURANCE_PROFILE)
            stages.append(
                stage_record(
                    "nemo_input_rails",
                    "llama-guard+self-check" if ASSURANCE_PROFILE == "high-assurance" else "llama-guard",
                    "allow" if input_rails["valid"] else "block",
                    activated_rails=input_rails["activated_rails"],
                    metrics=input_rails["metrics"],
                )
            )
            if not input_rails["valid"] and GUARD_MODE == "enforce":
                result = result_record(
                    request_id=request.request_id,
                    reply="요청이 NeMo 입력 가드레일에 의해 차단되었습니다.",
                    decision="block",
                    blocking_reason=f"input:{input_rails['blocking_rail']}",
                    upstream_called=False,
                    stages=stages,
                    started=started,
                )
                emit_metadata({"event": "hub_chat", **result["guardrail"], "request_id": request.request_id})
                return result

            if request.retrieval:
                joined = "\n\n".join(request.retrieval.chunks)
                privacy_retrieval = await analyze_privacy("retrieval", joined, request.request_id)
                retrieval_entities = set(privacy_retrieval["entity_types"])
                prohibited = sorted(retrieval_entities & PROHIBITED_ENTITIES)
                if prohibited:
                    retrieval_decision = "block"
                elif request.retrieval.exact_value_required:
                    retrieval_decision = "allow_unredacted"
                    allowed_exact_sources = list(request.retrieval.chunks)
                elif retrieval_entities:
                    retrieval_decision = "redact"
                else:
                    retrieval_decision = "allow"
                stages.append(
                    stage_record(
                        "presidio_retrieval",
                        "presidio-privacy-spoke",
                        retrieval_decision,
                        classification=request.retrieval.classification,
                        purpose=request.retrieval.purpose,
                        entity_types=privacy_retrieval["entity_types"],
                        detection_count=len(privacy_retrieval["detections"]),
                    )
                )
                if prohibited and GUARD_MODE == "enforce":
                    result = result_record(
                        request_id=request.request_id,
                        reply="금지된 비밀값이 검색 문서에서 탐지되어 차단되었습니다.",
                        decision="block",
                        blocking_reason=f"retrieval:prohibited:{','.join(prohibited)}",
                        upstream_called=False,
                        stages=stages,
                        started=started,
                    )
                    emit_metadata({"event": "hub_chat", **result["guardrail"], "request_id": request.request_id})
                    return result
                if GUARD_MODE == "enforce" and retrieval_decision == "redact":
                    context_for_model = privacy_retrieval["sanitized_candidate"]
                else:
                    context_for_model = joined

        elif request.retrieval:
            context_for_model = "\n\n".join(request.retrieval.chunks)

        upstream_called = True
        reply = await call_main_model(message_for_model, context_for_model)
        stages.append(stage_record("ollama_main", "ollama", "called", model=MAIN_MODEL))

        final_reply = reply
        blocking_reason = None
        decision = "allow"
        if GUARD_MODE != "off":
            checked_reply, output_stages, output_reason = await evaluate_output(
                message_for_model,
                reply,
                request.request_id,
                allowed_exact_sources,
            )
            stages.extend(output_stages)
            if output_reason and GUARD_MODE == "enforce":
                decision = "block"
                blocking_reason = output_reason
                final_reply = "생성 결과가 NeMo 출력 가드레일에 의해 차단되었습니다."
            elif GUARD_MODE == "enforce":
                final_reply = checked_reply
                if checked_reply != reply:
                    decision = "redact"

        result = result_record(
            request_id=request.request_id,
            reply=final_reply,
            decision=decision,
            blocking_reason=blocking_reason,
            upstream_called=upstream_called,
            stages=stages,
            started=started,
        )
        emit_metadata({"event": "hub_chat", **result["guardrail"], "request_id": request.request_id})
        return result
    except Exception as exc:
        result = result_record(
            request_id=request.request_id,
            reply="guardrail infrastructure unavailable",
            decision="infra",
            blocking_reason=f"guardrail_dependency:{type(exc).__name__}",
            upstream_called=upstream_called,
            stages=stages,
            started=started,
        )
        emit_metadata({"event": "hub_chat", **result["guardrail"], "request_id": request.request_id})
        return result


@app.post("/api/labs/output-candidate")
async def output_candidate(
    request: OutputCandidateRequest,
    authorization: str | None = Header(default=None),
) -> dict:
    require_internal_token(authorization)
    if not ENABLE_LAB_ENDPOINTS:
        raise HTTPException(status_code=404, detail="lab endpoint disabled")
    require_ready()
    started = time.perf_counter()
    checked, stages, reason = await evaluate_output(
        request.prompt,
        request.model_output,
        request.request_id,
    )
    return result_record(
        request_id=request.request_id,
        reply=checked if reason is None else "생성 결과가 출력 가드레일에 의해 차단되었습니다.",
        decision="allow" if reason is None else "block",
        blocking_reason=reason,
        upstream_called=False,
        stages=stages,
        started=started,
    )
