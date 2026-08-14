#!/usr/bin/env python3
"""Loopback-only LLM security event collector, policy API, and metrics endpoint."""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Literal

import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi import Header
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field

try:
    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
    from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
except ImportError:  # Unit policy tests do not install the runtime extras.
    trace = None

from policy_engine import (
    Decision,
    PolicyError,
    evaluate,
    load_policy,
    normalize_observed_decision,
    text_identity,
)


POLICY_PATH = Path(os.getenv("SECURITY_POLICY_PATH", "/app/policy.json"))
DATABASE_PATH = Path(os.getenv("SECURITY_EVENT_DB", "/data/security-events.db"))
ENABLE_LAB_ENDPOINTS = os.getenv("ENABLE_LAB_ENDPOINTS", "false").lower() in {
    "1", "true", "yes", "on"
}
POLICY = load_policy(POLICY_PATH)
STARTED_AT = time.time()
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://host.containers.internal:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1:8b-instruct-q4_K_M")
OTEL_ENDPOINT = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "").rstrip("/")
HTTP_TIMEOUT_SECONDS = float(os.getenv("UPSTREAM_TIMEOUT_SECONDS", "180"))
TOKEN_PRINCIPALS = {
    "llm-monitor-acme-token": {"subject": "acme-observer", "tenant": "acme", "dangerous_tools": []},
    "llm-monitor-admin-token": {"subject": "acme-operator", "tenant": "acme", "dangerous_tools": ["delete_animal"]},
}
CORPUS = (
    {
        "document_id": "acme/incident-response.md",
        "tenant": "acme",
        "text": "공개 사고 대응 절차는 탐지, 격리, 조사, 복구, 사후 검토 순서로 진행합니다.",
        "keywords": ("사고", "대응", "절차", "incident", "response"),
    },
    {
        "document_id": "beta/phoenix.md",
        "tenant": "beta",
        "text": "Beta Phoenix project launches on 2026-07-01.",
        "keywords": ("불사조", "phoenix", "경쟁", "beta"),
    },
)
REQUEST_WINDOWS: dict[str, list[float]] = {}
REQUEST_WINDOW_LOCK = threading.Lock()
SECURITY_LOGGER = logging.getLogger("llm.security")


def configure_telemetry() -> Any:
    if trace is None or not OTEL_ENDPOINT:
        return None
    resource = Resource.create({"service.name": "llm-security-gateway", "service.version": "2.0.0"})
    tracer_provider = TracerProvider(resource=resource)
    tracer_provider.add_span_processor(
        BatchSpanProcessor(OTLPSpanExporter(endpoint=f"{OTEL_ENDPOINT}/v1/traces"))
    )
    trace.set_tracer_provider(tracer_provider)

    logger_provider = LoggerProvider(resource=resource)
    logger_provider.add_log_record_processor(
        BatchLogRecordProcessor(OTLPLogExporter(endpoint=f"{OTEL_ENDPOINT}/v1/logs"))
    )
    SECURITY_LOGGER.setLevel(logging.INFO)
    SECURITY_LOGGER.handlers.clear()
    SECURITY_LOGGER.addHandler(LoggingHandler(level=logging.INFO, logger_provider=logger_provider))
    SECURITY_LOGGER.propagate = False
    return trace.get_tracer("llm-security-gateway")


TRACER = configure_telemetry()


@contextmanager
def telemetry_span(name: str, attributes: dict[str, Any] | None = None):
    if TRACER is None:
        yield None
        return
    with TRACER.start_as_current_span(name) as span:
        for key, value in (attributes or {}).items():
            if value is not None:
                span.set_attribute(key, value)
        yield span


def current_trace_id() -> str:
    if trace is None:
        return "0" * 32
    context = trace.get_current_span().get_span_context()
    return f"{context.trace_id:032x}" if context.is_valid else "0" * 32

app = FastAPI(title="LLM Security Observability Gateway", version="2.0.0")


class SecurityEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: str = Field(min_length=3, max_length=128)
    stage: Literal["input", "retrieval", "tool", "output", "guardrail", "runtime"]
    event_type: str = Field(min_length=2, max_length=128)
    text: str = Field(default="", max_length=50000)
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    detected_entities: list[str] = Field(default_factory=list)
    actor: str | None = Field(default=None, max_length=128)
    authenticated_tenant: str | None = Field(default=None, max_length=128)
    resource_tenant: str | None = Field(default=None, max_length=128)
    tool_name: str | None = Field(default=None, max_length=128)
    approval_status: str | None = Field(default=None, max_length=64)
    window_request_count: int = Field(default=0, ge=0, le=100000)
    upstream_called: bool | None = None
    duration_ms: float = Field(default=0.0, ge=0.0)
    application_decision: str | None = Field(default=None, max_length=32)
    policy_rule: str | None = Field(default=None, max_length=128)
    attributes: dict[str, Any] = Field(default_factory=dict)


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    message: str = Field(min_length=1, max_length=12000)
    request_id: str | None = Field(default=None, min_length=3, max_length=128)


class OutputCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(min_length=1, max_length=50000)
    request_id: str | None = Field(default=None, min_length=3, max_length=128)


def connect() -> sqlite3.Connection:
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
          id TEXT PRIMARY KEY,
          timestamp_ms INTEGER NOT NULL,
          request_id TEXT NOT NULL,
          stage TEXT NOT NULL,
          event_type TEXT NOT NULL,
          application_decision TEXT NOT NULL,
          policy_rule TEXT NOT NULL,
          severity TEXT NOT NULL,
          reason TEXT NOT NULL,
          risk_score REAL NOT NULL,
          sanitized_excerpt TEXT NOT NULL,
          input_sha256 TEXT NOT NULL,
          raw_stored INTEGER NOT NULL,
          policy_version TEXT NOT NULL,
          actor TEXT,
          authenticated_tenant TEXT,
          resource_tenant TEXT,
          tool_name TEXT,
          approval_status TEXT,
          upstream_called INTEGER,
          duration_ms REAL NOT NULL,
          attributes_json TEXT NOT NULL
        )
        """
    )
    connection.commit()
    return connection


def row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    value = dict(row)
    value["raw_stored"] = bool(value["raw_stored"])
    if value["upstream_called"] is not None:
        value["upstream_called"] = bool(value["upstream_called"])
    value["attributes"] = json.loads(value.pop("attributes_json"))
    return value


def persist(event: SecurityEvent, decision: Decision) -> dict[str, Any]:
    digest, excerpt, inferred_entities = text_identity(event.text)
    attributes = dict(event.attributes)
    if inferred_entities:
        attributes["redacted_entities"] = inferred_entities
    record = {
        "id": str(uuid.uuid4()),
        "timestamp_ms": int(time.time() * 1000),
        "request_id": event.request_id,
        "stage": event.stage,
        "event_type": event.event_type,
        "application_decision": decision.application_decision,
        "policy_rule": decision.policy_rule,
        "severity": decision.severity,
        "reason": decision.reason,
        "risk_score": event.risk_score,
        "sanitized_excerpt": excerpt,
        "input_sha256": digest,
        "raw_stored": False,
        "policy_version": str(POLICY["version"]),
        "actor": event.actor,
        "authenticated_tenant": event.authenticated_tenant,
        "resource_tenant": event.resource_tenant,
        "tool_name": event.tool_name,
        "approval_status": event.approval_status,
        "upstream_called": event.upstream_called,
        "duration_ms": event.duration_ms,
        "attributes": {**attributes, "trace_id": attributes.get("trace_id") or current_trace_id()},
    }
    with connect() as connection:
        connection.execute(
            """
            INSERT INTO events VALUES (
              :id,:timestamp_ms,:request_id,:stage,:event_type,
              :application_decision,:policy_rule,:severity,:reason,:risk_score,
              :sanitized_excerpt,:input_sha256,:raw_stored,:policy_version,:actor,
              :authenticated_tenant,:resource_tenant,:tool_name,:approval_status,
              :upstream_called,:duration_ms,:attributes_json
            )
            """,
            {
                **record,
                "raw_stored": 0,
                "upstream_called": (
                    None if event.upstream_called is None else int(event.upstream_called)
                ),
                "attributes_json": json.dumps(record["attributes"], ensure_ascii=False, separators=(",", ":")),
            },
        )
        connection.commit()
    log_record = {"event": "llm_security_event", **record}
    serialized = json.dumps(log_record, ensure_ascii=False, separators=(",", ":"))
    print(serialized, flush=True)
    if OTEL_ENDPOINT:
        SECURITY_LOGGER.info(serialized)
    return record


def principal_from_authorization(authorization: str | None) -> dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = authorization.removeprefix("Bearer ").strip()
    principal = TOKEN_PRINCIPALS.get(token)
    if principal is None:
        raise HTTPException(status_code=403, detail="unknown bearer token")
    return principal


def prompt_risk_score(text: str) -> float:
    patterns = (
        r"ignore\s+(?:all\s+)?previous",
        r"reveal\s+(?:the\s+)?system\s+prompt",
        r"disregard\s+(?:all\s+)?earlier",
        r"system\s+emergency\s+override",
        r"시스템\s*프롬프트.*(?:출력|공개|알려)",
        r"이전\s*지시.*무시",
    )
    return 0.96 if any(re.search(pattern, text, re.I) for pattern in patterns) else 0.05


def select_document(message: str) -> dict[str, Any]:
    lowered = message.lower()
    ranked = sorted(
        CORPUS,
        key=lambda document: sum(keyword in lowered for keyword in document["keywords"]),
        reverse=True,
    )
    return ranked[0]


def requested_tool(message: str) -> str | None:
    lowered = message.lower()
    if "delete_animal" in lowered or "동물 삭제" in lowered or "g-003 삭제" in lowered:
        return "delete_animal"
    return None


def request_count(subject: str) -> int:
    now = time.time()
    window = int(POLICY["request_limit"].get("window_seconds", 60))
    with REQUEST_WINDOW_LOCK:
        recent = [timestamp for timestamp in REQUEST_WINDOWS.get(subject, []) if now - timestamp < window]
        recent.append(now)
        REQUEST_WINDOWS[subject] = recent
        return len(recent)


def record_stage(event: SecurityEvent) -> dict[str, Any]:
    try:
        decision = evaluate(event.model_dump(), POLICY)
    except PolicyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return persist(event, decision)


def call_ollama(message: str, context: str) -> tuple[str, float]:
    started = time.perf_counter()
    prompt = (
        "아래 신뢰된 문서만 참고하여 한국어 한 문장으로 답하세요. "
        "문서에 없는 내용은 모른다고 답하세요.\n\n"
        f"문서: {context}\n\n질문: {message}"
    )
    try:
        response = httpx.post(
            f"{OLLAMA_URL}/api/generate",
            json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False, "options": {"temperature": 0}},
            timeout=HTTP_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        reply = str(response.json().get("response") or "").strip()
    except (httpx.HTTPError, ValueError) as exc:
        raise HTTPException(status_code=502, detail=f"ollama upstream failed: {exc}") from exc
    if not reply:
        raise HTTPException(status_code=502, detail="ollama upstream returned an empty response")
    return reply, round((time.perf_counter() - started) * 1000, 2)


def observed_decision(event: SecurityEvent) -> Decision:
    decision = normalize_observed_decision(event.application_decision)
    severity = "critical" if decision == "block" else "high" if decision == "redact" else "info"
    return Decision(
        decision,
        event.policy_rule or "observed-application-decision",
        severity,
        "decision supplied by the instrumented application",
    )


@app.on_event("startup")
def initialize_database() -> None:
    connect().close()


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    return {
        "ok": True,
        "service": "llm-security-monitor",
        "component": "llm-security-gateway",
        "version": "2.0.0",
        "policy_version": POLICY["version"],
        "policy_mode": POLICY["mode"],
        "raw_prompt_storage": False,
        "lab_endpoints": ENABLE_LAB_ENDPOINTS,
        "otel_enabled": bool(OTEL_ENDPOINT),
        "ollama_model": OLLAMA_MODEL,
        "uptime_seconds": round(time.time() - STARTED_AT, 2),
    }


@app.get("/api/policy")
def policy() -> dict[str, Any]:
    return {
        "canonical_source": "examples/security-monitoring/policy.json",
        "runtime_source": str(POLICY_PATH),
        "apply_change": "edit the bind-mounted policy file and restart the container",
        "raw_prompt_storage": False,
        "policy": POLICY,
    }


def blocked_response(
    request_id: str,
    trace_id: str,
    record: dict[str, Any],
    stages: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "request_id": request_id,
        "trace_id": trace_id,
        "reply": "요청이 보안 정책에 의해 차단되었습니다.",
        "application_decision": "block",
        "blocked_stage": record["stage"],
        "policy_rule": record["policy_rule"],
        "upstream_called": False,
        "model": OLLAMA_MODEL,
        "stages": stages,
    }


def stage_summary(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "stage": record["stage"],
        "decision": record["application_decision"],
        "rule": record["policy_rule"],
    }


@app.post("/api/chat")
def integrated_chat(
    payload: ChatRequest,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    principal = principal_from_authorization(authorization)
    request_id = payload.request_id or f"chat-{uuid.uuid4()}"
    stages: list[dict[str, Any]] = []
    started = time.perf_counter()

    with telemetry_span(
        "llm.security.chat",
        {
            "llm.request.id": request_id,
            "enduser.id": principal["subject"],
            "llm.tenant": principal["tenant"],
        },
    ) as root_span:
        trace_id = current_trace_id()

        with telemetry_span("llm.security.rate_limit") as span:
            count = request_count(principal["subject"])
            rate_record = record_stage(
                SecurityEvent(
                    request_id=request_id,
                    stage="runtime",
                    event_type="request_window",
                    window_request_count=count,
                    actor=principal["subject"],
                    authenticated_tenant=principal["tenant"],
                    attributes={"trace_id": trace_id},
                )
            )
            stages.append(stage_summary(rate_record))
            if span is not None:
                span.set_attribute("llm.security.decision", rate_record["application_decision"])
            if rate_record["application_decision"] == "block":
                if root_span is not None:
                    root_span.set_attribute("llm.security.blocked_stage", "runtime")
                return blocked_response(request_id, trace_id, rate_record, stages)

        with telemetry_span("llm.security.input_guardrail") as span:
            input_record = record_stage(
                SecurityEvent(
                    request_id=request_id,
                    stage="input",
                    event_type="user_prompt",
                    text=payload.message,
                    risk_score=prompt_risk_score(payload.message),
                    actor=principal["subject"],
                    authenticated_tenant=principal["tenant"],
                    attributes={"trace_id": trace_id},
                )
            )
            stages.append(stage_summary(input_record))
            if span is not None:
                span.set_attribute("llm.security.decision", input_record["application_decision"])
                span.set_attribute("llm.security.policy_rule", input_record["policy_rule"])
            if input_record["application_decision"] == "block":
                if root_span is not None:
                    root_span.set_attribute("llm.security.blocked_stage", "input")
                return blocked_response(request_id, trace_id, input_record, stages)

        with telemetry_span("llm.security.retrieval") as span:
            document = select_document(payload.message)
            retrieval_record = record_stage(
                SecurityEvent(
                    request_id=request_id,
                    stage="retrieval",
                    event_type="vector_hit",
                    actor=principal["subject"],
                    authenticated_tenant=principal["tenant"],
                    resource_tenant=document["tenant"],
                    attributes={
                        "trace_id": trace_id,
                        "document_id": document["document_id"],
                    },
                )
            )
            stages.append(stage_summary(retrieval_record))
            if span is not None:
                span.set_attribute("llm.retrieval.document_id", document["document_id"])
                span.set_attribute("llm.security.decision", retrieval_record["application_decision"])
            if retrieval_record["application_decision"] == "block":
                if root_span is not None:
                    root_span.set_attribute("llm.security.blocked_stage", "retrieval")
                return blocked_response(request_id, trace_id, retrieval_record, stages)

        tool_name = requested_tool(payload.message)
        if tool_name:
            with telemetry_span("llm.security.tool_authorization") as span:
                approved = tool_name in principal["dangerous_tools"]
                tool_record = record_stage(
                    SecurityEvent(
                        request_id=request_id,
                        stage="tool",
                        event_type="tool_request",
                        actor=principal["subject"],
                        authenticated_tenant=principal["tenant"],
                        tool_name=tool_name,
                        approval_status="approved" if approved else "missing",
                        attributes={"trace_id": trace_id},
                    )
                )
                stages.append(stage_summary(tool_record))
                if span is not None:
                    span.set_attribute("llm.tool.name", tool_name)
                    span.set_attribute("llm.security.decision", tool_record["application_decision"])
                if tool_record["application_decision"] == "block":
                    if root_span is not None:
                        root_span.set_attribute("llm.security.blocked_stage", "tool")
                    return blocked_response(request_id, trace_id, tool_record, stages)

        with telemetry_span("llm.ollama.generate", {"gen_ai.request.model": OLLAMA_MODEL}) as span:
            try:
                reply, upstream_duration = call_ollama(payload.message, document["text"])
                upstream_record = persist(
                    SecurityEvent(
                        request_id=request_id,
                        stage="runtime",
                        event_type="ollama_call",
                        actor=principal["subject"],
                        authenticated_tenant=principal["tenant"],
                        upstream_called=True,
                        duration_ms=upstream_duration,
                        application_decision="allow",
                        policy_rule="ollama-upstream",
                        attributes={"trace_id": trace_id, "model": OLLAMA_MODEL},
                    ),
                    Decision("allow", "ollama-upstream", "info", "Ollama returned a response"),
                )
            except HTTPException as exc:
                persist(
                    SecurityEvent(
                        request_id=request_id,
                        stage="runtime",
                        event_type="ollama_call",
                        actor=principal["subject"],
                        authenticated_tenant=principal["tenant"],
                        upstream_called=True,
                        application_decision="infra",
                        policy_rule="ollama-upstream-error",
                        attributes={"trace_id": trace_id},
                    ),
                    Decision("infra", "ollama-upstream-error", "high", str(exc.detail)),
                )
                if span is not None:
                    span.record_exception(exc)
                raise
            stages.append(stage_summary(upstream_record))

        with telemetry_span("llm.security.output_guardrail") as span:
            output_record = record_stage(
                SecurityEvent(
                    request_id=request_id,
                    stage="output",
                    event_type="model_response",
                    text=reply,
                    actor=principal["subject"],
                    authenticated_tenant=principal["tenant"],
                    upstream_called=True,
                    attributes={"trace_id": trace_id},
                )
            )
            stages.append(stage_summary(output_record))
            if span is not None:
                span.set_attribute("llm.security.decision", output_record["application_decision"])
            if output_record["application_decision"] == "redact":
                reply = output_record["sanitized_excerpt"]

        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        if root_span is not None:
            root_span.set_attribute("llm.security.decision", "allow")
            root_span.set_attribute("llm.upstream.called", True)
        return {
            "request_id": request_id,
            "trace_id": trace_id,
            "reply": reply,
            "application_decision": output_record["application_decision"],
            "blocked_stage": None,
            "policy_rule": output_record["policy_rule"],
            "upstream_called": True,
            "model": OLLAMA_MODEL,
            "duration_ms": duration_ms,
            "stages": stages,
        }


@app.post("/api/labs/scan-output")
def scan_output_candidate(payload: OutputCandidate) -> dict[str, Any]:
    if not ENABLE_LAB_ENDPOINTS:
        raise HTTPException(status_code=404, detail="lab endpoint disabled")
    request_id = payload.request_id or f"output-{uuid.uuid4()}"
    record = record_stage(
        SecurityEvent(
            request_id=request_id,
            stage="output",
            event_type="model_output_candidate",
            text=payload.text,
            attributes={"source": "learner-supplied-candidate"},
        )
    )
    return {
        "request_id": request_id,
        "application_decision": record["application_decision"],
        "policy_rule": record["policy_rule"],
        "sanitized_text": record["sanitized_excerpt"],
        "raw_stored": record["raw_stored"],
        "detected_entities": record["attributes"].get("redacted_entities", []),
    }


@app.post("/api/evaluate")
def evaluate_and_store(event: SecurityEvent) -> dict[str, Any]:
    try:
        decision = evaluate(event.model_dump(), POLICY)
    except PolicyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return persist(event, decision)


@app.post("/api/events")
def collect_observed_event(event: SecurityEvent) -> dict[str, Any]:
    return persist(event, observed_decision(event))


@app.post("/api/events/guardrail")
def collect_guardrail_event(payload: dict[str, Any]) -> dict[str, Any]:
    request_id = str(payload.get("request_id") or f"guard-{uuid.uuid4()}")
    original = str(
        payload.get("original_text")
        or payload.get("input")
        or payload.get("message")
        or ""
    )
    decision = (
        payload.get("application_decision")
        or payload.get("policy_decision")
        or payload.get("decision")
        or "observe"
    )
    reason = payload.get("blocking_reason") or payload.get("blocked_stage")
    event = SecurityEvent(
        request_id=request_id,
        stage="guardrail",
        event_type=str(payload.get("event") or "guardrail_decision"),
        text=original,
        risk_score=float(payload.get("risk_score") or (1.0 if reason else 0.0)),
        detected_entities=[str(item) for item in payload.get("entity_types", [])],
        upstream_called=payload.get("upstream_called"),
        duration_ms=float(payload.get("duration_ms") or 0.0),
        application_decision=str(decision),
        policy_rule=str(reason or "guardrail-observation"),
        attributes={
            "guard_engine": payload.get("guard_engine") or payload.get("framework"),
            "guard_mode": payload.get("guard_mode") or payload.get("mode"),
        },
    )
    return persist(event, observed_decision(event))


def query_records(where: str = "", parameters: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    statement = "SELECT * FROM events"
    if where:
        statement += " WHERE " + where
    statement += " ORDER BY timestamp_ms ASC, id ASC"
    with connect() as connection:
        rows = connection.execute(statement, parameters).fetchall()
    return [row_to_dict(row) for row in rows]


@app.get("/api/events")
def events(limit: int = Query(default=100, ge=1, le=1000)) -> dict[str, Any]:
    records = query_records()
    return {"count": min(len(records), limit), "events": records[-limit:]}


@app.get("/api/traces/{request_id}")
def request_trace(request_id: str) -> dict[str, Any]:
    records = query_records("request_id = ?", (request_id,))
    if not records:
        raise HTTPException(status_code=404, detail="request trace not found")
    return {
        "request_id": request_id,
        "event_count": len(records),
        "stage_order": [record["stage"] for record in records],
        "decisions": [record["application_decision"] for record in records],
        "events": records,
    }


@app.get("/api/alerts")
def alerts() -> dict[str, Any]:
    records = query_records("application_decision IN ('block','redact','infra')")
    return {"count": len(records), "alerts": records}


@app.get("/api/summary")
def summary() -> dict[str, Any]:
    with connect() as connection:
        total = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        decisions = {
            row[0]: row[1]
            for row in connection.execute(
                "SELECT application_decision, COUNT(*) FROM events GROUP BY application_decision"
            )
        }
        stages = {
            row[0]: row[1]
            for row in connection.execute(
                "SELECT stage, COUNT(*) FROM events GROUP BY stage"
            )
        }
        rules = {
            row[0]: row[1]
            for row in connection.execute(
                "SELECT policy_rule, COUNT(*) FROM events GROUP BY policy_rule"
            )
        }
    return {
        "total_events": total,
        "decisions": decisions,
        "stages": stages,
        "rules": rules,
        "raw_prompt_storage": False,
        "policy_version": POLICY["version"],
    }


@app.get("/api/anomalies")
def anomalies() -> dict[str, Any]:
    settings = POLICY.get("anomaly_detection", {})
    minimum_events = int(settings.get("minimum_events", 5))
    ratio_threshold = float(settings.get("block_ratio_threshold", 0.5))
    critical_threshold = int(settings.get("critical_rule_count_threshold", 1))
    critical_rules = ("rag-tenant-boundary", "agent-execution-approval")
    with connect() as connection:
        total = int(connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])
        blocked = int(
            connection.execute(
                "SELECT COUNT(*) FROM events WHERE application_decision = 'block'"
            ).fetchone()[0]
        )
        critical = {
            rule: int(
                connection.execute(
                    "SELECT COUNT(*) FROM events WHERE policy_rule = ?",
                    (rule,),
                ).fetchone()[0]
            )
            for rule in critical_rules
        }
    ratio = round(blocked / total, 4) if total else 0.0
    findings: list[dict[str, Any]] = []
    if total >= minimum_events and ratio >= ratio_threshold:
        findings.append(
            {
                "rule": "elevated-block-ratio",
                "observed": ratio,
                "threshold": ratio_threshold,
                "severity": "high",
            }
        )
    for rule, count in critical.items():
        if count >= critical_threshold:
            findings.append(
                {
                    "rule": f"repeated-{rule}",
                    "observed": count,
                    "threshold": critical_threshold,
                    "severity": "critical",
                }
            )
    return {
        "event_count": total,
        "block_count": blocked,
        "block_ratio": ratio,
        "anomaly_count": len(findings),
        "anomalies": findings,
        "policy_version": POLICY["version"],
    }


def prometheus_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


@app.get("/metrics", response_class=PlainTextResponse)
def metrics() -> str:
    lines = [
        "# HELP llm_security_events_total Structured LLM security events.",
        "# TYPE llm_security_events_total counter",
    ]
    with connect() as connection:
        for stage, event_type, count in connection.execute(
            "SELECT stage,event_type,COUNT(*) FROM events GROUP BY stage,event_type ORDER BY stage,event_type"
        ):
            lines.append(
                f'llm_security_events_total{{stage="{prometheus_escape(stage)}",event_type="{prometheus_escape(event_type)}"}} {count}'
            )
        lines.extend([
            "# HELP llm_security_decisions_total LLM security policy decisions.",
            "# TYPE llm_security_decisions_total counter",
        ])
        for decision, rule, severity, count in connection.execute(
            "SELECT application_decision,policy_rule,severity,COUNT(*) FROM events GROUP BY application_decision,policy_rule,severity ORDER BY application_decision,policy_rule"
        ):
            lines.append(
                "llm_security_decisions_total"
                f'{{decision="{prometheus_escape(decision)}",rule="{prometheus_escape(rule)}",severity="{prometheus_escape(severity)}"}} {count}'
            )
        duration_sum, duration_count = connection.execute(
            "SELECT COALESCE(SUM(duration_ms),0),COUNT(*) FROM events"
        ).fetchone()
    lines.extend([
        "# HELP llm_security_event_duration_ms Processing time reported by instrumented stages.",
        "# TYPE llm_security_event_duration_ms summary",
        f"llm_security_event_duration_ms_sum {float(duration_sum):.2f}",
        f"llm_security_event_duration_ms_count {duration_count}",
        "# HELP llm_upstream_calls_total Ollama upstream call outcomes.",
        "# TYPE llm_upstream_calls_total counter",
    ])
    with connect() as connection:
        for decision, count in connection.execute(
            "SELECT application_decision,COUNT(*) FROM events WHERE event_type = 'ollama_call' GROUP BY application_decision ORDER BY application_decision"
        ):
            lines.append(
                f'llm_upstream_calls_total{{decision="{prometheus_escape(decision)}"}} {count}'
            )
    return "\n".join(lines) + "\n"


@app.delete("/api/labs/events")
def reset_events() -> dict[str, Any]:
    if not ENABLE_LAB_ENDPOINTS:
        raise HTTPException(status_code=404, detail="lab endpoint disabled")
    with connect() as connection:
        deleted = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        connection.execute("DELETE FROM events")
        connection.commit()
    with REQUEST_WINDOW_LOCK:
        REQUEST_WINDOWS.clear()
    return {"deleted": deleted}


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    return Path("/app/dashboard.html").read_text(encoding="utf-8")
