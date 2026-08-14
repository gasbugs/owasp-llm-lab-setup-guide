#!/usr/bin/env python3
"""Loopback-only LLM security event collector, policy API, and metrics endpoint."""

from __future__ import annotations

import json
import os
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field

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

app = FastAPI(title="LLM Security Monitoring Lab", version="1.0.0")


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
        "attributes": attributes,
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
                "attributes_json": json.dumps(attributes, ensure_ascii=False, separators=(",", ":")),
            },
        )
        connection.commit()
    print(json.dumps({"event": "llm_security_event", **record}, ensure_ascii=False, separators=(",", ":")), flush=True)
    return record


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
        "policy_version": POLICY["version"],
        "policy_mode": POLICY["mode"],
        "raw_prompt_storage": False,
        "lab_endpoints": ENABLE_LAB_ENDPOINTS,
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
def trace(request_id: str) -> dict[str, Any]:
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
    ])
    return "\n".join(lines) + "\n"


@app.delete("/api/labs/events")
def reset_events() -> dict[str, Any]:
    if not ENABLE_LAB_ENDPOINTS:
        raise HTTPException(status_code=404, detail="lab endpoint disabled")
    with connect() as connection:
        deleted = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        connection.execute("DELETE FROM events")
        connection.commit()
    return {"deleted": deleted}


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    return Path("/app/dashboard.html").read_text(encoding="utf-8")
