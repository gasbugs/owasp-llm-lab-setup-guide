#!/usr/bin/env python3
"""Small internal retrieval service used to produce a real distributed trace."""

from __future__ import annotations

import hmac
import json
import os
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import PlainTextResponse
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from pydantic import BaseModel, ConfigDict, Field
from prometheus_client import Counter, generate_latest


OTEL_ENDPOINT = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "").rstrip("/")
SERVICE_TOKEN = os.environ["RETRIEVAL_SERVICE_TOKEN"]
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
REQUESTS = Counter(
    "llm_retrieval_service_requests_total",
    "Internal retrieval service requests by selected resource tenant.",
    ["resource_tenant"],
)


def configure_tracer() -> Any:
    if not OTEL_ENDPOINT:
        return None
    provider = TracerProvider(
        resource=Resource.create(
            {
                "service.name": "llm-security-retrieval",
                "service.namespace": "owasp-llm-lab",
                "service.version": "1.0.0",
                "deployment.environment.name": "lab",
            }
        )
    )
    provider.add_span_processor(
        BatchSpanProcessor(OTLPSpanExporter(endpoint=f"{OTEL_ENDPOINT}/v1/traces"))
    )
    trace.set_tracer_provider(provider)
    return trace.get_tracer("llm-security-retrieval")


TRACER = configure_tracer()
app = FastAPI(title="Module 08 Retrieval Service", version="1.0.0")


class RetrievalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: str = Field(min_length=1, max_length=12000)


def select_document(query: str) -> dict[str, Any]:
    lowered = query.lower()
    ranked = sorted(
        CORPUS,
        key=lambda document: sum(keyword in lowered for keyword in document["keywords"]),
        reverse=True,
    )
    return ranked[0]


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    return {
        "ok": True,
        "service": "llm-security-retrieval",
        "otel_enabled": bool(OTEL_ENDPOINT),
        "corpus_documents": len(CORPUS),
    }


@app.post("/retrieve")
def retrieve(
    payload: RetrievalRequest,
    x_service_token: str | None = Header(default=None),
) -> dict[str, Any]:
    if not x_service_token or not hmac.compare_digest(x_service_token, SERVICE_TOKEN):
        raise HTTPException(status_code=403, detail="invalid retrieval service token")
    document = select_document(payload.query)
    REQUESTS.labels(resource_tenant=document["tenant"]).inc()
    span = trace.get_current_span()
    span.set_attribute("llm.retrieval.document_id", document["document_id"])
    span.set_attribute("llm.retrieval.resource_tenant", document["tenant"])
    print(
        json.dumps(
            {
                "event": "retrieval_candidate_selected",
                "document_id": document["document_id"],
                "resource_tenant": document["tenant"],
                "raw_query_stored": False,
            },
            separators=(",", ":"),
        ),
        flush=True,
    )
    return {key: document[key] for key in ("document_id", "tenant", "text")}


@app.get("/metrics", response_class=PlainTextResponse)
def metrics() -> bytes:
    return generate_latest()


FastAPIInstrumentor.instrument_app(app, excluded_urls="healthz,metrics")
