"""Credential-isolated OpenAI-compatible gateway for Amazon Bedrock Converse."""

from __future__ import annotations

import hmac
import os
import time
import uuid
from contextlib import asynccontextmanager

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import Depends, FastAPI, Header, HTTPException, Response
from opentelemetry import trace
from opentelemetry.trace import SpanKind
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
from pydantic import BaseModel, ConfigDict, Field

from telemetry import configure_telemetry


AWS_REGION = os.getenv("AWS_REGION", os.getenv("AWS_DEFAULT_REGION", "us-east-1"))
MODEL_ID = os.getenv("BEDROCK_MODEL_ID", "us.amazon.nova-lite-v1:0")
INPUT_USD_PER_MILLION = float(os.getenv("BEDROCK_INPUT_USD_PER_MILLION", "0.06"))
OUTPUT_USD_PER_MILLION = float(os.getenv("BEDROCK_OUTPUT_USD_PER_MILLION", "0.24"))
PRICING_REFERENCE_DATE = os.getenv("BEDROCK_PRICING_REFERENCE_DATE", "2026-08-24")
KNOWLEDGE_BASE_ID = os.getenv("BEDROCK_KNOWLEDGE_BASE_ID", "")
BEDROCK_GATEWAY_TOKEN = os.environ["BEDROCK_GATEWAY_TOKEN"]
BEDROCK = boto3.client("bedrock-runtime", region_name=AWS_REGION)
BEDROCK_AGENT_RUNTIME = boto3.client("bedrock-agent-runtime", region_name=AWS_REGION)
RUNTIME = {"ready": False, "error": "startup-not-complete"}
TRACER = trace.get_tracer("llm-security-bedrock-gateway")

REQUESTS = Counter(
    "bedrock_requests_total", "Bedrock Converse requests", ["model", "outcome", "task"]
)
TOKENS = Counter(
    "bedrock_tokens_total", "Bedrock tokens reported by Converse", ["model", "direction", "task"]
)
DURATION = Histogram(
    "bedrock_request_duration_seconds", "Bedrock Converse latency", ["model", "outcome", "task"]
)
ERRORS = Counter(
    "bedrock_errors_total", "Bedrock Converse errors", ["model", "error_type", "task"]
)
ESTIMATED_COST = Counter(
    "bedrock_estimated_cost_usd_total",
    "Estimated Bedrock cost from configured per-million-token rates",
    ["model", "task"],
)
PRICING_INFO = Gauge(
    "bedrock_pricing_info",
    "Configured estimate metadata; value is initialized once per gateway process",
    ["model", "region", "reference_date", "input_usd_per_million", "output_usd_per_million"],
)
PRICING_INFO.labels(
    MODEL_ID,
    AWS_REGION,
    PRICING_REFERENCE_DATE,
    str(INPUT_USD_PER_MILLION),
    str(OUTPUT_USD_PER_MILLION),
).inc()


class Message(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: str = Field(pattern="^(system|user|assistant)$")
    content: str = Field(min_length=1, max_length=50000)


class ChatCompletionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    model: str
    messages: list[Message] = Field(min_length=1, max_length=30)
    temperature: float = Field(default=0.0, ge=0.0, le=1.0)
    max_tokens: int = Field(default=180, ge=1, le=4096)
    stream: bool = False


class RetrievalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: str = Field(min_length=1, max_length=4000)
    number_of_results: int = Field(default=3, ge=1, le=10)


def require_gateway_token(authorization: str | None = Header(default=None)) -> None:
    """Allow only local services that know the fixed Module 08/09 gateway token."""
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(
        token, BEDROCK_GATEWAY_TOKEN
    ):
        raise HTTPException(status_code=401, detail="invalid Bedrock Gateway token")


def _converse(request: ChatCompletionRequest) -> dict:
    model_id, separator, task_name = request.model.partition("#")
    task = task_name if separator else "main"
    if model_id != MODEL_ID or task not in {"main", "general_safety", "self_check"}:
        raise HTTPException(status_code=422, detail="model must match configured Bedrock model")
    if request.stream:
        raise HTTPException(status_code=422, detail="streaming is not enabled in this lab gateway")
    system = [{"text": item.content} for item in request.messages if item.role == "system"]
    messages = [
        {"role": item.role, "content": [{"text": item.content}]}
        for item in request.messages
        if item.role != "system"
    ]
    if not messages:
        raise HTTPException(status_code=422, detail="at least one user or assistant message is required")

    started = time.perf_counter()
    outcome = "error"
    with TRACER.start_as_current_span(
        f"chat {MODEL_ID}", kind=SpanKind.CLIENT
    ) as span:
        span.set_attribute("gen_ai.operation.name", "chat")
        span.set_attribute("gen_ai.provider.name", "aws.bedrock")
        span.set_attribute("gen_ai.request.model", MODEL_ID)
        span.set_attribute("owasp_llm.security.task", task)
        try:
            kwargs = {
                "modelId": MODEL_ID,
                "messages": messages,
                "inferenceConfig": {
                    "temperature": request.temperature,
                    "maxTokens": request.max_tokens,
                },
            }
            if system:
                kwargs["system"] = system
            result = BEDROCK.converse(**kwargs)
            outcome = "allow"
        except (BotoCoreError, ClientError) as exc:
            error_type = type(exc).__name__
            ERRORS.labels(MODEL_ID, error_type, task).inc()
            span.record_exception(exc)
            raise HTTPException(status_code=502, detail=f"bedrock converse failed: {error_type}") from exc
        finally:
            DURATION.labels(MODEL_ID, outcome, task).observe(
                time.perf_counter() - started
            )
            REQUESTS.labels(MODEL_ID, outcome, task).inc()

    usage = result.get("usage", {})
    input_tokens = int(usage.get("inputTokens", 0))
    output_tokens = int(usage.get("outputTokens", 0))
    TOKENS.labels(MODEL_ID, "input", task).inc(input_tokens)
    TOKENS.labels(MODEL_ID, "output", task).inc(output_tokens)
    ESTIMATED_COST.labels(MODEL_ID, task).inc(
        (input_tokens * INPUT_USD_PER_MILLION + output_tokens * OUTPUT_USD_PER_MILLION)
        / 1_000_000
    )
    text = "".join(
        item.get("text", "") for item in result["output"]["message"].get("content", [])
    )
    request_id = result.get("ResponseMetadata", {}).get("RequestId", str(uuid.uuid4()))
    return {
        "id": request_id,
        "object": "chat.completion",
        "model": MODEL_ID,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": text},
                "finish_reason": result.get("stopReason", "stop"),
            }
        ],
        "usage": {
            "prompt_tokens": input_tokens,
            "completion_tokens": output_tokens,
            "total_tokens": int(usage.get("totalTokens", input_tokens + output_tokens)),
        },
        "bedrock": {
            "request_id": request_id,
            "latency_ms": result.get("metrics", {}).get("latencyMs"),
        },
    }


@asynccontextmanager
async def lifespan(_app: FastAPI):
    try:
        _converse(
            ChatCompletionRequest(
                model=MODEL_ID,
                messages=[Message(role="user", content="Reply OK")],
                max_tokens=2,
            )
        )
        RUNTIME.update({"ready": True, "error": None})
    except Exception as exc:
        RUNTIME.update({"ready": False, "error": type(exc).__name__})
    yield


app = FastAPI(title="Local Amazon Bedrock gateway", docs_url=None, redoc_url=None, lifespan=lifespan)
configure_telemetry(app, "llm-security-bedrock-gateway")


@app.get("/healthz")
def healthz() -> dict:
    return {
        "ok": RUNTIME["ready"],
        "provider": "amazon-bedrock",
        "model": MODEL_ID,
        "region": AWS_REGION,
        "pricing": {
            "input_usd_per_million_tokens": INPUT_USD_PER_MILLION,
            "output_usd_per_million_tokens": OUTPUT_USD_PER_MILLION,
            "kind": "configured-estimate",
            "reference_date": PRICING_REFERENCE_DATE,
        },
        "error": RUNTIME["error"],
    }


@app.get("/authz")
def authz(_authorized: None = Depends(require_gateway_token)) -> dict:
    """Verify that a downstream service has the current token without invoking Bedrock."""
    return {"ok": True, "authorized": True}


@app.get("/metrics")
def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.post("/v1/chat/completions")
def chat_completions(
    request: ChatCompletionRequest,
    _authorized: None = Depends(require_gateway_token),
) -> dict:
    if not RUNTIME["ready"]:
        raise HTTPException(status_code=503, detail="Bedrock gateway startup check failed")
    return _converse(request)


@app.post("/v1/retrieve")
def retrieve(
    request: RetrievalRequest, _authorized: None = Depends(require_gateway_token)
) -> dict:
    """Retrieve through the credential boundary instead of exposing AWS credentials downstream."""
    if not KNOWLEDGE_BASE_ID:
        raise HTTPException(status_code=503, detail="Module 08 Knowledge Base is not configured")
    try:
        result = BEDROCK_AGENT_RUNTIME.retrieve(
            knowledgeBaseId=KNOWLEDGE_BASE_ID,
            retrievalQuery={"text": request.query},
            retrievalConfiguration={
                "vectorSearchConfiguration": {"numberOfResults": request.number_of_results}
            },
        )
    except (BotoCoreError, ClientError) as exc:
        raise HTTPException(
            status_code=502, detail=f"bedrock retrieve failed: {type(exc).__name__}"
        ) from exc
    return {
        "knowledge_base_id": KNOWLEDGE_BASE_ID,
        "hits": [
            {
                "score": item.get("score"),
                "source": item.get("location", {}).get("s3Location", {}).get("uri"),
                "text": item.get("content", {}).get("text", ""),
            }
            for item in result.get("retrievalResults", [])
        ],
    }
