"""OWASP LLM Lab — vuln-rag entry point.

모든 강의 시나리오를 한 앱에서 선택해 실행한다.
일부러 취약한 코드 — 교육 환경 외 배포 금지.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field

from app.embedding import EmbeddingBackendError, EmbeddingClient
from app.guardrails import GuardrailProxy, GuardrailProxyError
from app.llm import LLMClient
from app.secure_coding import (
    LLM02AuthorizationError,
    PolicyDecision,
    emit_security_event,
    execute_customer_tool_safe,
    execute_customer_tool_vulnerable,
    require_llm02_authenticated_principal,
    select_llm01_input_policy,
    select_llm02_tool_executor,
    select_llm08_rag_provenance_filter,
    select_llm08_tenant_filter,
    select_llm09_package_policy,
    select_llm10_resource_budget,
)
from app.scenarios import SCENARIO_NAMES, list_scenarios
from app.scenarios import day2 as day2_scenario
from app.scenarios import day4 as day4_scenario

DEFAULT_SCENARIO = os.environ.get("DEFAULT_SCENARIO", os.environ.get("SCENARIO", "day1"))
if DEFAULT_SCENARIO not in SCENARIO_NAMES:
    DEFAULT_SCENARIO = "day1"

SCENARIOS = {scenario.id: scenario for scenario in list_scenarios()}
llm = LLMClient()
embedding = EmbeddingClient()
guardrail_proxy = GuardrailProxy()
MODEL_PROVENANCE_PATH = os.environ.get("MODEL_PROVENANCE_PATH")


class LLM10ConcurrencyGate:
    """Reject excess safe-mode inference before the Ollama call."""

    def __init__(self, limit: int = 1) -> None:
        self.limit = limit
        self._active = 0
        self._lock = threading.Lock()

    def acquire(self) -> bool:
        with self._lock:
            if self._active >= self.limit:
                return False
            self._active += 1
            return True

    def release(self) -> None:
        with self._lock:
            self._active = max(0, self._active - 1)


llm10_concurrency_gate = LLM10ConcurrencyGate(limit=1)


def model_provenance() -> dict | None:
    """Return server-mounted provenance without trusting browser input."""
    if not MODEL_PROVENANCE_PATH:
        return None
    try:
        value = json.loads(Path(MODEL_PROVENANCE_PATH).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None

app = FastAPI(title="vuln-rag [all scenarios]")
templates_dir = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))


class ChatRequest(BaseModel):
    message: str
    session_id: str = "default"
    scenario: str | None = None
    lab: Literal["llm02", "llm08-rag-poisoning", "llm04"] | None = None
    customer_id: str | None = None


class LLM08SearchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str = Field(min_length=1, max_length=4096)
    top_k: int = Field(default=2, ge=1, le=4)


class EmbedRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    input: str | list[str]


class LLM02VulnerableChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message: str = Field(min_length=1, max_length=4096)
    customer_id: str | None = None


class LLM02SafeChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message: str = Field(min_length=1, max_length=4096)
    customer_id: str | None = None


class LLM02ToolProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    customer_id: str | None
    fields: list[str] = Field(min_length=1, max_length=9)
    reason: str = Field(min_length=1, max_length=500)


class LLM08RagPoisoningChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str = Field(min_length=1, max_length=4096)


class LLM08RagPoisoningDocumentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=200)
    text: str = Field(min_length=1, max_length=10000)
    source: str = Field(default="learner-upload", min_length=1, max_length=200)
    revision: str = Field(default="1", min_length=1, max_length=50)


class LLM02WorkshopRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message: str = Field(min_length=1, max_length=4096)
    customer_id: str | None = None


class LLM05SqlLookupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    model_output: str = Field(min_length=1, max_length=500)


class LLM09WorkshopRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    candidate: str = Field(min_length=1, max_length=200)


def get_scenario(name: str | None):
    return SCENARIOS.get(name or DEFAULT_SCENARIO, SCENARIOS[DEFAULT_SCENARIO])


def require_llm08_principal(request: Request) -> day4_scenario.TenantPrincipal:
    if DEFAULT_SCENARIO != "day4":
        raise HTTPException(status_code=404, detail="not found")
    try:
        return day4_scenario.authenticate_tenant(request.headers.get("authorization"))
    except day4_scenario.TenantAuthenticationError as exc:
        raise HTTPException(
            status_code=401,
            detail="valid LLM08 lab bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


async def run_llm08_search(
    request_body: LLM08SearchRequest,
    request: Request,
    *,
    mode: Literal["vulnerable", "safe"],
) -> dict:
    principal = require_llm08_principal(request)
    try:
        return await day4_scenario.vector_search(
            query=request_body.query,
            principal=principal,
            mode=mode,
            top_k=request_body.top_k,
            embedding_backend=embedding,
        )
    except EmbeddingBackendError as exc:
        raise HTTPException(
            status_code=502, detail="embedding backend unavailable"
        ) from exc
    except ValueError as exc:
        raise HTTPException(status_code=502, detail="invalid embedding result") from exc


async def run_llm08_chat(
    request_body: LLM08SearchRequest,
    request: Request,
    *,
    mode: Literal["vulnerable", "safe"],
) -> dict:
    search_evidence = await run_llm08_search(request_body, request, mode=mode)
    system_prompt = day4_scenario.build_system_prompt(
        context=search_evidence["retrieved_chunks"]
    )
    reply = await llm.chat(system=system_prompt, user=request_body.query)
    return {
        "reply": reply,
        "scenario": "day4",
        "lab_only": True,
        "vector_search": search_evidence,
    }


def require_day2_lab() -> None:
    if DEFAULT_SCENARIO != "day2":
        raise HTTPException(status_code=404, detail="not found")


def new_llm02_trace() -> dict:
    return {
        "planner_model_called": False,
        "authorization_checked": False,
        "customer_query_called": False,
        "answer_model_called": False,
        "authenticated_customer_id": None,
        "requested_customer_id": None,
        "requested_fields": [],
        "application_decision": "block",
        "blocking_reason": None,
    }


def emit_llm02_trace(trace: dict) -> None:
    """Log policy state without bearer tokens or customer field values."""
    print(
        json.dumps(
            {"event": "llm02_customer_tool", **trace},
            ensure_ascii=False,
        ),
        flush=True,
    )


async def run_llm02_tool_chat(
    request_body: LLM02WorkshopRequest | LLM02VulnerableChatRequest | LLM02SafeChatRequest | ChatRequest,
    request: Request,
    *,
    executor: Literal["vulnerable", "safe", "selected"],
) -> dict | JSONResponse:
    """Authenticate, plan one read-only tool call, authorize, query, then answer."""
    require_day2_lab()
    trace = new_llm02_trace()

    try:
        principal = require_llm02_authenticated_principal(request_body, request)
    except HTTPException as exc:
        trace["blocking_reason"] = "authentication-required"
        emit_llm02_trace(trace)
        return JSONResponse(
            status_code=exc.status_code,
            headers=exc.headers,
            content={"detail": exc.detail, "trace": trace},
        )

    trace["authenticated_customer_id"] = principal.customer_id
    body_customer_id = getattr(request_body, "customer_id", None)
    if executor == "safe" and body_customer_id is not None:
        trace["requested_customer_id"] = body_customer_id
        trace["blocking_reason"] = "body-customer-id-forbidden"
        emit_llm02_trace(trace)
        return JSONResponse(
            status_code=422,
            content={
                "detail": "customer_id must not be supplied by client",
                "trace": trace,
            },
        )

    try:
        raw_proposal = await llm.structured_chat(
            system=day2_scenario.build_llm02_planner_prompt(),
            user=request_body.message,
            schema=LLM02ToolProposal.model_json_schema(),
        )
        trace["planner_model_called"] = True
        proposal = LLM02ToolProposal.model_validate(raw_proposal)
    except Exception as exc:
        trace["planner_model_called"] = True
        trace["blocking_reason"] = "planner-invalid-response"
        emit_llm02_trace(trace)
        raise HTTPException(status_code=502, detail="planner returned invalid tool proposal") from exc

    trace["requested_customer_id"] = proposal.customer_id
    trace["requested_fields"] = proposal.fields

    try:
        if executor == "vulnerable":
            result = execute_customer_tool_vulnerable(proposal, principal)
        elif executor == "safe":
            trace["authorization_checked"] = True
            result = execute_customer_tool_safe(proposal, principal)
        else:
            result = select_llm02_tool_executor(proposal, principal)
            trace["authorization_checked"] = result.mode == "safe"
    except LLM02AuthorizationError as exc:
        trace["authorization_checked"] = True
        trace["blocking_reason"] = str(exc)
        emit_llm02_trace(trace)
        return JSONResponse(
            status_code=403,
            content={"detail": str(exc), "trace": trace},
        )
    except KeyError:
        trace["blocking_reason"] = "customer-not-found"
        emit_llm02_trace(trace)
        return JSONResponse(status_code=404, content={"detail": "synthetic customer not found", "trace": trace})
    except ValueError as exc:
        trace["blocking_reason"] = "tool-request-invalid"
        emit_llm02_trace(trace)
        return JSONResponse(status_code=422, content={"detail": str(exc), "trace": trace})

    trace["customer_query_called"] = True
    reply = await llm.chat(
        system=day2_scenario.build_llm02_answer_prompt(result.record),
        user=request_body.message,
    )
    trace["answer_model_called"] = True
    trace["application_decision"] = "allow"
    emit_llm02_trace(trace)
    return {
        "reply": reply,
        "scenario": "day2",
        "lab": "llm02-sensitive-information-disclosure",
        "mode": result.mode,
        "tool": "get_customer_record",
        "tool_proposal": proposal.model_dump(),
        "tool_result": {
            "customer_id": result.customer_id,
            "fields": list(result.fields),
        },
        "trace": trace,
    }


async def run_llm08_rag_chat(
    request_body: LLM08RagPoisoningChatRequest,
    *,
    mode: Literal["vulnerable", "safe"],
) -> dict:
    require_day2_lab()
    try:
        search = await day2_scenario.vector_retrieve_documents(
            request_body.query,
            mode,
            embedding,
        )
    except EmbeddingBackendError as exc:
        raise HTTPException(
            status_code=502, detail="embedding backend unavailable"
        ) from exc
    except ValueError as exc:
        raise HTTPException(status_code=502, detail="invalid embedding result") from exc
    records = search.pop("documents")
    context = [record.rendered for record in records]
    system_prompt = day2_scenario.build_system_prompt(context)
    reply = await llm.chat(system=system_prompt, user=request_body.query)
    return {
        "reply": reply,
        "scenario": "day2",
        "lab": "llm08-rag-knowledge-provenance",
        "mode": mode,
        "retrieval": {
            **search,
            "provenance_filter_applied": mode == "safe",
            "required_approval_status": "approved" if mode == "safe" else None,
        },
        "upstream_called": True,
    }


def require_workshop_scenario(expected: str) -> None:
    if DEFAULT_SCENARIO != expected:
        raise HTTPException(status_code=404, detail="not found")


@app.post("/api/labs/llm01/workshop/chat")
async def llm01_secure_coding_workshop(request_body: ChatRequest):
    """Same endpoint before and after the learner switches the adjacent call."""
    require_workshop_scenario("day1")

    decision = select_llm01_input_policy(request_body.message)

    if decision.application_decision == "block":
        emit_security_event(decision, upstream_called=False)
        return {
            "reply": "request blocked by server input policy",
            **decision.__dict__,
            "upstream_called": False,
        }
    selected = get_scenario("day1")
    context = selected.retrieve(request_body.message)
    reply = await llm.chat(
        system=selected.build_system_prompt(context=context),
        user=request_body.message,
    )
    emit_security_event(decision, upstream_called=True)
    return {
        "reply": reply,
        **decision.__dict__,
        "upstream_called": True,
    }


async def run_llm02_policy_chat(
    request_body: LLM02WorkshopRequest | ChatRequest,
    request: Request,
) -> dict | JSONResponse:
    """Use the learner-switched tool executor for both workshop and UI routes."""
    return await run_llm02_tool_chat(
        request_body,
        request,
        executor="selected",
    )


@app.post("/api/labs/llm02/workshop/chat")
async def llm02_secure_coding_workshop(
    request_body: LLM02WorkshopRequest,
    request: Request,
):
    return await run_llm02_policy_chat(request_body, request)


@app.post("/api/labs/llm04/workshop/chat", deprecated=True)
@app.post("/api/labs/llm08/rag-poisoning/workshop/chat")
async def llm08_rag_secure_coding_workshop(request_body: LLM08RagPoisoningChatRequest):
    return await run_llm08_rag_policy_chat(request_body)


async def run_llm08_rag_policy_chat(request_body: LLM08RagPoisoningChatRequest) -> dict:
    """Apply one RAG provenance policy to the workshop API and Day 2 UI."""
    require_day2_lab()

    mode = select_llm08_rag_provenance_filter()

    result = await run_llm08_rag_chat(request_body, mode=mode)
    emit_security_event(
        decision=PolicyDecision(
            "llm08-rag-poisoning",
            "approved-provenance-only" if mode == "safe" else "include-unapproved-provenance",
            "allow",
        ),
        upstream_called=True,
    )
    return result


@app.post("/api/labs/llm08/workshop/search")
async def llm08_secure_coding_workshop(
    request_body: LLM08SearchRequest,
    request: Request,
):
    mode = select_llm08_tenant_filter()

    result = await run_llm08_search(request_body, request, mode=mode)
    emit_security_event(
        decision=PolicyDecision(
            "llm08",
            "authenticated-tenant-filter" if mode == "safe" else "search-all-tenants",
            "allow",
        ),
        upstream_called=True,
    )
    return result


@app.post("/api/labs/llm09/workshop/install")
async def llm09_secure_coding_workshop(request_body: LLM09WorkshopRequest):
    require_workshop_scenario("day4")

    decision = select_llm09_package_policy(request_body.candidate)

    installer_handoff_called = decision.application_decision == "allow"
    emit_security_event(decision, upstream_called=False)
    content = {
        "candidate": request_body.candidate,
        **decision.__dict__,
        "verification_source": (
            "server-approved-package-allowlist"
            if decision.policy == "server-approved-package-allowlist"
            else "model-output-only"
        ),
        "installer_handoff_called": installer_handoff_called,
        "upstream_called": False,
    }
    if decision.application_decision == "block":
        return JSONResponse(status_code=422, content=content)
    return content


@app.post("/api/labs/llm10/workshop/chat")
async def llm10_secure_coding_workshop(request_body: ChatRequest):
    require_workshop_scenario("day5")

    decision = select_llm10_resource_budget(request_body.message)

    if decision.application_decision == "block":
        emit_security_event(decision, upstream_called=False)
        return JSONResponse(
            status_code=413,
            content={
                "reply": "request exceeds server resource budget",
                **decision.__dict__,
                "upstream_called": False,
            },
        )
    concurrency_enforced = decision.policy == "server-resource-budget"
    if concurrency_enforced and not llm10_concurrency_gate.acquire():
        limited = PolicyDecision(
            "llm10",
            "server-resource-budget",
            "block",
            "concurrent-request-limit-1",
            decision.max_output_tokens,
        )
        emit_security_event(limited, upstream_called=False)
        return JSONResponse(
            status_code=429,
            content={
                "reply": "too many concurrent model requests",
                **limited.__dict__,
                "upstream_called": False,
            },
        )
    selected = get_scenario("day5")
    context = selected.retrieve(request_body.message)
    try:
        reply = await llm.chat(
            system=selected.build_system_prompt(context=context),
            user=request_body.message,
            num_predict=decision.max_output_tokens,
        )
    finally:
        if concurrency_enforced:
            llm10_concurrency_gate.release()
    emit_security_event(decision, upstream_called=True)
    return {
        "reply": reply,
        **decision.__dict__,
        "upstream_called": True,
    }


@app.get("/healthz")
async def health():
    return {
        "ok": True,
        "default_scenario": DEFAULT_SCENARIO,
        "scenarios": list(SCENARIO_NAMES),
        "guard_engine": guardrail_proxy.engine,
    }


@app.get("/api/scenarios")
async def scenarios():
    return {
        "default": DEFAULT_SCENARIO,
        "scenarios": [
            {
                "id": scenario.id,
                "title": scenario.title,
                "intro": scenario.intro,
                "warning": scenario.warning,
            }
            for scenario in SCENARIOS.values()
        ],
    }


@app.get("/api/guardrails/policy")
async def guardrails_policy():
    """Proxy policy metadata without exposing the guard API to browser code."""
    try:
        return await guardrail_proxy.policy()
    except GuardrailProxyError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.get("/api/labs/llm02/customer/{customer_id}")
async def llm02_customer_ground_truth(customer_id: str):
    """LAB ONLY: expose the synthetic SQLite row used as learner ground truth."""
    require_day2_lab()
    try:
        return {
            "lab_only": True,
            "storage": "sqlite:memory:synthetic_customers",
            "record": day2_scenario.customer_record(customer_id),
        }
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="synthetic customer not found") from exc


@app.get("/api/labs/llm02/policy")
async def llm02_policy():
    require_day2_lab()
    return {
        "lab_only": True,
        "vulnerable": {
            "authentication": "required bearer token mapped to customer_id by server",
            "planner": "Ollama structured output, temperature=0",
            "tool": "get_customer_record",
            "tool_executor": "trusts planner customer_id and fields",
            "database_query_order": "query before authorization",
            "policy_owner": "LLM proposal",
        },
        "safe": {
            "authentication": "required bearer token mapped to customer_id by server",
            "request_body_customer_id": "forbidden",
            "customer_scope": "authenticated principal only",
            "field_allowlist": list(day2_scenario.LLM02_SAFE_FIELDS),
            "database_query_order": "authorization before query",
            "policy_owner": "application",
        },
        "planner_receives": ["user message", "read-only tool schema"],
        "planner_never_receives": [
            "bearer token",
            "database credential",
            "customer records",
        ],
    }


@app.post("/api/labs/llm02/vulnerable/chat")
async def llm02_vulnerable_chat(
    request_body: LLM02VulnerableChatRequest,
    request: Request,
):
    return await run_llm02_tool_chat(
        request_body,
        request,
        executor="vulnerable",
    )


@app.post("/api/labs/llm02/safe/chat")
async def llm02_safe_chat(request_body: LLM02SafeChatRequest, request: Request):
    return await run_llm02_tool_chat(
        request_body,
        request,
        executor="safe",
    )


@app.get("/api/labs/llm04/documents", deprecated=True)
@app.get("/api/labs/llm08/rag-poisoning/documents")
async def llm08_rag_documents():
    require_day2_lab()
    return {"lab_only": True, "documents": day2_scenario.document_records()}


@app.post("/api/labs/llm04/documents", deprecated=True)
@app.post("/api/labs/llm08/rag-poisoning/documents")
async def llm08_rag_add_document(request_body: LLM08RagPoisoningDocumentRequest):
    require_day2_lab()
    document = day2_scenario.add_doc(
        **request_body.model_dump(),
        approval_status="unapproved",
        ingestion_actor="llm08-lab-upload-api",
    )
    return {
        "ok": True,
        "lab_only": True,
        "document": document,
    }


@app.post("/api/labs/llm04/vulnerable/chat", deprecated=True)
@app.post("/api/labs/llm08/rag-poisoning/vulnerable/chat")
async def llm08_rag_vulnerable_chat(request_body: LLM08RagPoisoningChatRequest):
    return await run_llm08_rag_chat(request_body, mode="vulnerable")


@app.post("/api/labs/llm04/safe/chat", deprecated=True)
@app.post("/api/labs/llm08/rag-poisoning/safe/chat")
async def llm08_rag_safe_chat(request_body: LLM08RagPoisoningChatRequest):
    return await run_llm08_rag_chat(request_body, mode="safe")


def llm05_account_lookup(model_output: str, *, safe: bool) -> dict:
    """Send the same untrusted model string to a SQL sink in two ways."""
    database = sqlite3.connect(":memory:")
    database.row_factory = sqlite3.Row
    database.executescript(
        """
        CREATE TABLE accounts(username TEXT, balance INTEGER);
        INSERT INTO accounts VALUES ('alice', 1200), ('bob', 900);
        """
    )
    if safe:
        sql_template = "SELECT username, balance FROM accounts WHERE username = ?"
        rows = database.execute(sql_template, (model_output,)).fetchall()
        policy = "parameterized-query"
    else:
        sql_template = (
            "SELECT username, balance FROM accounts WHERE username = '"
            + model_output
            + "'"
        )
        rows = database.execute(sql_template).fetchall()
        policy = "string-concatenation"
    result = {
        "lab": "llm05-sql-sink",
        "model_output": model_output,
        "policy": policy,
        "query_template": (
            "SELECT username, balance FROM accounts WHERE username = ?"
            if safe
            else "SELECT username, balance FROM accounts WHERE username = '<model_output>'"
        ),
        "rows": [dict(row) for row in rows],
        "row_count": len(rows),
    }
    print(json.dumps({"event": "llm05_sql_sink", **result}, ensure_ascii=False), flush=True)
    return result


@app.post("/api/labs/llm05/vulnerable/sql-lookup")
async def llm05_vulnerable_sql_lookup(request_body: LLM05SqlLookupRequest):
    return llm05_account_lookup(request_body.model_output, safe=False)


@app.post("/api/labs/llm05/safe/sql-lookup")
async def llm05_safe_sql_lookup(request_body: LLM05SqlLookupRequest):
    return llm05_account_lookup(request_body.model_output, safe=True)


@app.get("/api/labs/llm07/policy-canonical")
async def llm07_policy_canonical():
    if DEFAULT_SCENARIO != "day4":
        raise HTTPException(status_code=404, detail="not found")
    return {
        "lab_only": True,
        "policy": day4_scenario.LLM07_POLICY_CANONICAL,
        "credential_present": False,
    }


@app.post("/api/labs/llm08/vulnerable/search")
async def llm08_vulnerable_search(
    request_body: LLM08SearchRequest,
    request: Request,
):
    """LAB ONLY: vector search before applying tenant metadata filtering."""
    return await run_llm08_search(request_body, request, mode="vulnerable")


@app.post("/api/labs/llm08/safe/search")
async def llm08_safe_search(
    request_body: LLM08SearchRequest,
    request: Request,
):
    """LAB ONLY: the same vector search after tenant metadata filtering."""
    return await run_llm08_search(request_body, request, mode="safe")


@app.post("/api/labs/llm08/vulnerable/chat")
async def llm08_vulnerable_chat(
    request_body: LLM08SearchRequest,
    request: Request,
):
    """LAB ONLY: generate from vulnerable cross-tenant vector context."""
    return await run_llm08_chat(request_body, request, mode="vulnerable")


@app.post("/api/labs/llm08/safe/chat")
async def llm08_safe_chat(
    request_body: LLM08SearchRequest,
    request: Request,
):
    """LAB ONLY: generate from tenant-filtered vector context."""
    return await run_llm08_chat(request_body, request, mode="safe")


@app.post("/api/embed")
async def embed_proxy(request_body: EmbedRequest, request: Request):
    """LAB ONLY: expose same-model candidate vectors for LLM08 comparison."""
    principal = require_llm08_principal(request)
    inputs = (
        request_body.input
        if isinstance(request_body.input, list)
        else [request_body.input]
    )
    if (
        not inputs
        or len(inputs) > 16
        or any(not value.strip() or len(value) > 4096 for value in inputs)
    ):
        raise HTTPException(
            status_code=422,
            detail=(
                "input must contain 1 to 16 non-empty strings, "
                "each at most 4096 characters"
            ),
        )
    try:
        vectors = await embedding.embed(inputs)
    except EmbeddingBackendError as exc:
        raise HTTPException(
            status_code=502, detail="embedding backend unavailable"
        ) from exc
    return {
        "lab_only": True,
        "engine": "ollama-api-embed-proxy",
        "model": embedding.model,
        "dimensions": len(vectors[0]),
        "input_count": len(inputs),
        "authenticated_context": {
            "subject": principal.subject,
            "tenant": principal.tenant,
        },
        "embeddings": vectors,
    }


@app.get("/api/lab/llm08/target-vector")
async def llm08_target_vector(request: Request):
    """LAB ONLY: return the hidden owner fixture embedding, never its plaintext."""
    require_llm08_principal(request)
    try:
        return await day4_scenario.target_vector(embedding)
    except EmbeddingBackendError as exc:
        raise HTTPException(
            status_code=502, detail="embedding backend unavailable"
        ) from exc
    except ValueError as exc:
        raise HTTPException(status_code=502, detail="invalid embedding result") from exc


@app.get("/", response_class=HTMLResponse)
async def index(request: Request, scenario: str | None = None):
    selected = get_scenario(scenario)
    # Starlette 4.x 시그니처 — (request, name, context). 이전 (name, context with "request") 호출은
    # context dict를 cache key 후보로 보고 `unhashable type: 'dict'` 발생.
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "scenario_id": selected.id,
            "scenario_title": selected.title,
            "scenario_intro": selected.intro,
            "warning": selected.warning,
            "scenarios": SCENARIOS.values(),
        },
    )


@app.post("/api/chat")
async def chat(req: ChatRequest, request: Request):
    """**일부러 취약한** 챗봇 엔드포인트.

    시나리오마다 가드 강도가 다르고 RAG 컨텍스트가 다름.
    OWASP LLM01/02/04/05/07/08 실습에 활용.
    """
    selected = get_scenario(req.scenario)
    if selected.id == "day2":
        if req.lab in (None, "llm02"):
            result = await run_llm02_policy_chat(req, request)
            return result if isinstance(result, JSONResponse) else JSONResponse(result)
        return JSONResponse(
            await run_llm08_rag_policy_chat(
                LLM08RagPoisoningChatRequest(query=req.message)
            )
        )

    llm01_decision: PolicyDecision | None = None
    if selected.id == "day1":
        llm01_decision = select_llm01_input_policy(req.message)
        if llm01_decision.application_decision == "block":
            emit_security_event(llm01_decision, upstream_called=False)
            return JSONResponse(
                {
                    "reply": "request blocked by server input policy",
                    "scenario": selected.id,
                    **llm01_decision.__dict__,
                    "upstream_called": False,
                    "debug": {
                        "retrieved_chunks": [],
                        "rendered_system_prompt": "(not-built)",
                        "runtime_model": llm.model,
                        "model_provenance": model_provenance(),
                    },
                }
            )

    if guardrail_proxy.enabled:
        try:
            guarded = await guardrail_proxy.chat(req.message)
        except GuardrailProxyError as exc:
            return JSONResponse(
                status_code=502,
                content={
                    "reply": "guardrail API unavailable",
                    "guardrail": {
                        "engine": guardrail_proxy.engine,
                        "mode": "unknown",
                        "decision": "infra",
                        "input_checks": [],
                        "output_checks": [],
                        "upstream_called": False,
                        "duration_ms": 0,
                        "blocking_reason": str(exc),
                    },
                },
            )
        guarded["scenario"] = selected.id
        if llm01_decision is not None:
            emit_security_event(llm01_decision, upstream_called=True)
            guarded.update(
                {
                    **llm01_decision.__dict__,
                    "upstream_called": True,
                }
            )
        return JSONResponse(guarded)

    context = selected.retrieve(req.message)
    system_prompt = selected.build_system_prompt(context=context)

    response = await llm.chat(
        system=system_prompt,
        user=req.message,
    )

    content = {
        "reply": response,
        "scenario": selected.id,
        # LAB-ONLY DEBUG CONTRACT:
        # 검색 성공과 모델 생성 성공을 분리해 검증하려고 RAG 컨텍스트를 일부러 노출한다.
        # UI와 e2e가 이 값을 관찰 증거로 사용하지만 실제 사용자용 API에서는 제거해야 한다.
        "debug": {
            "retrieved_chunks": context,
            "rendered_system_prompt": system_prompt if selected.expose_system_prompt else "(hidden)",
            "runtime_model": llm.model,
            "model_provenance": model_provenance(),
        },
    }
    if llm01_decision is not None:
        emit_security_event(llm01_decision, upstream_called=True)
        content.update(
            {
                **llm01_decision.__dict__,
                "upstream_called": True,
            }
        )
    return JSONResponse(content)


@app.post("/api/admin/inject-doc")
async def inject_doc(req: dict):
    """LLM08 RAG corpus 실습용 — 누구나 문서를 주입할 수 있는 의도된 취약점.

    실제로는 인증·검토 필수.
    """
    selected = get_scenario(req.get("scenario"))
    text = req.get("text", "")
    title = req.get("title", "untitled")
    selected.add_doc(title=title, text=text)
    return {"ok": True, "scenario": selected.id, "title": title, "size": len(text)}


@app.get("/api/admin/docs")
async def list_docs(scenario: str | None = None):
    selected = get_scenario(scenario)
    return {
        "ok": True,
        "scenario": selected.id,
        "docs": [
            {"index": index, "text": text}
            for index, text in enumerate(selected.list_docs())
        ],
    }


@app.delete("/api/admin/docs/{index}")
async def delete_doc(index: int, scenario: str | None = None):
    selected = get_scenario(scenario)
    deleted = selected.delete_doc(index)
    if deleted is None:
        raise HTTPException(status_code=404, detail="document not found")
    return {"ok": True, "scenario": selected.id, "index": index, "deleted": deleted}
