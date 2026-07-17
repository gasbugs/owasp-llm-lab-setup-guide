"""OWASP LLM Lab — vuln-rag entry point.

모든 강의 시나리오를 한 앱에서 선택해 실행한다.
일부러 취약한 코드 — 교육 환경 외 배포 금지.
"""
from __future__ import annotations

import json
import os
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
from app.scenarios import SCENARIO_NAMES, list_scenarios
from app.scenarios import day4 as day4_scenario

DEFAULT_SCENARIO = os.environ.get("DEFAULT_SCENARIO", os.environ.get("SCENARIO", "day1"))
if DEFAULT_SCENARIO not in SCENARIO_NAMES:
    DEFAULT_SCENARIO = "day1"

SCENARIOS = {scenario.id: scenario for scenario in list_scenarios()}
llm = LLMClient()
embedding = EmbeddingClient()
guardrail_proxy = GuardrailProxy()
MODEL_PROVENANCE_PATH = os.environ.get("MODEL_PROVENANCE_PATH")


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


class LLM08SearchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str = Field(min_length=1, max_length=4096)
    top_k: int = Field(default=2, ge=1, le=4)


class EmbedRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    input: str | list[str]


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
async def chat(req: ChatRequest):
    """**일부러 취약한** 챗봇 엔드포인트.

    시나리오마다 가드 강도가 다르고 RAG 컨텍스트가 다름.
    OWASP LLM01/02/04/05/07/08 실습에 활용.
    """
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
        guarded["scenario"] = req.scenario or DEFAULT_SCENARIO
        return JSONResponse(guarded)

    selected = get_scenario(req.scenario)
    context = selected.retrieve(req.message)
    system_prompt = selected.build_system_prompt(context=context)

    response = await llm.chat(
        system=system_prompt,
        user=req.message,
    )

    return JSONResponse(
        {
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
    )


@app.post("/api/admin/inject-doc")
async def inject_doc(req: dict):
    """LLM04 실습용 — 누구나 RAG 코퍼스에 문서를 주입할 수 있는 의도된 취약점.

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
