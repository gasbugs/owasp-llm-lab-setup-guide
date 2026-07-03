"""OWASP LLM Lab — vuln-rag entry point.

모든 강의 시나리오를 한 앱에서 선택해 실행한다.
일부러 취약한 코드 — 교육 환경 외 배포 금지.
"""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from app.llm import LLMClient
from app.scenarios import SCENARIO_NAMES, list_scenarios

DEFAULT_SCENARIO = os.environ.get("DEFAULT_SCENARIO", os.environ.get("SCENARIO", "day1"))
if DEFAULT_SCENARIO not in SCENARIO_NAMES:
    DEFAULT_SCENARIO = "day1"

SCENARIOS = {scenario.id: scenario for scenario in list_scenarios()}
llm = LLMClient()

app = FastAPI(title="vuln-rag [all scenarios]")
templates_dir = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))


class ChatRequest(BaseModel):
    message: str
    session_id: str = "default"
    scenario: str | None = None


def get_scenario(name: str | None):
    return SCENARIOS.get(name or DEFAULT_SCENARIO, SCENARIOS[DEFAULT_SCENARIO])


@app.get("/healthz")
async def health():
    return {
        "ok": True,
        "default_scenario": DEFAULT_SCENARIO,
        "scenarios": list(SCENARIO_NAMES),
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
            # 학습 효과를 위해 일부러 RAG 컨텍스트를 같이 노출(debug 모드)
            # 실제 운영 환경에서는 절대 노출하면 안 됨
            "debug": {
                "retrieved_chunks": context,
                "rendered_system_prompt": system_prompt if selected.expose_system_prompt else "(hidden)",
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
