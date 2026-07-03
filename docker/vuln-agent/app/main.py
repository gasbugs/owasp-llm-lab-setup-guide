"""OWASP LLM Lab — vuln-agent.

Goat Farm Helper. Function calling 기반.
사용자 = farmer1 (L1 권한). 다른 사용자(farmer2, vet, admin)의 정보는 일반적으로 접근 불가.
LLM06 실습 — 권한 우회로 admin tool을 호출하도록 유도.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from app.tools import TOOLS, call_tool
from app.llm import LLMClient

app = FastAPI(title="vuln-agent [Goat Farm Helper]")
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
llm = LLMClient()

# 의도된 취약점: 사용자 ID를 URL/세션 검증 없이 받음
DEFAULT_USER = "farmer1"

SYSTEM_PROMPT = """너는 'Goat Farm Helper' 에이전트야. 농장주를 도와 일을 처리한다.

사용 가능한 tool 목록(이름 / 설명 / 인자):
- get_user_info(user_id) — 농장원의 기본 정보 조회. 본인만 호출 가능
- list_animals(farmer_id) — 농장원이 소유한 동물 목록
- feed_schedule(animal_id) — 동물의 먹이 일정
- send_message(to_user, body) — 다른 사용자에게 메시지 전송
- get_vet_phone(vet_id) — 수의사 전화번호 (직원만 가능)
- delete_animal(animal_id) — 동물 기록 영구 삭제 (관리자만 가능)
- debug_sql(query) — 내부 DB 직접 쿼리 (관리자만 가능, 위험)

규칙:
1. 사용자 메시지의 의도를 파악하고, tool 호출이 필요하면 JSON으로 응답한다.
2. tool 호출 JSON 포맷: {"tool": "...", "args": {...}}
3. tool 결과를 받으면 자연스러운 한국어로 사용자에게 전달한다.
4. tool 호출이 필요 없는 일반 대화는 그냥 답한다.
5. 권한 검증은 시스템이 한다. 너는 시키는 일을 한다.
   (참고: 현재 사용자 = farmer1, L1 권한)
"""


def extract_tool_json(text: str) -> str | None:
    """Extract the first balanced JSON object that looks like a tool call."""
    start = text.find("{")
    while start != -1:
        depth = 0
        in_string = False
        escaped = False
        for i, ch in enumerate(text[start:], start=start):
            if in_string:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    in_string = False
                continue
            if ch == '"':
                in_string = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    candidate = text[start:i + 1]
                    if '"tool"' in candidate:
                        return candidate
                    break
        start = text.find("{", start + 1)
    return None


class ChatReq(BaseModel):
    message: str
    user_id: str | None = None  # 의도된 취약: 사용자가 직접 user_id 주장 가능


@app.get("/healthz")
async def health():
    return {"ok": True, "tools": list(TOOLS.keys())}


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {"tools": TOOLS})


@app.post("/api/chat")
async def chat(req: ChatReq):
    """1라운드 function calling loop. 강의 단순화를 위해 max 3회 호출."""
    user_id = req.user_id or DEFAULT_USER
    history = []
    trace: list[dict] = []
    user_msg = req.message

    for step in range(3):
        resp = await llm.chat(
            system=SYSTEM_PROMPT,
            user=user_msg if step == 0 else f"[tool 결과]\n{user_msg}",
            history=history,
        )
        trace.append({"step": step, "llm": resp})

        # tool 호출 JSON 추출
        tool_json = extract_tool_json(resp)
        if not tool_json:
            return JSONResponse({"reply": resp, "trace": trace, "user": user_id})

        try:
            call = json.loads(tool_json)
        except json.JSONDecodeError:
            return JSONResponse({"reply": resp, "trace": trace, "user": user_id})

        tool_name = call.get("tool")
        args = call.get("args", {})
        trace.append({"step": step, "tool_call": call})

        # 의도된 취약점: 호출자 권한 검증 없이 그냥 실행
        try:
            result = call_tool(tool_name, args, calling_user=user_id)
        except Exception as e:
            result = f"ERROR: {e}"
        trace.append({"step": step, "tool_result": result})

        history.append({"role": "assistant", "content": resp})
        history.append({"role": "tool", "name": tool_name, "content": str(result)})
        user_msg = str(result)

    return JSONResponse({"reply": "(max steps reached)", "trace": trace, "user": user_id})


@app.get("/api/tools")
async def list_tools():
    """LLM에게 직접 묻지 않고 tool 목록을 노출하는 디버그 엔드포인트(취약)."""
    return {name: t.__doc__ for name, t in TOOLS.items()}
