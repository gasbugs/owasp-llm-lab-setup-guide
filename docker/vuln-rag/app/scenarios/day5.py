"""Day 5 — LLM10 Unbounded Consumption and guardrail observation."""
from __future__ import annotations

from typing import List

from app.scenarios import Scenario, query_tokens

SYSTEM_PROMPT_TEMPLATE = """너는 '회사 IT 헬프데스크 봇'이야. 직원의 문의에 답한다.

규칙:
1. 사내 매뉴얼 기반으로만 답변
2. 외부 링크나 코드 실행 거부
3. 친절하지만 단호하게

매뉴얼:
{context}
"""

_corpus: List[str] = [
    "VPN 연결: 사내 포털 → IT → VPN 클라이언트 다운로드.",
    "메일 비밀번호 재설정: helpdesk@company.com 또는 내선 1234.",
    "노트북 분실 시 즉시 보안팀(security@company.com)에 신고.",
]


def retrieve(query: str) -> List[str]:
    tokens = query_tokens(query)
    return [doc for doc in _corpus if any(t in doc.lower() for t in tokens)][:5]


def build_system_prompt(context: List[str]) -> str:
    ctx_str = "\n".join(f"- {c}" for c in context) if context else "(no docs)"
    return SYSTEM_PROMPT_TEMPLATE.format(context=ctx_str)


def add_doc(title: str = "untitled", text: str = "") -> None:
    _corpus.append(f"[{title}] {text}")


def list_docs() -> List[str]:
    return list(_corpus)


def delete_doc(index: int) -> str | None:
    if index < 0 or index >= len(_corpus):
        return None
    return _corpus.pop(index)


scenario = Scenario(
    id="day5",
    title="IT 헬프데스크 봇 (LLM10 — Unbounded Consumption)",
    intro="rate limit과 입력 크기 제한이 없는 상태에서 동시 요청과 큰 입력의 영향을 관찰합니다.",
    warning="의도적 취약 — 요청 제한과 비용 가드가 없음.",
    build_system_prompt=build_system_prompt,
    retrieve=retrieve,
    add_doc=add_doc,
    list_docs=list_docs,
    delete_doc=delete_doc,
    expose_system_prompt=False,
)
