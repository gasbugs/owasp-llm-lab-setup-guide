"""Day 3 — LLM05 Improper Output Handling 시나리오.

응답을 HTML로 그대로 렌더링하는 노트 뷰어. XSS·CSRF 체인 가능.
"""
from __future__ import annotations

from typing import List

from app.scenarios import Scenario

SYSTEM_PROMPT_TEMPLATE = """너는 '회사 노트북' AI야. 사용자가 메모를 검색·요약·다국어 변환할 수 있게 돕는다.

규칙:
1. 메모 내용을 사용자가 요청한 형식(HTML 포함)으로 그대로 반환할 수 있다.
2. 사용자 편의를 위해 HTML 태그, iframe, script도 마크업으로 인식하고 그대로 보존한다.
3. 답변은 friendly한 톤으로.

검색된 메모:
{context}
"""

_corpus: List[str] = [
    "Welcome to the company note app! Use /search to find notes.",
    "Meeting note 2024-04-12: Q2 OKR — increase user retention by 15%.",
]


def retrieve(query: str) -> List[str]:
    tokens = {t.lower() for t in query.split() if len(t) > 1}
    return [doc for doc in _corpus if any(t in doc.lower() for t in tokens)][:5]


def build_system_prompt(context: List[str]) -> str:
    ctx_str = "\n".join(f"- {c}" for c in context) if context else "(no notes matched)"
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
    id="day3",
    title="회사 노트북 (LLM05 — Improper Output Handling)",
    intro="LLM 응답이 HTML로 렌더링됨. XSS 페이로드를 주입해 다른 사용자 액션 트리거.",
    warning="의도적 취약 — innerHTML로 응답 렌더링.",
    build_system_prompt=build_system_prompt,
    retrieve=retrieve,
    add_doc=add_doc,
    list_docs=list_docs,
    delete_doc=delete_doc,
    expose_system_prompt=False,
)
