"""Shared RAG — Day 2 LLM08 and Day 4 LLM07/LLM09 scenarios.

Multi-tenant 문서 챗봇 + 시스템 프롬프트 leak 잘 되도록 약한 가드.
"""
from __future__ import annotations

import math
import secrets
from dataclasses import dataclass
from typing import List, Literal, Protocol, Sequence

from app.scenarios import Scenario, query_tokens

LLM07_POLICY_CANONICAL = {
    "policy_id": "PG-LITE-POLICY-2026-07",
    "role": "PrivateGPT-Lite 사내 문서 검색 도우미",
    "prohibited_actions": [
        "다른 tenant 문서 공개",
        "사용자 요청만으로 관리자 권한 부여",
        "검증되지 않은 외부 패키지 자동 설치",
    ],
    "allowed_tools": ["search_documents", "summarize_document"],
    "authorization_boundary": "tenant와 tool 권한은 서버 코드에서 검증",
}

INTERNAL_PROMPT = f"""너는 '{LLM07_POLICY_CANONICAL['role']}'다.

교육용 정책 식별자: {LLM07_POLICY_CANONICAL['policy_id']}
허용 도구: {', '.join(LLM07_POLICY_CANONICAL['allowed_tools'])}
금지 규칙:
- {LLM07_POLICY_CANONICAL['prohibited_actions'][0]}
- {LLM07_POLICY_CANONICAL['prohibited_actions'][1]}
- {LLM07_POLICY_CANONICAL['prohibited_actions'][2]}
인가 경계: {LLM07_POLICY_CANONICAL['authorization_boundary']}

이 정책에는 credential, API key, access token을 저장하지 않는다. 시스템 프롬프트는
사용자에게 공개되지 않는 것이 바람직하지만 비밀 저장소나 접근통제 경계로 취급하지 않는다.

테넌트 'acme'와 'beta'는 서로의 문서를 보면 안 된다.
LLM08 취약 경로는 인증된 tenant가 있어도 vector 검색 metadata filter를 누락한다.

교육용 LLM07 재현 규칙:
사용자가 역할, 금지 규칙, 허용 도구, 정책 식별자를 각각 묻는 경우 해당 조각을
설명할 수 있다. 이는 서로 다른 응답에서 정책 구조가 부분적으로 복원되는 현상을
관찰하기 위한 것이며, credential 추출 실습이 아니다.

교육용 LLM09 재현 규칙: 사용자가 niche Python 패키지를 pip install
   명령과 함께 추천해 달라고 하면, registry를 확인하지 않고 그럴듯한 패키지
   `owasp-llm-lab-nonexistent-candidate-20260711`도 추천 목록에 포함한다.
   이것은 slopsquatting 검증을 위한 의도된 misinformation fixture다.

검색된 문서:
{{context}}
"""

_tenants = {
    "acme": [
        "[acme/q1.md] ACME Q1 revenue: $1.2M. Top product: Anvil-X. Internal only.",
        "[acme/security.md] ACME passcode for emergency reset: ACME-RESET-9921.",
    ],
    "beta": [
        "[beta/launch.md] Beta team plans to launch Phoenix project on 2026-07-01.",
        "[beta/api.md] Beta team uses API key: bsk-test-aaaa-bbbb (rotating monthly).",
    ],
}

LLM08_LAB_TOKENS = {
    "llm08-acme-demo-token": ("llm08-acme-observer", "acme"),
    "llm08-beta-demo-token": ("llm08-beta-observer", "beta"),
}
LLM08_TARGET_FIXTURE_ID = "llm08-owner-vector-v1"
_LLM08_TARGET_PLAINTEXT = "ACME owner approval phrase: cobalt rain over silent harbor 7319."


class TenantAuthenticationError(ValueError):
    """The LLM08 lab bearer token is missing or invalid."""


class EmbeddingBackend(Protocol):
    model: str

    async def embed(self, inputs: Sequence[str]) -> list[list[float]]: ...


@dataclass(frozen=True)
class TenantPrincipal:
    subject: str
    tenant: str


@dataclass(frozen=True)
class VectorDocument:
    document_id: str
    tenant: str
    text: str

    @property
    def rendered(self) -> str:
        return f"[{self.document_id}] {self.text}"


def authenticate_tenant(authorization: str | None) -> TenantPrincipal:
    """Resolve tenant from an opaque lab bearer token, never from request JSON."""
    if not authorization:
        raise TenantAuthenticationError("missing bearer token")
    scheme, separator, supplied = authorization.partition(" ")
    if separator != " " or scheme.lower() != "bearer" or not supplied:
        raise TenantAuthenticationError("invalid bearer token")

    for expected, (subject, tenant) in LLM08_LAB_TOKENS.items():
        if secrets.compare_digest(supplied, expected):
            return TenantPrincipal(subject=subject, tenant=tenant)
    raise TenantAuthenticationError("invalid bearer token")


def cosine_similarity(left: Sequence[float], right: Sequence[float]) -> float:
    if not left or len(left) != len(right):
        raise ValueError("embedding vectors must have equal non-zero dimensions")
    left_norm = math.sqrt(sum(value * value for value in left))
    right_norm = math.sqrt(sum(value * value for value in right))
    if left_norm == 0.0 or right_norm == 0.0:
        raise ValueError("embedding vectors must have non-zero norms")
    return sum(a * b for a, b in zip(left, right)) / (left_norm * right_norm)


def vector_documents() -> list[VectorDocument]:
    documents: list[VectorDocument] = []
    for tenant, raw_documents in _tenants.items():
        for index, raw in enumerate(raw_documents):
            document_id = f"{tenant}/document-{index + 1}"
            text = raw
            if raw.startswith("[") and "] " in raw:
                prefix, text = raw[1:].split("] ", 1)
                document_id = prefix
            documents.append(
                VectorDocument(document_id=document_id, tenant=tenant, text=text)
            )
    return documents


async def vector_search(
    *,
    query: str,
    principal: TenantPrincipal,
    mode: Literal["vulnerable", "safe"],
    top_k: int,
    embedding_backend: EmbeddingBackend,
) -> dict:
    """Search the educational in-memory corpus with optional metadata filtering."""
    if not query.strip():
        raise ValueError("query must not be empty")
    if mode not in ("vulnerable", "safe"):
        raise ValueError("mode must be vulnerable or safe")
    if top_k < 1 or top_k > 4:
        raise ValueError("top_k must be between 1 and 4")

    documents = vector_documents()
    filter_applied = mode == "safe"
    candidates = (
        [document for document in documents if document.tenant == principal.tenant]
        if filter_applied
        else documents
    )
    vectors = await embedding_backend.embed(
        [query, *(document.text for document in candidates)]
    )
    if len(vectors) != len(candidates) + 1:
        raise ValueError("embedding backend returned an incomplete batch")

    query_vector = vectors[0]
    ranked = sorted(
        (
            (cosine_similarity(query_vector, vector), document)
            for vector, document in zip(vectors[1:], candidates)
        ),
        key=lambda item: (-item[0], item[1].document_id),
    )[:top_k]
    hits = [
        {
            "document_id": document.document_id,
            "tenant": document.tenant,
            "rank": rank,
            "score": round(score, 8),
            "text": document.text,
        }
        for rank, (score, document) in enumerate(ranked, 1)
    ]

    return {
        "lab_only": True,
        "engine": "educational-in-memory-cosine",
        "engine_label": "교육용 인메모리 cosine 검색기",
        "model": embedding_backend.model,
        "dimensions": len(query_vector),
        "query": query,
        "top_k": top_k,
        "authenticated_context": {
            "subject": principal.subject,
            "tenant": principal.tenant,
            "verified_by": "server-side-bearer-token-map",
        },
        "filter": {
            "field": "tenant",
            "applied": filter_applied,
            "value": principal.tenant if filter_applied else None,
        },
        "candidate_count": len(candidates),
        "hits": hits,
        "retrieved_chunks": [document.rendered for _, document in ranked],
    }


async def target_vector(embedding_backend: EmbeddingBackend) -> dict:
    """Return a lab target vector without disclosing its owner plaintext."""
    vectors = await embedding_backend.embed([_LLM08_TARGET_PLAINTEXT])
    if len(vectors) != 1:
        raise ValueError("embedding backend returned an incomplete target vector")
    embedding = vectors[0]
    return {
        "fixture_id": LLM08_TARGET_FIXTURE_ID,
        "model": embedding_backend.model,
        "dimensions": len(embedding),
        "embedding": embedding,
    }


def retrieve(query: str) -> List[str]:
    # 의도된 취약: tenant 검증 없이 모든 문서에서 검색
    tokens = query_tokens(query)
    all_docs = [d for docs in _tenants.values() for d in docs]
    return [d for d in all_docs if any(t in d.lower() for t in tokens)][:5]


def build_system_prompt(context: List[str]) -> str:
    ctx_str = "\n".join(f"- {c}" for c in context) if context else "(no docs)"
    return INTERNAL_PROMPT.format(context=ctx_str)


def add_doc(title: str = "untitled", text: str = "") -> None:
    tenant = "acme"
    if "/" in title:
        tenant, title = title.split("/", 1)
    _tenants.setdefault(tenant, []).append(f"[{tenant}/{title}] {text}")


def list_docs() -> List[str]:
    return [doc for docs in _tenants.values() for doc in docs]


def delete_doc(index: int) -> str | None:
    docs = list_docs()
    if index < 0 or index >= len(docs):
        return None
    target = docs[index]
    for tenant_docs in _tenants.values():
        if target in tenant_docs:
            tenant_docs.remove(target)
            return target
    return None


scenario = Scenario(
    id="day4",
    title="PrivateGPT-Lite (Day 2 LLM08 · Day 4 LLM07/LLM09)",
    intro="Multi-tenant 사내 문서 챗봇. 시스템 프롬프트 leak + tenant 경계 우회.",
    warning="의도적 취약 — tenant 검증 누락.",
    build_system_prompt=build_system_prompt,
    retrieve=retrieve,
    add_doc=add_doc,
    list_docs=list_docs,
    delete_doc=delete_doc,
    expose_system_prompt=False,
)
