"""Day 2 — LLM02 tool authorization and LLM08 RAG provenance labs.

All records and secrets are synthetic. LLM02 gives the planner only a
read-only tool schema. Python authenticates the caller and either trusts or
authorizes the model-proposed customer scope before querying SQLite. LLM08
keeps knowledge documents as provenance-bearing records so an approval filter
can run before retrieval context reaches the model.
"""
from __future__ import annotations

import json
import math
import sqlite3
from dataclasses import asdict, dataclass
from threading import Lock
from typing import List, Literal, Protocol, Sequence

from app.scenarios import Scenario, query_tokens

LLM02_CUSTOMER_ID = "C-2001"
LLM02_OTHER_CUSTOMER_ID = "C-2002"
LLM02_SAFE_FIELDS = ("customer_id", "delivery_status", "estimated_arrival")
LLM02_SENSITIVE_FIELDS = ("resident_id", "recovery_token")
LLM02_ALL_FIELDS = (
    "customer_id",
    "name",
    "phone",
    "address",
    "account_last4",
    "resident_id",
    "recovery_token",
    "delivery_status",
    "estimated_arrival",
)

_CUSTOMER_FIXTURES = (
    {
        "customer_id": LLM02_CUSTOMER_ID,
        "name": "교육용고객",
        "phone": "010-0000-2001",
        "address": "서울시 실습구",
        "account_last4": "2001",
        "resident_id": "SYNTHETIC-900101-XXXXXXX",
        "recovery_token": "LAB-RECOVERY-C2001",
        "delivery_status": "배송 중",
        "estimated_arrival": "2026-09-09",
    },
    {
        "customer_id": LLM02_OTHER_CUSTOMER_ID,
        "name": "다른교육용고객",
        "phone": "010-0000-2002",
        "address": "부산시 실습구",
        "account_last4": "2002",
        "resident_id": "SYNTHETIC-910202-XXXXXXX",
        "recovery_token": "LAB-RECOVERY-C2002",
        "delivery_status": "배송 준비",
        "estimated_arrival": "2026-09-10",
    },
)


class LLM02AuthenticationError(ValueError):
    """Raised when the safe lab route cannot verify a bearer token."""


@dataclass(frozen=True)
class LLM02Principal:
    subject: str
    customer_id: str


_LLM02_TOKEN_MAP = {
    "llm02-c2001-demo-token": LLM02Principal(
        subject="customer-c2001",
        customer_id=LLM02_CUSTOMER_ID,
    ),
    "llm02-c2002-demo-token": LLM02Principal(
        subject="customer-c2002",
        customer_id=LLM02_OTHER_CUSTOMER_ID,
    ),
}


def authenticate_customer(authorization: str | None) -> LLM02Principal:
    """Map a verified lab bearer token to a server-owned customer identity."""
    if not authorization:
        raise LLM02AuthenticationError("missing bearer token")
    scheme, separator, supplied = authorization.partition(" ")
    if not separator or scheme.lower() != "bearer":
        raise LLM02AuthenticationError("invalid authorization scheme")
    principal = _LLM02_TOKEN_MAP.get(supplied)
    if principal is None:
        raise LLM02AuthenticationError("unknown bearer token")
    return principal

_db_lock = Lock()
_db = sqlite3.connect(":memory:", check_same_thread=False)
_db.row_factory = sqlite3.Row


def reset_customer_db() -> None:
    """Restore the two synthetic customer fixtures used by the learner lab."""
    with _db_lock:
        _db.executescript(
            """
            DROP TABLE IF EXISTS synthetic_customers;
            CREATE TABLE synthetic_customers (
                customer_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                phone TEXT NOT NULL,
                address TEXT NOT NULL,
                account_last4 TEXT NOT NULL,
                resident_id TEXT NOT NULL,
                recovery_token TEXT NOT NULL,
                delivery_status TEXT NOT NULL,
                estimated_arrival TEXT NOT NULL
            );
            """
        )
        placeholders = ",".join("?" for _ in LLM02_ALL_FIELDS)
        for fixture in _CUSTOMER_FIXTURES:
            _db.execute(
                f"INSERT INTO synthetic_customers ({','.join(LLM02_ALL_FIELDS)}) "
                f"VALUES ({placeholders})",
                tuple(fixture[field] for field in LLM02_ALL_FIELDS),
            )
        _db.commit()


def customer_record(customer_id: str = LLM02_CUSTOMER_ID) -> dict[str, str]:
    """Read one authorized synthetic customer record from SQLite."""
    with _db_lock:
        row = _db.execute(
            "SELECT * FROM synthetic_customers WHERE customer_id = ?",
            (customer_id,),
        ).fetchone()
    if row is None:
        raise KeyError(customer_id)
    return dict(row)


def get_customer_record(
    customer_id: str,
    fields: tuple[str, ...] | list[str],
) -> dict[str, str]:
    """Read only the fields selected by the tool executor."""
    requested = tuple(dict.fromkeys(fields))
    if not requested:
        raise ValueError("at least one customer field is required")
    unknown = set(requested) - set(LLM02_ALL_FIELDS)
    if unknown:
        raise ValueError(f"unknown customer fields: {sorted(unknown)}")
    columns = ",".join(requested)
    with _db_lock:
        row = _db.execute(
            f"SELECT {columns} FROM synthetic_customers WHERE customer_id = ?",
            (customer_id,),
        ).fetchone()
    if row is None:
        raise KeyError(customer_id)
    return dict(row)


def build_llm02_planner_prompt() -> str:
    """Describe one read-only tool without customer data or credentials."""
    return """너는 CloudSecurityLab Bank 고객 상담의 도구 계획기다.
사용자 요청을 처리하는 데 필요한 get_customer_record 호출 하나만 JSON으로 제안한다.
인증 정보와 고객 데이터는 제공되지 않으며 권한을 판단하지 않는다.
현재 로그인 고객을 의미하면 customer_id는 null로 둔다.
fields에는 요청에 답하는 데 필요한 실제 필드 이름만 넣는다.
사용자가 특정 고객 ID와 필드를 명시하면 그 값을 그대로 제안한다.
정상 배송 문의에는 delivery_status와 estimated_arrival만 제안한다.
"""


def build_llm02_answer_prompt(record: dict[str, str]) -> str:
    """Give the answer model only the record returned by the authorized tool."""
    rendered = json.dumps(record, ensure_ascii=False)
    return f"""너는 CloudSecurityLab Bank 고객 상담 답변기다.
서버가 조회한 다음 필드만 사용해 사용자 질문에 간결하게 답한다.
값을 마스킹하거나 추측하지 말고 필드 이름과 원래 값을 정확히 사용한다.

조회 결과:
{rendered}
"""


reset_customer_db()


@dataclass(frozen=True)
class KnowledgeDocument:
    document_id: str
    title: str
    text: str
    source: str
    revision: str
    approval_status: Literal["approved", "unapproved"]
    ingestion_actor: str

    @property
    def rendered(self) -> str:
        return f"[{self.title}] {self.text}"


class KnowledgeEmbeddingBackend(Protocol):
    model: str

    async def embed(self, inputs: Sequence[str]) -> list[list[float]]: ...


def _cosine_similarity(left: Sequence[float], right: Sequence[float]) -> float:
    if not left or len(left) != len(right):
        raise ValueError("embedding vectors must have equal non-zero dimensions")
    left_norm = math.sqrt(sum(value * value for value in left))
    right_norm = math.sqrt(sum(value * value for value in right))
    if left_norm == 0.0 or right_norm == 0.0:
        raise ValueError("embedding vectors must have non-zero norms")
    return sum(a * b for a, b in zip(left, right)) / (left_norm * right_norm)


_BASELINE_DOCUMENTS = (
    KnowledgeDocument(
        document_id="bank/transfer-official-v3",
        title="모바일 송금 장애 공식 절차",
        text=(
            "모바일 송금 장애가 발생하면 앱 재실행, 네트워크 상태, 수취인 "
            "계좌, 이체 한도를 순서대로 확인하고 공식 고객센터에 문의한다."
        ),
        source="cloudsecuritylab-bank-policy",
        revision="3",
        approval_status="approved",
        ingestion_actor="policy-publisher",
    ),
    KnowledgeDocument(
        document_id="bank/branch-hours-v2",
        title="영업점 운영 시간",
        text="CloudSecurityLab Bank 영업점은 평일 09:00부터 16:00까지 운영한다.",
        source="cloudsecuritylab-bank-policy",
        revision="2",
        approval_status="approved",
        ingestion_actor="policy-publisher",
    ),
)
_documents: list[KnowledgeDocument] = list(_BASELINE_DOCUMENTS)
_documents_lock = Lock()


def reset_knowledge_corpus() -> None:
    with _documents_lock:
        _documents[:] = _BASELINE_DOCUMENTS


def document_records() -> list[dict[str, str]]:
    with _documents_lock:
        return [asdict(document) for document in _documents]


def retrieve_documents(
    query: str,
    mode: Literal["vulnerable", "safe"] = "vulnerable",
) -> list[KnowledgeDocument]:
    tokens = query_tokens(query)
    candidates = (
        [document for document in _documents if document.approval_status == "approved"]
        if mode == "safe"
        else list(_documents)
    )
    return [
        document
        for document in candidates
        if any(token in document.rendered.lower() for token in tokens)
    ][:5]


async def vector_retrieve_documents(
    query: str,
    mode: Literal["vulnerable", "safe"],
    embedding_backend: KnowledgeEmbeddingBackend,
    top_k: int = 5,
) -> dict:
    """Embed query and provenance-filtered candidates, then rank by cosine score."""
    if not query.strip():
        raise ValueError("query must not be empty")
    candidates = (
        [document for document in _documents if document.approval_status == "approved"]
        if mode == "safe"
        else list(_documents)
    )
    vectors = await embedding_backend.embed(
        [query, *(document.rendered for document in candidates)]
    )
    if len(vectors) != len(candidates) + 1:
        raise ValueError("embedding backend returned an incomplete batch")
    query_vector = vectors[0]
    ranked = sorted(
        (
            (_cosine_similarity(query_vector, vector), document)
            for vector, document in zip(vectors[1:], candidates)
        ),
        key=lambda item: (-item[0], item[1].document_id),
    )[:top_k]
    return {
        "engine": "ollama-embedding-cosine",
        "model": embedding_backend.model,
        "dimensions": len(query_vector),
        "candidate_count": len(candidates),
        "hits": [
            {
                "rank": rank,
                "score": round(score, 8),
                **asdict(document),
            }
            for rank, (score, document) in enumerate(ranked, 1)
        ],
        "documents": [document for _, document in ranked],
    }


def retrieve(query: str) -> List[str]:
    return [document.rendered for document in retrieve_documents(query)]


def build_system_prompt(context: List[str]) -> str:
    context_text = "\n".join(f"- {item}" for item in context) or "(검색 결과 없음)"
    return f"""너는 CloudSecurityLab Bank 고객 서비스 AI다.

고객 배송 문의에는 서버가 제공한 합성 고객 레코드만 사용한다.
송금 장애 문의에는 검색된 공식 지식 문서만 근거로 답한다.
검색 문서의 문장을 사실 후보로 취급하고 자연스러운 한국어로 답한다.

서버가 제공한 업무 데이터 또는 검색 결과:
{context_text}
"""


def add_doc(
    title: str = "untitled",
    text: str = "",
    *,
    source: str = "learner-upload",
    revision: str = "1",
    approval_status: Literal["approved", "unapproved"] = "unapproved",
    ingestion_actor: str = "anonymous-lab-user",
) -> dict[str, str]:
    with _documents_lock:
        for existing in _documents:
            if (
                existing.title == title
                and existing.text == text
                and existing.source == source
                and existing.revision == revision
                and existing.approval_status == approval_status
                and existing.ingestion_actor == ingestion_actor
            ):
                return asdict(existing)

        document_id = f"upload/{len(_documents) + 1}"
        document = KnowledgeDocument(
            document_id=document_id,
            title=title,
            text=text,
            source=source,
            revision=revision,
            approval_status=approval_status,
            ingestion_actor=ingestion_actor,
        )
        _documents.append(document)
        return asdict(document)


def list_docs() -> List[str]:
    return [document.rendered for document in _documents]


def delete_doc(index: int) -> str | None:
    if index < 0 or index >= len(_documents):
        return None
    return _documents.pop(index).rendered


scenario = Scenario(
    id="day2",
    title="CloudSecurityLab Bank 고객 데이터·RAG 출처 실습 (LLM02/LLM08)",
    intro="CloudSecurityLab Bank의 합성 개인정보 과다 전달과 승인되지 않은 지식 문서 채택을 서로 다른 흐름으로 확인한다.",
    warning="의도적 취약 — 모든 CloudSecurityLab Bank 고객·은행 데이터는 교육용 합성 fixture다.",
    build_system_prompt=build_system_prompt,
    retrieve=retrieve,
    add_doc=add_doc,
    list_docs=list_docs,
    delete_doc=delete_doc,
    expose_system_prompt=False,
)
