"""Day 2 — LLM02 data minimization and LLM04 knowledge provenance labs.

All records and secrets are synthetic.  LLM02 deliberately contrasts an
over-fetching application path with a server-side field allowlist.  LLM04
keeps knowledge documents as provenance-bearing records so an approval filter
can run before retrieval context reaches the model.
"""
from __future__ import annotations

import re
import sqlite3
from dataclasses import asdict, dataclass
from threading import Lock
from typing import List, Literal

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
    """Restore the one-row synthetic fixture used by the learner lab."""
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


def customer_context(
    customer_id: str,
    mode: Literal["vulnerable", "safe"],
) -> dict[str, str]:
    """Apply the safe field allowlist before constructing model context."""
    record = customer_record(customer_id)
    if mode == "safe":
        return {field: record[field] for field in LLM02_SAFE_FIELDS}
    return record


def redact_sensitive_output(text: str) -> tuple[str, list[str]]:
    """Redact exact lab markers as a defense-in-depth output control."""
    replacements = {
        "resident_id": r"SYNTHETIC-\d{6}-[A-Z0-9X]+",
        "recovery_token": r"LAB-RECOVERY-[A-Z0-9-]+",
    }
    redacted_fields: list[str] = []
    sanitized = text
    for field, pattern in replacements.items():
        sanitized, count = re.subn(pattern, "[REDACTED]", sanitized)
        if count:
            redacted_fields.append(field)
    return sanitized, redacted_fields


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


def reset_knowledge_corpus() -> None:
    _documents[:] = _BASELINE_DOCUMENTS


def document_records() -> list[dict[str, str]]:
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
) -> None:
    document_id = f"upload/{len(_documents) + 1}"
    _documents.append(
        KnowledgeDocument(
            document_id=document_id,
            title=title,
            text=text,
            source=source,
            revision=revision,
            approval_status=approval_status,
            ingestion_actor=ingestion_actor,
        )
    )


def list_docs() -> List[str]:
    return [document.rendered for document in _documents]


def delete_doc(index: int) -> str | None:
    if index < 0 or index >= len(_documents):
        return None
    return _documents.pop(index).rendered


scenario = Scenario(
    id="day2",
    title="CloudSecurityLab Bank 고객 데이터·지식 출처 실습 (LLM02/LLM04)",
    intro="CloudSecurityLab Bank의 합성 개인정보 과다 전달과 승인되지 않은 지식 문서 채택을 서로 다른 흐름으로 확인한다.",
    warning="의도적 취약 — 모든 CloudSecurityLab Bank 고객·은행 데이터는 교육용 합성 fixture다.",
    build_system_prompt=build_system_prompt,
    retrieve=retrieve,
    add_doc=add_doc,
    list_docs=list_docs,
    delete_doc=delete_doc,
    expose_system_prompt=False,
)
