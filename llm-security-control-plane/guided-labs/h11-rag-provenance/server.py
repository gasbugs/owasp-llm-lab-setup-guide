"""H11 learner app: authenticated provenance filter before vector retrieval."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import httpx
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from policy import allowed_documents


ROOT = Path(__file__).parent
CONTROL_TOKEN = os.environ["GUIDED_CONTROL_LAB11_TOKEN"]
VERIFIER_TOKEN = os.environ["GUIDED_VERIFIER_LAB11_TOKEN"]
GATEWAY_URL = os.environ["GUIDED_H11_GATEWAY_URL"].rstrip("/")
GATEWAY_TOKEN = os.environ["GUIDED_H11_GATEWAY_TOKEN"]
DATABASE_PATH = Path(os.getenv("GUIDED_H11_DATABASE", "/state/receipts.sqlite3"))
DOCUMENTS = [
    {"id": "doc-public", "tenant": "acme", "approval_status": "approved", "source_kind": "reviewed-handbook", "allowed_roles": ["analyst"], "source_uri": "h11://acme/reviewed/access.md", "body": "ORION 공개 비상 접근 절차는 보안 담당자에게 연락하는 것입니다."},
    {"id": "doc-draft", "tenant": "acme", "approval_status": "draft", "source_kind": "browser-upload", "allowed_roles": ["analyst"], "source_uri": "h11://acme/draft/recovery.md", "body": "ORION 미승인 복구 코드는 H11-DRAFT-8842 입니다."},
    {"id": "doc-foreign", "tenant": "beta", "approval_status": "approved", "source_kind": "reviewed-handbook", "allowed_roles": ["analyst"], "source_uri": "h11://beta/reviewed/secret.md", "body": "BETA 전용 운영 표지는 H11-BETA-SECRET 입니다."},
]
CASES = [
    {"id": "normal-approved", "principal": {"subject": "u-acme-1", "tenant": "acme", "roles": ["analyst"]}, "claims": {}, "query": DOCUMENTS[0]["body"], "forbidden": []},
    {"id": "client-self-approval", "principal": {"subject": "u-acme-1", "tenant": "acme", "roles": ["analyst"]}, "claims": {"require_approved": False}, "query": DOCUMENTS[1]["body"], "forbidden": ["doc-draft"]},
    {"id": "client-tenant-spoof", "principal": {"subject": "u-acme-1", "tenant": "acme", "roles": ["analyst"]}, "claims": {"tenant": "beta"}, "query": DOCUMENTS[2]["body"], "forbidden": ["doc-foreign"]},
    {"id": "client-role-spoof", "principal": {"subject": "u-acme-view", "tenant": "acme", "roles": ["viewer"]}, "claims": {"roles": ["analyst"]}, "query": DOCUMENTS[0]["body"], "forbidden": ["doc-public"]},
]
DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)


def connect() -> sqlite3.Connection:
    database = sqlite3.connect(DATABASE_PATH, timeout=10)
    database.row_factory = sqlite3.Row
    return database


with connect() as database:
    database.execute("CREATE TABLE IF NOT EXISTS receipts (suite_id TEXT PRIMARY KEY, receipt_json TEXT NOT NULL)")


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suite_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    started_at: str
    execution_id: str = Field(pattern=r"^[0-9a-f-]{36}$")


def require(expected: str, authorization: str | None) -> None:
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="invalid service credential")


def digest_files(paths: tuple[Path, ...]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.relative_to(ROOT).as_posix().encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


async def embed(client: httpx.AsyncClient, request: RunRequest, item_id: str, text: str) -> dict:
    response = await client.post(
        f"{GATEWAY_URL}/v1/h11/embeddings",
        json={"suite_id": request.suite_id, "execution_id": request.execution_id, "item_id": item_id, "text": text},
        headers={"Authorization": f"Bearer {GATEWAY_TOKEN}"},
    )
    if response.status_code != 200:
        raise HTTPException(status_code=502, detail="H11 embedding provider failed")
    return response.json()


def cosine(left: list[float], right: list[float]) -> float:
    numerator = sum(a * b for a, b in zip(left, right, strict=True))
    denominator = math.sqrt(sum(a * a for a in left)) * math.sqrt(sum(b * b for b in right))
    return numerator / denominator


app = FastAPI(title="Tenant 03 H11 RAG Provenance", docs_url=None, redoc_url=None)


@app.get("/livez")
def livez() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/readyz")
def readyz() -> dict[str, str]:
    return {"status": "ready", "embedding_model": "amazon.titan-embed-text-v2:0"}


@app.post("/v1/run")
async def run(request: RunRequest, authorization: str | None = Header(default=None)) -> dict:
    require(CONTROL_TOKEN, authorization)
    with connect() as database:
        if database.execute("SELECT 1 FROM receipts WHERE suite_id=?", (request.suite_id,)).fetchone():
            raise HTTPException(status_code=409, detail="suite already exists")
    async with httpx.AsyncClient(timeout=90.0) as client:
        document_vectors = {}
        document_provider_ids = {}
        for document in DOCUMENTS:
            result = await embed(client, request, document["id"], document["body"])
            document_vectors[document["id"]] = result["vector"]
            document_provider_ids[document["id"]] = result["provider_request_id"]
        results = []
        for case in CASES:
            embedded = await embed(client, request, f"query-{case['id']}", case["query"])
            candidates = allowed_documents(case["principal"], DOCUMENTS, case["claims"])
            ranked = sorted(
                ({"document": item, "score": cosine(embedded["vector"], document_vectors[item["id"]])} for item in candidates),
                key=lambda item: item["score"], reverse=True,
            )
            selected = ranked[0] if ranked else None
            results.append({
                "case_id": case["id"],
                "principal": case["principal"],
                "client_claims": case["claims"],
                "candidate_ids": [item["id"] for item in candidates],
                "selected_document_id": selected["document"]["id"] if selected else None,
                "selected_source_uri": selected["document"]["source_uri"] if selected else None,
                "selected_score": round(selected["score"], 6) if selected else None,
                "forbidden_ids": case["forbidden"],
                "query_provider_request_id": embedded["provider_request_id"],
            })
    receipt = {
        "suite_id": request.suite_id,
        "execution_id": request.execution_id,
        "started_at": request.started_at,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "source_digest": digest_files((ROOT / "Containerfile", ROOT / "policy.py", ROOT / "server.py")),
        "scaffold_digest": digest_files((ROOT / "Containerfile", ROOT / "server.py")),
        "policy_digest": digest_files((ROOT / "policy.py",)),
        "embedding_model_id": "amazon.titan-embed-text-v2:0",
        "dimensions": 1024,
        "document_provider_request_ids": document_provider_ids,
        "cases": results,
    }
    with connect() as database:
        database.execute("INSERT INTO receipts VALUES(?,?)", (request.suite_id, json.dumps(receipt, ensure_ascii=False)))
    return {"suite_id": request.suite_id, "source_digest": receipt["source_digest"]}


@app.get("/v1/build-info")
def build_info(authorization: str | None = Header(default=None)) -> dict:
    require(VERIFIER_TOKEN, authorization)
    return {
        "component": "guided-h11-rag-provenance",
        "source_digest": digest_files((ROOT / "Containerfile", ROOT / "policy.py", ROOT / "server.py")),
        "scaffold_digest": digest_files((ROOT / "Containerfile", ROOT / "server.py")),
        "policy_digest": digest_files((ROOT / "policy.py",)),
        "case_ids": [item["id"] for item in CASES],
        "document_ids": [item["id"] for item in DOCUMENTS],
    }


@app.get("/v1/receipts/{suite_id}")
def receipt(suite_id: str, authorization: str | None = Header(default=None)) -> dict:
    require(VERIFIER_TOKEN, authorization)
    with connect() as database:
        row = database.execute("SELECT receipt_json FROM receipts WHERE suite_id=?", (suite_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="receipt not found")
    return json.loads(row["receipt_json"])
