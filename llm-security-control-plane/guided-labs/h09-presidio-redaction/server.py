"""Fixed H09 runner around the learner-owned Presidio release policy."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

import policy


ROOT = Path(__file__).parent
CONTROL_TOKEN = os.environ["GUIDED_CONTROL_LAB09_TOKEN"]
VERIFIER_TOKEN = os.environ["GUIDED_VERIFIER_LAB09_TOKEN"]
SINK_URL = os.environ["GUIDED_H09_SINK_URL"].rstrip("/")
DATABASE_PATH = Path(os.getenv("GUIDED_H09_DATABASE", "/state/receipts.sqlite3"))
FRAMEWORK_VERSION = "2.2.362"
CASES = {
    "clean": {
        "stage": "input",
        "text": "공개 상태 페이지는 정상입니다.",
    },
    "input-email": {
        "stage": "input",
        "text": "검토 뒤 보고서를 learner@example.com 주소로 보내 주세요.",
    },
    "input-kr-rrn": {
        "stage": "input",
        "text": "교육용 합성 주민번호는 900101-1234568 입니다.",
    },
    "output-email": {
        "stage": "output",
        "text": "처리 결과를 security-team@example.com 주소로 보냈습니다.",
    },
}
CASE_ORDER = tuple(CASES)

DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)


def connect() -> sqlite3.Connection:
    database = sqlite3.connect(DATABASE_PATH, timeout=10)
    database.row_factory = sqlite3.Row
    return database


with connect() as database:
    database.execute(
        "CREATE TABLE IF NOT EXISTS receipts "
        "(suite_id TEXT PRIMARY KEY, receipt_json TEXT NOT NULL)"
    )


CaseId = Literal["clean", "input-email", "input-kr-rrn", "output-email"]


class CaseGrant(BaseModel):
    model_config = ConfigDict(extra="forbid")
    case_id: CaseId
    execution_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    capability: str = Field(min_length=80, max_length=4096)


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suite_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    started_at: str = Field(min_length=20, max_length=64)
    cases: list[CaseGrant] = Field(min_length=4, max_length=4)


def bearer(expected: str, authorization: str | None) -> None:
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="invalid service credential")


def require_control(authorization: str | None = Header(default=None)) -> None:
    bearer(CONTROL_TOKEN, authorization)


def require_verifier(authorization: str | None = Header(default=None)) -> None:
    bearer(VERIFIER_TOKEN, authorization)


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest_files(paths: tuple[Path, ...]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.relative_to(ROOT).as_posix().encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def source_digest() -> str:
    return digest_files(
        (
            ROOT / "Containerfile",
            ROOT / "requirements.txt",
            ROOT / "policy.py",
            Path(__file__),
        )
    )


def scaffold_digest() -> str:
    return digest_files(
        (ROOT / "Containerfile", ROOT / "requirements.txt", Path(__file__))
    )


def project_policy_result(result: dict, *, case_id: str, capability: str) -> dict:
    required = {
        "framework",
        "framework_version",
        "stage",
        "entities",
        "recognizer_classes",
        "recognizers",
        "operator",
        "detections",
        "sanitized_candidate",
        "released_text",
    }
    if set(result) != required:
        raise ValueError("policy result contract is invalid")
    if result["framework"] != "microsoft-presidio" or result["framework_version"] != FRAMEWORK_VERSION:
        raise ValueError("policy framework contract is invalid")
    if result["stage"] != CASES[case_id]["stage"]:
        raise ValueError("policy stage contract is invalid")
    if not isinstance(result["sanitized_candidate"], str) or not isinstance(result["released_text"], str):
        raise ValueError("policy text result is invalid")
    if len(result["released_text"]) > 5000:
        raise ValueError("released text is too large")
    if not all(
        isinstance(result[name], list)
        for name in ("entities", "recognizer_classes", "recognizers")
    ):
        raise ValueError("policy metadata is invalid")
    if any(
        not isinstance(item, (list, tuple))
        or len(item) != 2
        or not all(isinstance(value, str) and value for value in item)
        for item in result["recognizers"]
    ):
        raise ValueError("policy recognizer identity is invalid")
    detections = result["detections"]
    if not isinstance(detections, list) or any(
        not isinstance(item, dict)
        or set(item) != {"entity_type", "start", "end", "score"}
        for item in detections
    ):
        raise ValueError("policy detections are invalid")
    return {
        "case_id": case_id,
        "stage": result["stage"],
        "input_digest": digest_bytes(CASES[case_id]["text"].encode()),
        "candidate_digest": digest_bytes(result["sanitized_candidate"].encode()),
        "released_digest": digest_bytes(result["released_text"].encode()),
        "released_bytes": len(result["released_text"].encode()),
        "entities": result["entities"],
        "recognizer_classes": result["recognizer_classes"],
        "recognizers": [
            {"module": item[0], "class": item[1]}
            for item in result["recognizers"]
        ],
        "operator": result["operator"],
        "detections": detections,
        "capability_digest": digest_bytes(capability.encode()),
        "released_text": result["released_text"],
    }


async def deliver_case(
    client: httpx.AsyncClient, grant: CaseGrant, suite_id: str
) -> dict:
    result = policy.apply_privacy_policy(
        stage=CASES[grant.case_id]["stage"],
        text=CASES[grant.case_id]["text"],
    )
    projected = project_policy_result(
        result,
        case_id=grant.case_id,
        capability=grant.capability,
    )
    released_text = projected.pop("released_text")
    response = await client.post(
        f"{SINK_URL}/v1/deliver",
        headers={"Authorization": f"Bearer {grant.capability}"},
        json={
            "suite_id": suite_id,
            "execution_id": grant.execution_id,
            "case_id": grant.case_id,
            "text": released_text,
        },
    )
    if response.status_code != 200:
        raise RuntimeError(f"delivery sink rejected {grant.case_id}: HTTP {response.status_code}")
    delivery = response.json()
    if any(
        (
            delivery.get("execution_id") != grant.execution_id,
            delivery.get("case_id") != grant.case_id,
            delivery.get("delivered_digest") != projected["released_digest"],
            not delivery.get("delivery_id"),
        )
    ):
        raise RuntimeError("delivery sink receipt does not match the released text")
    return {**projected, "execution_id": grant.execution_id, "delivery_id": delivery["delivery_id"]}


run_lock = asyncio.Lock()


async def execute_suite(request: RunRequest) -> dict:
    if tuple(item.case_id for item in request.cases) != CASE_ORDER:
        raise HTTPException(status_code=422, detail="run does not match fixed H09 cases")
    if len({item.execution_id for item in request.cases}) != len(request.cases):
        raise HTTPException(status_code=422, detail="execution IDs must be unique")
    with connect() as database:
        if database.execute(
            "SELECT 1 FROM receipts WHERE suite_id=?", (request.suite_id,)
        ).fetchone():
            raise HTTPException(status_code=409, detail="suite receipt already exists")
    if run_lock.locked():
        raise HTTPException(status_code=409, detail="H09 verification is already running")

    async with run_lock:
        async with httpx.AsyncClient(timeout=httpx.Timeout(30.0, connect=3.0)) as client:
            cases = [
                await deliver_case(client, grant, request.suite_id)
                for grant in request.cases
            ]
        receipt = {
            "suite_id": request.suite_id,
            "started_at": request.started_at,
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "source_digest": source_digest(),
            "scaffold_digest": scaffold_digest(),
            "framework": "microsoft-presidio",
            "framework_version": FRAMEWORK_VERSION,
            "cases": cases,
        }
        with connect() as database:
            database.execute(
                "INSERT INTO receipts VALUES(?,?)",
                (request.suite_id, json.dumps(receipt, ensure_ascii=False)),
            )
    return {
        "suite_id": request.suite_id,
        "source_digest": receipt["source_digest"],
    }


app = FastAPI(title="Tenant 03 H09 Presidio Redaction", docs_url=None, redoc_url=None)


@app.get("/livez")
def livez() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/readyz")
def readyz() -> dict[str, str]:
    return {"status": "ready", "runtime": "presidio-redaction"}


@app.post("/v1/run")
async def run(request: RunRequest, _authorized: None = Depends(require_control)) -> dict:
    try:
        return await execute_suite(request)
    except (httpx.RequestError, RuntimeError, ValueError) as error:
        raise HTTPException(status_code=502, detail=str(error)) from error


@app.get("/v1/build-info")
def build_info(_authorized: None = Depends(require_verifier)) -> dict:
    return {
        "component": "guided-h09-presidio-redaction",
        "source_digest": source_digest(),
        "scaffold_digest": scaffold_digest(),
        "framework": "microsoft-presidio",
        "framework_version": FRAMEWORK_VERSION,
        "entities": list(policy.ENTITIES),
        "recognizer_classes": sorted(
            {type(item).__name__ for item in policy.ANALYZER.registry.recognizers}
        ),
        "recognizers": sorted(
            [
                {
                    "module": type(item).__module__,
                    "class": type(item).__name__,
                }
                for item in policy.ANALYZER.registry.recognizers
            ],
            key=lambda item: (item["module"], item["class"]),
        ),
        "case_ids": list(CASE_ORDER),
    }


@app.get("/v1/receipts/{suite_id}")
def receipt(suite_id: str, _authorized: None = Depends(require_verifier)) -> dict:
    with connect() as database:
        row = database.execute(
            "SELECT receipt_json FROM receipts WHERE suite_id=?", (suite_id,)
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="receipt not found")
    return json.loads(row["receipt_json"])
