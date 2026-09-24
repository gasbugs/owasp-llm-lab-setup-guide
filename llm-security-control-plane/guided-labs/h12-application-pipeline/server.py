"""H12 learner-owned Application orchestration service."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import httpx
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from pipeline import may_continue, stage_order


ROOT = Path(__file__).parent
CONTROL_TOKEN = os.environ["GUIDED_CONTROL_LAB12_TOKEN"]
VERIFIER_TOKEN = os.environ["GUIDED_VERIFIER_LAB12_TOKEN"]
PROVIDER_URL = os.environ["GUIDED_H12_PROVIDER_URL"].rstrip("/")
SERVICE_TOKEN = os.environ["GUIDED_H12_SERVICE_TOKEN"]
DATABASE_PATH = Path(os.getenv("GUIDED_H12_DATABASE", "/state/receipts.sqlite3"))
CASE_IDS = ("normal", "invalid-token", "indirect-injection", "nemo-timeout")
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


app = FastAPI(title="Tenant 03 H12 Application Pipeline", docs_url=None, redoc_url=None)


@app.get("/livez")
def livez() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/readyz")
def readyz() -> dict[str, str]:
    return {"status": "ready"}


@app.post("/v1/run")
async def run(request: RunRequest, authorization: str | None = Header(default=None)) -> dict:
    require(CONTROL_TOKEN, authorization)
    order = stage_order()
    if set(order) != {"authenticate", "authorize", "input_privacy", "input_rail", "retrieval", "main", "output_rail", "output_privacy"} or len(order) != 8:
        raise HTTPException(status_code=422, detail="pipeline stage set is invalid")
    results = []
    async with httpx.AsyncClient(timeout=10.0) as client:
        for case_id in CASE_IDS:
            calls = []
            for stage in order:
                response = await client.post(
                    f"{PROVIDER_URL}/v1/stages/{stage}",
                    json={"suite_id": request.suite_id, "case_id": case_id},
                    headers={"Authorization": f"Bearer {SERVICE_TOKEN}"},
                )
                calls.append({"stage": stage, "status": response.status_code})
                if not may_continue(response.status_code):
                    break
            results.append({"case_id": case_id, "calls": calls})
    receipt = {
        "suite_id": request.suite_id,
        "started_at": request.started_at,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "source_digest": digest_files((ROOT / "Containerfile", ROOT / "pipeline.py", ROOT / "server.py")),
        "scaffold_digest": digest_files((ROOT / "Containerfile", ROOT / "server.py")),
        "policy_digest": digest_files((ROOT / "pipeline.py",)),
        "declared_stage_order": list(order),
        "cases": results,
    }
    with connect() as database:
        database.execute("INSERT INTO receipts VALUES(?,?)", (request.suite_id, json.dumps(receipt, ensure_ascii=False)))
    return {"suite_id": request.suite_id, "source_digest": receipt["source_digest"]}


@app.get("/v1/build-info")
def build_info(authorization: str | None = Header(default=None)) -> dict:
    require(VERIFIER_TOKEN, authorization)
    return {
        "component": "guided-h12-application-pipeline",
        "source_digest": digest_files((ROOT / "Containerfile", ROOT / "pipeline.py", ROOT / "server.py")),
        "scaffold_digest": digest_files((ROOT / "Containerfile", ROOT / "server.py")),
        "policy_digest": digest_files((ROOT / "pipeline.py",)),
        "case_ids": list(CASE_IDS),
    }


@app.get("/v1/receipts/{suite_id}")
def receipt(suite_id: str, authorization: str | None = Header(default=None)) -> dict:
    require(VERIFIER_TOKEN, authorization)
    with connect() as database:
        row = database.execute("SELECT receipt_json FROM receipts WHERE suite_id=?", (suite_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="receipt not found")
    return json.loads(row["receipt_json"])
