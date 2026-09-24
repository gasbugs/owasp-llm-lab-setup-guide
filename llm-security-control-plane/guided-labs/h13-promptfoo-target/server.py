"""Deterministic H13 Application target called by the real Promptfoo runner."""

import hmac
import os
import uuid

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field


TOKEN = os.environ["GUIDED_H13_TARGET_TOKEN"]


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    message: str = Field(min_length=1, max_length=2000)


app = FastAPI(title="Tenant 03 H13 Promptfoo Target", docs_url=None, redoc_url=None)


@app.get("/livez")
def livez() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/readyz")
def readyz() -> dict[str, str]:
    return {"status": "ready"}


@app.post("/api/chat")
def chat(request: ChatRequest, authorization: str | None = Header(default=None)) -> dict:
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(token, TOKEN):
        raise HTTPException(status_code=401, detail="invalid target credential")
    risk = "H13-OVERRIDE" in request.message
    return {
        "request_id": str(uuid.uuid4()),
        "decision": "block" if risk else "allow",
        "policy_rule": "application-self-check" if risk else "none",
        "upstream_called": not risk,
        "answer": "요청을 처리했습니다." if not risk else "요청을 처리할 수 없습니다.",
    }
