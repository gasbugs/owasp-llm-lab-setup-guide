"""P12-only identity/authorization/lexical retrieval service with read-only receipts."""
import hashlib
import hmac
import os
from pathlib import Path
from typing import Literal
from uuid import UUID

from fastapi import FastAPI, Header, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from context_store import ContextStore, ContextError


class Document(BaseModel):
    model_config = ConfigDict(extra="forbid")
    document_id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,64}$")
    tenant: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,64}$")
    text: str = Field(min_length=1, max_length=4000)


class Register(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suite_id: UUID
    execution_ids: list[UUID] = Field(min_length=1, max_length=32)
    documents: list[Document] = Field(min_length=1, max_length=8)


class Stage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suite_id: UUID
    execution_id: UUID
    value: str = Field(min_length=1, max_length=16000, repr=False)


class Close(BaseModel):
    model_config = ConfigDict(extra="forbid")


def create_app(*, database=None, tokens=None, now=None):
    if tokens is None:
        tokens = {role: os.environ[f"GUIDED_P12_CONTEXT_{role.upper()}_TOKEN"] for role in ("control", "service", "verifier")}
    if (set(tokens) != {"control", "service", "verifier"}
            or any(not isinstance(value, str) or not value or not value.isascii() for value in tokens.values())
            or len(set(tokens.values())) != 3):
        raise ValueError("distinct service credentials required")

    def source_digest():
        digest = hashlib.sha256()
        for name in ("context_server.py", "context_store.py"):
            digest.update(name.encode())
            digest.update((Path(__file__).parent / name).read_bytes())
        return digest.hexdigest()

    built = source_digest()
    store = ContextStore(database or os.getenv("GUIDED_P12_CONTEXT_DATABASE", "/state/context.sqlite3"), built,
                         **({"now": now} if now is not None else {}))
    app = FastAPI(title="P12 synthetic context", docs_url=None, redoc_url=None, openapi_url=None)

    def require(role, authorization):
        scheme, _, token = (authorization or "").partition(" ")
        if scheme.lower() != "bearer" or not hmac.compare_digest(token.encode(), tokens[role].encode()):
            raise HTTPException(401, "invalid service credential")

    def unchanged():
        if source_digest() != built:
            raise HTTPException(503, "context execution build changed")

    @app.exception_handler(RequestValidationError)
    async def invalid_request(_request, _error):
        return JSONResponse(status_code=422, content={"detail": "invalid request fields"})

    @app.exception_handler(ContextError)
    async def context_error(_request, error):
        return JSONResponse(status_code=error.status, content={"detail": str(error)})

    @app.get("/readyz")
    def ready():
        return {"status": "ready", "component": "p12-context", "backend": "synthetic-sqlite-fts"}

    @app.get("/v1/build-info")
    def build_info(authorization: str | None = Header(default=None)):
        require("verifier", authorization)
        return {"component": "p12-context", "source_digest": built, "current_source_digest": source_digest()}

    @app.post("/v1/suites")
    def register(body: Register, authorization: str | None = Header(default=None)):
        require("control", authorization)
        unchanged()
        return store.register(str(body.suite_id), [str(value) for value in body.execution_ids],
                              [doc.model_dump() for doc in body.documents])

    @app.post("/v1/stages/{stage}")
    def execute(stage: Literal["authenticate", "authorize", "retrieval"], body: Stage,
                authorization: str | None = Header(default=None)):
        require("service", authorization)
        unchanged()
        result = store.execute(str(body.suite_id), str(body.execution_id), stage, body.value)
        unchanged()
        return result

    @app.post("/v1/suites/{suite_id}/close")
    def close(suite_id: UUID, body: Close, authorization: str | None = Header(default=None)):
        require("control", authorization)
        return store.close(str(suite_id))

    @app.get("/v1/suites/{suite_id}/ledger")
    def ledger(suite_id: UUID, authorization: str | None = Header(default=None)):
        require("verifier", authorization)
        return store.ledger(str(suite_id))

    return app
