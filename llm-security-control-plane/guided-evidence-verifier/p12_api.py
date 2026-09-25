"""P12 HTTP boundary: caller supplies only an execution ID, never grading inputs."""
import asyncio
from copy import deepcopy
import hmac
from uuid import UUID

from fastapi import FastAPI, Header, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

from p12_grading import grade_run


class Verify(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suite_id: UUID


def create_app(*, control_token, origin, token, origins, tokens, specifications, documents, scaffold_files):
    credentials = [control_token, token, *tokens.values()]
    if (any(not isinstance(value, str) or not value or not value.isascii() for value in credentials)
            or control_token in credentials[1:]):
        raise ValueError("distinct control and read-only verifier credentials required")
    config = deepcopy({"origin": origin, "token": token, "origins": origins, "tokens": tokens,
                       "specifications": specifications, "documents": documents, "scaffold_files": scaffold_files})
    app = FastAPI(title="P12 evidence verifier", docs_url=None, redoc_url=None, openapi_url=None)
    lock = asyncio.Lock()

    @app.exception_handler(RequestValidationError)
    async def invalid(_request, _exc):
        return JSONResponse(status_code=422, content={"detail": "invalid verification fields"})

    @app.get("/readyz")
    async def ready():
        return {"status": "ready", "component": "p12-verifier"}

    @app.post("/v1/verify/p12")
    async def verify(body: Verify, authorization: str | None = Header(default=None)):
        scheme, _, credential = (authorization or "").partition(" ")
        if scheme.lower() != "bearer" or not hmac.compare_digest(credential.encode(), control_token.encode()):
            raise HTTPException(401, "invalid verifier caller")
        if lock.locked():
            raise HTTPException(409, "P12 verification is already running")
        async with lock:
            return await grade_run(suite_id=str(body.suite_id), **config)

    return app
