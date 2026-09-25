"""P02 lifecycle, invocation and read-only evidence HTTP boundary."""
import hmac
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from p02_ledger import LedgerError


class Registration(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    suite_id: str
    execution_id: str
    source_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    runner_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class Invocation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    suite_id: str
    execution_id: str
    operation: Literal["store_source", "embed"]
    payload: dict


class Empty(BaseModel):
    model_config = ConfigDict(extra="forbid")


def create_app(ledger, provider_factory, *, control_token, verifier_token, resource_reader=None):
    if (any(not isinstance(token, str) or not token or not token.isascii() for token in (control_token, verifier_token))
            or control_token == verifier_token):
        raise ValueError("distinct server credentials required")
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    def token(authorization):
        scheme, _, value = (authorization or "").partition(" ")
        if scheme.lower() != "bearer" or not value.isascii():
            raise HTTPException(401, "invalid service credential")
        return value

    def control(authorization: str | None = Header(default=None)):
        if not hmac.compare_digest(token(authorization), control_token):
            raise HTTPException(401, "invalid service credential")

    def verifier(authorization: str | None = Header(default=None)):
        if not hmac.compare_digest(token(authorization), verifier_token):
            raise HTTPException(401, "invalid service credential")

    @app.exception_handler(LedgerError)
    async def ledger_error(_request, error):
        return JSONResponse(status_code=error.status, content={"detail": "P02 execution evidence unavailable"})

    @app.post("/executions", dependencies=[Depends(control)])
    def register(body: Registration):
        return ledger.register(**body.model_dump())

    @app.post("/executions/{execution_id}/close", dependencies=[Depends(control)])
    def close(execution_id: str, _body: Empty):
        return ledger.close(execution_id)

    @app.post("/invoke")
    def invoke(body: Invocation, authorization: str | None = Header(default=None)):
        credential = token(authorization)
        # Factory must only resolve the configured resource; it must never provision.
        response = provider_factory().invoke(credential, **body.model_dump())
        return {"suite_id": body.suite_id, "execution_id": body.execution_id,
                "operation": body.operation, "response": response}

    @app.get("/executions/{execution_id}", dependencies=[Depends(verifier)])
    def read(execution_id: str):
        return ledger.read(execution_id)

    @app.get("/executions/{execution_id}/source", dependencies=[Depends(verifier)])
    def source(execution_id: str):
        return provider_factory().source_evidence(execution_id)

    @app.get("/resources", dependencies=[Depends(verifier)])
    def resources():
        if resource_reader is None:
            raise HTTPException(503, "P02 resource evidence unavailable")
        return resource_reader()

    return app
