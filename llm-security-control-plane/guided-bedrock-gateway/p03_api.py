"""P03 lifecycle, invocation and read-only evidence HTTP boundary."""
import hmac
import hashlib
import json
from typing import Literal
from uuid import UUID

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from p03_ledger import LedgerError


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
    operation: Literal["job_status", "retrieve"]
    payload: dict


class Empty(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ExecutionMapping(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    case_id: str = Field(min_length=1, max_length=64)
    execution_id: str


class Preparation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    suite_id: str
    executions: list[ExecutionMapping] = Field(min_length=1, max_length=32)


class ResourcePreparation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    operation_id: str


def create_app(ledger, provider_factory, *, control_token, verifier_token, job_resolver,
               suite_preparer=None, suite_reader=None, suite_resources=None,
               provision_token=None, resource_preparer=None, preparation_reader=None):
    if (any(not isinstance(token, str) or not token or not token.isascii() for token in (control_token, verifier_token))
            or control_token == verifier_token):
        raise ValueError("distinct server credentials required")
    if provision_token is not None and (
            not isinstance(provision_token, str) or not provision_token or not provision_token.isascii()
            or provision_token in {control_token, verifier_token}):
        raise ValueError("distinct preparation credential required")
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

    def provisioner(authorization: str | None = Header(default=None)):
        if provision_token is None or not hmac.compare_digest(token(authorization), provision_token):
            raise HTTPException(401, "invalid service credential")

    @app.exception_handler(LedgerError)
    async def ledger_error(_request, error):
        return JSONResponse(status_code=error.status, content={"detail": "P03 execution evidence unavailable"})

    @app.post("/resources/prepare", dependencies=[Depends(provisioner)])
    def prepare_resources(body: ResourcePreparation):
        try:
            if str(UUID(body.operation_id)) != body.operation_id:
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            raise HTTPException(422, "invalid preparation identifier") from None
        if resource_preparer is None:
            raise HTTPException(503, "P03 AWS preparation unavailable")
        return resource_preparer(body.operation_id)

    @app.get("/preparations/{operation_id}", dependencies=[Depends(verifier)])
    def read_preparation(operation_id: str):
        if preparation_reader is None:
            raise HTTPException(503, "P03 preparation evidence unavailable")
        return preparation_reader(operation_id)

    @app.post("/executions", dependencies=[Depends(control)])
    def register(body: Registration):
        current_job_id = job_resolver(body.suite_id, body.execution_id)
        return ledger.register(**body.model_dump(), current_job_id=current_job_id)

    @app.post("/suites", dependencies=[Depends(control)])
    def prepare(body: Preparation):
        if suite_preparer is None:
            raise HTTPException(503, "P03 suite preparation unavailable")
        from p03_ledger import identifier
        identifier(body.suite_id)
        rows = [row.model_dump() for row in body.executions]
        for row in rows:
            identifier(row["execution_id"])
        if (len({row["execution_id"] for row in rows}) != len(rows)
                or len({row["case_id"] for row in rows}) != len(rows)):
            raise HTTPException(422, "duplicate execution mapping")
        suite_preparer(body.suite_id, rows)
        return {"suite_id": body.suite_id, "contract_version": "p03-search-v1", "prepared": True,
                "mapping_digest": hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()}

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

    @app.get("/suites/{suite_id}", dependencies=[Depends(verifier)])
    def read_suite(suite_id: str):
        if suite_reader is None:
            raise HTTPException(503, "P03 suite evidence unavailable")
        return suite_reader(suite_id)

    @app.get("/suites/{suite_id}/resources", dependencies=[Depends(verifier)])
    def inspect_suite_resources(suite_id: str):
        if suite_resources is None:
            raise HTTPException(503, "P03 resource evidence unavailable")
        return suite_resources(suite_id)

    return app
