"""Role-separated P04 lifecycle and read-only evidence API factory."""
import hmac

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from p04_invocation import InvocationError
from p04_ledger import LedgerError

UUID_PATTERN = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"


class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suite_id: str = Field(pattern=UUID_PATTERN)
    execution_id: str = Field(pattern=UUID_PATTERN)
    source_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    runner_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class InvokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suite_id: str = Field(pattern=UUID_PATTERN)
    execution_id: str = Field(pattern=UUID_PATTERN)
    operation: str
    payload: dict


class EmptyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PreparationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    operation_id: str = Field(pattern=UUID_PATTERN)


class CaseMapping(BaseModel):
    model_config = ConfigDict(extra="forbid")
    case_id: str = Field(pattern=r"^[a-z0-9_-]{1,64}$")
    execution_id: str = Field(pattern=UUID_PATTERN)


class SuiteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suite_id: str = Field(pattern=UUID_PATTERN)
    cases: list[CaseMapping] = Field(min_length=1, max_length=32)


def create_app(ledger, *, control_token, verifier_token, invocation_for,
               resolve_execution=None, suite_store=None, provision_token=None, preparation=None,
               resource_audit=None):
    if (any(not isinstance(value, str) or not value.isascii() or len(value) < 32
            for value in (control_token, verifier_token)) or control_token == verifier_token):
        raise ValueError("separate configured service credentials required")
    if provision_token is not None and (not isinstance(provision_token, str) or not provision_token.isascii()
            or len(provision_token) < 32 or provision_token in (control_token, verifier_token)):
        raise ValueError("separate provisioning credential required")
    if suite_store is not None:
        if resolve_execution is not None:
            raise ValueError("suite store owns execution resolution")
        resolve_execution = suite_store.resolve
    if not callable(resolve_execution):
        raise ValueError("registered execution resolver required")
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    def token(authorization):
        scheme, _, value = (authorization or "").partition(" ")
        if scheme.lower() != "bearer" or not value.isascii():
            raise HTTPException(401, "invalid service credential")
        return value

    def require_control(authorization: str | None = Header(default=None)):
        if not hmac.compare_digest(token(authorization), control_token):
            raise HTTPException(401, "invalid service credential")

    def require_verifier(authorization: str | None = Header(default=None)):
        if not hmac.compare_digest(token(authorization), verifier_token):
            raise HTTPException(401, "invalid service credential")

    def require_provision(authorization: str | None = Header(default=None)):
        if provision_token is None or not hmac.compare_digest(token(authorization), provision_token):
            raise HTTPException(401, "invalid service credential")

    @app.exception_handler(RequestValidationError)
    async def invalid_request(_request, _error):
        return JSONResponse(status_code=422, content={"detail": "invalid P04 request"})

    @app.exception_handler(LedgerError)
    async def ledger_error(_request, error):
        return JSONResponse(status_code=error.status, content={"detail": str(error)})

    @app.get("/readyz")
    def ready():
        return {"status": "ready", "provider_check": "not-run"}

    @app.post("/resources/prepare", dependencies=[Depends(require_provision)])
    def prepare_resources(request: PreparationRequest):
        if preparation is None:
            raise HTTPException(503, "P04 AWS preparation is unavailable")
        try:
            return preparation.prepare(request.operation_id)
        except LedgerError:
            raise
        except Exception:
            raise HTTPException(503, "P04 AWS preparation is unavailable") from None

    @app.get("/resources/preparations/{operation_id}", dependencies=[Depends(require_verifier)])
    def preparation_evidence(operation_id: str):
        if preparation is None:
            raise HTTPException(503, "P04 preparation evidence is unavailable")
        try:
            return preparation.read(operation_id)
        except LedgerError:
            raise
        except Exception:
            raise HTTPException(503, "P04 preparation evidence is unavailable") from None

    @app.post("/suites", dependencies=[Depends(require_control)])
    def prepare(request: SuiteRequest):
        if suite_store is None:
            raise HTTPException(503, "P04 suite registration is unavailable")
        try:
            return suite_store.prepare(request.suite_id, [row.model_dump() for row in request.cases])
        except LedgerError:
            raise
        except Exception:
            raise HTTPException(503, "P04 suite registration is unavailable") from None

    @app.get("/suites/{suite_id}", dependencies=[Depends(require_verifier)])
    def suite_evidence(suite_id: str):
        if suite_store is None:
            raise HTTPException(503, "P04 suite registration is unavailable")
        try:
            return suite_store.read(suite_id)
        except LedgerError:
            raise
        except Exception:
            raise HTTPException(503, "P04 suite evidence is unavailable") from None

    @app.get("/suites/{suite_id}/resources", dependencies=[Depends(require_verifier)])
    def resources_evidence(suite_id: str):
        if suite_store is None:
            raise HTTPException(503, "P04 suite registration is unavailable")
        try:
            result = suite_store.inspect(suite_id)
            if result['resources']['provider_mode'] == 'aws':
                if resource_audit is None:
                    raise LedgerError(503)
                result['aws_policy_audit'] = resource_audit(result['resources'])
            return result
        except LedgerError:
            raise
        except Exception:
            raise HTTPException(503, "P04 resource evidence is unavailable") from None

    @app.post("/executions", dependencies=[Depends(require_control)])
    def register(request: RegisterRequest):
        try:
            registered = resolve_execution(request.suite_id, request.execution_id)
            if set(registered) != {"body", "guardrail", "resource_digest", "provider_mode"}:
                raise ValueError()
        except LedgerError:
            raise
        except Exception:
            raise HTTPException(503, "P04 registered case is unavailable") from None
        grant = ledger.register(**request.model_dump(), **registered)
        return {**grant, "body": registered["body"], "guardrail": registered["guardrail"]}

    @app.post("/invoke")
    def invoke(request: InvokeRequest, authorization: str | None = Header(default=None)):
        capability = token(authorization)
        ledger.authorize(capability, request.suite_id, request.execution_id)
        # Provider resolution is trusted and follows authentication; reserve checks again.
        try:
            invocation = invocation_for(request.suite_id, request.execution_id)
        except LedgerError:
            raise
        except Exception:
            raise HTTPException(503, "P04 provider is unavailable") from None
        try:
            return invocation.invoke(capability, **request.model_dump())
        except InvocationError:
            raise HTTPException(502, "P04 provider invocation failed") from None

    @app.post("/executions/{execution_id}/close", dependencies=[Depends(require_control)])
    def close(execution_id: str, _body: EmptyRequest):
        return ledger.close(execution_id)

    @app.get("/executions/{execution_id}", dependencies=[Depends(require_verifier)])
    def evidence(execution_id: str):
        return ledger.read(execution_id)

    return app
