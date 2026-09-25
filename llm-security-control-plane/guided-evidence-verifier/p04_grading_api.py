"""P04 grading accepts a suite ID only; never caller-supplied proof or verdicts."""
import hmac
import threading
from uuid import UUID

from fastapi import FastAPI, Header, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict


class Verify(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suite_id: UUID


def grade_run(verification, suite, *, expected_cases):
    try:
        result = verification.collect(suite)
        completed = (len(expected_cases) == 27 and len(set(expected_cases)) == 27
            and result["suite_contract_verified"] is True and result["suite_id"] == suite
            and result["provider_mode"] in ("aws", "contract")
            and tuple(row["case_id"] for row in result["cases"]) == expected_cases
            and all(row["binding"]["execution_verified"] is True for row in result["cases"])
            and sum(row["product"] is not None and row["product"].get("product_result_verified") is True
                    for row in result["cases"]) == 4)
        if not completed:
            raise ValueError("incomplete evidence")
    except Exception:
        result = {"suite_contract_verified": False, "cases": []}
        completed = False
    return {**result, "practice_id": "P04", "activity_id": "H04", "contract_version": "p04-guardrail-v1",
            "suite_id": suite, "task_completed": completed, "security_verdict": "PASS" if completed else "ERR"}


def validate_roles(verification, control_token):
    credentials = (control_token, verification.app_token, verification.gateway_token)
    if (any(not isinstance(value, str) or not value.isascii() or len(value) < 32 for value in credentials)
            or control_token in credentials[1:]):
        raise ValueError("separate control and read-only credentials required")


def create_app(verification, *, control_token):
    validate_roles(verification, control_token)
    expected = tuple(case["case_id"] for case in verification.cases)
    if len(expected) != 27 or len(set(expected)) != 27:
        raise ValueError("complete server-owned P04 contract required")
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    lock = threading.Lock()

    @app.exception_handler(RequestValidationError)
    async def invalid(_request, _error):
        return JSONResponse(status_code=422, content={"detail": "invalid P04 verification fields"})

    @app.get("/readyz")
    def ready():
        return {"status": "ready", "component": "p04-verifier", "provider_check": "not-run"}

    @app.post("/v1/verify/p04")
    def verify(body: Verify, authorization: str | None = Header(default=None)):
        scheme, _, token = (authorization or "").partition(" ")
        if scheme.lower() != "bearer" or not token.isascii() or not hmac.compare_digest(token, control_token):
            raise HTTPException(401, "invalid verifier caller")
        if not lock.acquire(blocking=False):
            raise HTTPException(409, "P04 verification already running")
        try:
            return grade_run(verification, str(body.suite_id), expected_cases=expected)
        finally:
            lock.release()

    return app
