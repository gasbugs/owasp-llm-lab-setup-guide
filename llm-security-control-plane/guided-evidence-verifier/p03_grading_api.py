"""P03 grading boundary: only a suite ID enters; all proof is collected afresh."""
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


def validate_roles(verification, control_token):
    credentials = (control_token, verification.app_token, verification.gateway_token)
    if (any(not isinstance(value, str) or not value or not value.isascii() for value in credentials)
            or control_token in credentials[1:]):
        raise ValueError("separate control and read-only credentials required")


def grade_run(verification, suite, *, expected_cases=None):
    try:
        expected = (tuple(case["case_id"] for case in verification.cases)
                    if expected_cases is None else expected_cases)
        if not expected or len(set(expected)) != len(expected):
            raise ValueError("closed server-owned case list required")
        result = verification.collect(suite)
        completed = (result.get("case_contract_verified") is True
                     and result.get("provider_mode") in {"aws", "contract"}
                     and result.get("root", {}).get("suite_id") == suite
                     and tuple(case["case_id"] for case in result["cases"]) == expected
                     and all(case.get("case_verified") is True for case in result["cases"]))
        if not completed:
            raise ValueError("incomplete evidence")
    except Exception:
        result = {"case_contract_verified": False, "cases": []}
        completed = False
    return {**result, "practice_id": "P03", "activity_id": "H03", "contract_version": "p03-search-v1",
            "suite_id": suite, "task_completed": completed,
            "security_verdict": "PASS" if completed else "ERR"}


def create_app(verification, *, control_token):
    validate_roles(verification, control_token)
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    lock = threading.Lock()
    expected_cases = tuple(case["case_id"] for case in verification.cases)
    if not expected_cases or len(set(expected_cases)) != len(expected_cases):
        raise ValueError("closed server-owned case list required")

    @app.exception_handler(RequestValidationError)
    async def invalid(_request, _error):
        return JSONResponse(status_code=422, content={"detail": "invalid verification fields"})

    @app.get("/readyz")
    def ready():
        return {"status": "ready", "component": "p03-verifier", "provider_check": "not-run"}

    @app.post("/v1/verify/p03")
    def verify(body: Verify, authorization: str | None = Header(default=None)):
        scheme, _, token = (authorization or "").partition(" ")
        if scheme.lower() != "bearer" or not token.isascii() or not hmac.compare_digest(token, control_token):
            raise HTTPException(401, "invalid verifier caller")
        if not lock.acquire(blocking=False):
            raise HTTPException(409, "P03 verification already running")
        suite = str(body.suite_id)
        try:
            return grade_run(verification, suite, expected_cases=expected_cases)
        finally:
            lock.release()

    return app
