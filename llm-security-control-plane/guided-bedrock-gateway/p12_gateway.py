"""P12 role-bound Bedrock routes; mount only inside the credential-owning Gateway."""
import hashlib
import hmac
import json
import os
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, FastAPI, Header, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from p12_capabilities import CapabilityStore, GrantError, MODEL_ID


class Register(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suite_id: UUID
    execution_ids: list[UUID] = Field(min_length=1, max_length=32)


class Invoke(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suite_id: UUID
    execution_id: UUID
    role: Literal["input_rail", "retrieval_rail", "output_rail", "main"]
    model: str = Field(min_length=1, max_length=128)
    prompt: str = Field(min_length=1, max_length=40000)

    @field_validator("prompt")
    @classmethod
    def nonblank(cls, value):
        if not value.strip():
            raise ValueError("empty prompt")
        return value


class Close(BaseModel):
    model_config = ConfigDict(extra="forbid")


def main_input_binding(prompt):
    """Hash semantic fields from the exact outbound prompt; retain no raw text."""
    binding = {"schema_valid": False, "prompt_digest": hashlib.sha256(prompt.encode()).hexdigest()}
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON field")
            result[key] = value
        return result
    try:
        value = json.loads(prompt, object_pairs_hook=unique_object)
        if not isinstance(value, dict) or set(value) != {"question", "context"}:
            return binding
        if any(not isinstance(text, str) or not text.strip() or len(text) > 16000 for text in value.values()):
            return binding
        fields = {key + "_digest": hashlib.sha256(text.encode()).hexdigest() for key, text in value.items()}
        fields.update({key + "_bytes": len(text.encode()) for key, text in value.items()})
        return {**binding, "schema_valid": True, **fields}
    except (ValueError, TypeError, UnicodeError, RecursionError):
        return binding


def create_router(*, store: CapabilityStore, client, control_token, verifier_token, prefix="/v1/p12"):
    if (not all(isinstance(value, str) and value and value.isascii() for value in (control_token, verifier_token))
            or control_token == verifier_token):
        raise ValueError("distinct control and verifier credentials required")
    router = APIRouter(prefix=prefix)

    def bearer(authorization, expected=None):
        scheme, _, token = (authorization or "").partition(" ")
        if scheme.lower() != "bearer" or not token or (expected is not None and not hmac.compare_digest(token.encode(), expected.encode())):
            raise HTTPException(401, "invalid credential")
        return token

    def convert(error):
        return HTTPException(error.status, str(error))

    @router.post("/suites")
    def register(body: Register, authorization: str | None = Header(default=None)):
        bearer(authorization, control_token)
        try:
            return store.issue(str(body.suite_id), [str(value) for value in body.execution_ids])
        except GrantError as error:
            raise convert(error) from None

    @router.post("/invoke")
    def invoke(body: Invoke, authorization: str | None = Header(default=None)):
        token = bearer(authorization)
        max_tokens = 128 if body.role == "main" else 3
        request = {"modelId": MODEL_ID, "messages": [{"role": "user", "content": [{"text": body.prompt}]}],
                   "inferenceConfig": {"maxTokens": max_tokens, "temperature": 0.0}}
        request_digest = hashlib.sha256(json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        try:
            store.reserve(token, suite_id=str(body.suite_id), execution_id=str(body.execution_id),
                          role=body.role, model=body.model, request_digest=request_digest)
        except GrantError as error:
            raise convert(error) from None
        try:
            raw = client.converse(**request)
            message = raw["output"]["message"]
            parts = message["content"]
            if (message["role"] != "assistant" or not isinstance(parts, list) or not parts
                    or any(not isinstance(part, dict) or set(part) != {"text"} or not isinstance(part["text"], str) for part in parts)):
                raise ValueError("invalid provider message")
            provider = {"provider_request_id": raw["ResponseMetadata"]["RequestId"],
                        "text": "".join(part["text"] for part in parts), "usage": raw["usage"],
                        "stop_reason": raw["stopReason"]}
            if body.role == "main":
                provider["main_input"] = main_input_binding(request["messages"][0]["content"][0]["text"])
            evidence = store.complete(token, provider)
        except Exception:
            store.fail(token)
            raise HTTPException(502, "provider call or evidence failed") from None
        return {"suite_id": str(body.suite_id), "execution_id": str(body.execution_id),
                "role": body.role, "model": body.model, "request_digest": request_digest,
                "text": provider["text"], "evidence": evidence}

    @router.post("/suites/{suite_id}/close")
    def close(suite_id: UUID, body: Close, authorization: str | None = Header(default=None)):
        bearer(authorization, control_token)
        try:
            return store.close(str(suite_id))
        except GrantError as error:
            raise convert(error) from None

    @router.get("/suites/{suite_id}/ledger")
    def ledger(suite_id: UUID, authorization: str | None = Header(default=None)):
        bearer(authorization, verifier_token)
        try:
            return store.ledger(str(suite_id))
        except GrantError as error:
            raise convert(error) from None

    return router


def create_app(**dependencies):
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(_request, _error):
        return JSONResponse(status_code=422, content={"detail": "invalid request fields"})

    app.include_router(create_router(**dependencies))
    return app


class BedrockClient:
    def converse(self, **request):
        import boto3
        from botocore.config import Config
        client = boto3.client("bedrock-runtime", region_name=os.getenv("AWS_REGION", "us-east-1"),
                             config=Config(connect_timeout=5, read_timeout=55,
                                           retries={"total_max_attempts": 1}))
        try:
            return client.converse(**request)
        finally:
            client.close()


def configured_app():
    control = os.getenv("GUIDED_P12_GATEWAY_CONTROL_TOKEN")
    verifier = os.getenv("GUIDED_P12_GATEWAY_VERIFIER_TOKEN")
    if not control or not verifier or os.getenv("GUIDED_PROVIDER_MODE", "aws") != "aws":
        unavailable = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

        @unavailable.api_route("/{path:path}", methods=["GET", "POST"])
        def not_configured(path: str):
            raise HTTPException(503, "P12 AWS Gateway is not configured")

        return unavailable
    store = CapabilityStore(os.getenv("GUIDED_P12_GATEWAY_DATABASE", "/state/p12-gateway.sqlite3"))
    return create_app(store=store, client=BedrockClient(), control_token=control,
                      verifier_token=verifier, prefix="")
