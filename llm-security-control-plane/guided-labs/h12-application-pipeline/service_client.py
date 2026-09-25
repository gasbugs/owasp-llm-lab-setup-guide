"""Provided P12 HTTP transport, not the learner's orchestration or course grader."""
from copy import deepcopy
import asyncio
import hashlib
import json
import re
import time
from urllib.parse import urlsplit
from uuid import UUID

import httpx

MODEL = "us.amazon.nova-lite-v1:0"
RAILS = {"input_rail", "retrieval_rail", "output_rail"}
PRIVACY = {"input_privacy", "output_privacy"}
CALL_TIMEOUT = 95


class ServiceError(RuntimeError):
    """Service/transport/evidence failure, never a normal policy denial."""


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def is_digest(value):
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def text_value(value, maximum):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValueError("nonempty bounded text required")


class ServiceClient:
    def __init__(self, *, suite_id, execution_id, origins, tokens, capabilities, transport=None):
        self.suite_id, self.execution_id = str(UUID(suite_id)), str(UUID(execution_id))
        context = {"context"} if "context" in origins else set()
        if set(origins) != {"privacy", "nemo", "gateway"} | context or set(tokens) != {"privacy", "nemo"} | context:
            raise ValueError("dedicated P12 service configuration required")
        for origin in origins.values():
            parsed = urlsplit(origin)
            if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username
                    or parsed.password or parsed.query or parsed.fragment or parsed.path not in {"", "/"}):
                raise ValueError("invalid service origin")
        if set(capabilities) != RAILS | {"main"}:
            raise ValueError("all role capabilities required")
        for token in (*tokens.values(), *capabilities.values()):
            if not isinstance(token, str) or not token or not token.isascii():
                raise ValueError("invalid service credential")
        if any(not 40 <= len(value) <= 256 for value in capabilities.values()):
            raise ValueError("invalid role capability")
        self._origins = {key: value.rstrip("/") for key, value in origins.items()}
        self._tokens, self._capabilities = dict(tokens), dict(capabilities)
        self._transport = transport
        self._calls = []

    @property
    def calls(self):
        return deepcopy(self._calls)

    async def _call(self, stage, service, path, text, payload, bearer, validate):
        if any(call["stage"] == stage for call in self._calls):
            raise ServiceError("P12 stage already attempted")
        entry = {"sequence": len(self._calls) + 1, "stage": stage, "started_at": time.time(),
                 "finished_at": None, "state": "pending", "input_digest": digest(text)}
        self._calls.append(entry)
        try:
            async with asyncio.timeout(CALL_TIMEOUT), httpx.AsyncClient(timeout=95, follow_redirects=False, trust_env=False,
                                         transport=self._transport) as client:
                async with client.stream("POST", self._origins[service] + path,
                                         json={"suite_id": self.suite_id, "execution_id": self.execution_id, **payload},
                                         headers={"Authorization": "Bearer " + bearer}) as response:
                    entry["http_status"] = response.status_code
                    if response.status_code != 200:
                        raise ValueError("service HTTP failure")
                    raw = bytearray()
                    async for part in response.aiter_bytes():
                        raw.extend(part)
                        if len(raw) > 131072:
                            raise ValueError("oversized service response")
            result = json.loads(raw)
            if result["suite_id"] != self.suite_id or result["execution_id"] != self.execution_id:
                raise ValueError("execution binding mismatch")
            value, evidence = validate(result)
            entry.update(state="completed", evidence=evidence)
            if isinstance(value, str):
                entry["output_digest"] = digest(value)
            else:
                entry["allowed"] = value
            return value
        except asyncio.CancelledError:
            entry["state"] = "interrupted"
            raise
        except Exception:
            entry["state"] = "error"
            raise ServiceError("P12 service call or evidence failed") from None
        finally:
            entry["finished_at"] = time.time()

    async def privacy(self, stage, text):
        if stage not in PRIVACY:
            raise ValueError("invalid privacy stage")
        text_value(text, 16000)

        def validate(result):
            value, evidence = result["text"], result["evidence"]
            text_value(value, 16000)
            counts = evidence["entity_counts"]
            if (evidence["stage"] != stage or evidence["input_digest"] != digest(text)
                    or evidence["output_digest"] != digest(value)
                    or evidence["input_bytes"] != len(text.encode()) or evidence["output_bytes"] != len(value.encode())
                    or evidence["framework"] != "microsoft-presidio" or evidence["operator"] != "replace"
                    or evidence["versions"] != {"presidio-analyzer": "2.2.362", "presidio-anonymizer": "2.2.362"}
                    or not is_digest(evidence["service_digest"]) or not isinstance(counts, dict)
                    or set(counts) - {"EMAIL_ADDRESS", "KR_RRN"}
                    or any(type(count) is not int or count < 1 for count in counts.values())):
                raise ValueError("invalid privacy evidence")
            return value, {key: deepcopy(evidence[key]) for key in (
                "stage", "input_digest", "output_digest", "input_bytes", "output_bytes", "framework",
                "operator", "versions", "service_digest", "entity_counts")}

        return await self._call(stage, "privacy", "/v1/process", text, {"stage": stage, "text": text},
                                self._tokens["privacy"], validate)

    async def rail(self, stage, text):
        if stage not in RAILS:
            raise ValueError("invalid rail stage")
        text_value(text, 16000)

        def validate(result):
            allowed, evidence = result["allowed"], result["evidence"]
            gateway = evidence["gateway"]
            if (type(allowed) is not bool or evidence["stage"] != stage
                    or evidence["input_digest"] != digest(text) or evidence["version"] != "0.22.0"
                    or evidence["classifier_answer"] not in {"Yes", "No"}
                    or allowed != (evidence["classifier_answer"] == "No")
                    or evidence["native_stop"] is not (not allowed)
                    or not is_digest(evidence["service_digest"])
                    or gateway["capability_digest"] != digest(self._capabilities[stage])
                    or not is_digest(gateway["request_digest"])
                    or gateway["response_digest"] != digest(evidence["classifier_answer"])
                    or not isinstance(gateway["provider_request_id"], str) or not gateway["provider_request_id"]):
                raise ValueError("invalid rail evidence")
            return allowed, {"stage": stage, "input_digest": evidence["input_digest"],
                             "version": evidence["version"], "classifier_answer": evidence["classifier_answer"],
                             "native_stop": evidence["native_stop"], "service_digest": evidence["service_digest"],
                             "gateway": {key: gateway[key] for key in (
                                 "provider_request_id", "request_digest", "response_digest", "capability_digest")}}

        return await self._call(stage, "nemo", "/v1/process", text,
                                {"stage": stage, "text": text, "capability": self._capabilities[stage]},
                                self._tokens["nemo"], validate)

    async def main(self, prompt):
        text_value(prompt, 40000)
        def unique_object(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError("duplicate Main field")
                value[key] = item
            return value
        try:
            value = json.loads(prompt, object_pairs_hook=unique_object)
            if (isinstance(value, dict) and set(value) == {"question", "context"}
                    and all(isinstance(item, str) and item.strip() and len(item) <= 16000 for item in value.values())):
                prompt = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        except (ValueError, TypeError, RecursionError):
            pass  # Invalid contracts remain invalid; do not repair or invent fields.
        model = MODEL + "#p12-main"
        request = {"modelId": MODEL, "messages": [{"role": "user", "content": [{"text": prompt}]}],
                   "inferenceConfig": {"maxTokens": 128, "temperature": 0.0}}
        request_digest = digest(json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=False))

        def validate(result):
            text, evidence = result["text"], result["evidence"]
            text_value(text, 16000)
            if (result["role"] != "main" or result["model"] != model or result["request_digest"] != request_digest
                    or evidence["actual_model_id"] != MODEL or evidence["response_digest"] != digest(text)
                    or evidence["response_bytes"] != len(text.encode())
                    or not isinstance(evidence["provider_request_id"], str) or not evidence["provider_request_id"]):
                raise ValueError("invalid Main evidence")
            return text, {"provider_request_id": evidence["provider_request_id"], "actual_model_id": MODEL,
                          "request_digest": request_digest, "response_digest": digest(text),
                          "response_bytes": len(text.encode()), "capability_digest": digest(self._capabilities["main"])}

        return await self._call("main", "gateway", "/v1/p12/invoke", prompt,
                                {"role": "main", "model": model, "prompt": prompt},
                                self._capabilities["main"], validate)

    async def _context(self, stage, value):
        if "context" not in self._origins:
            raise ValueError("P12 Context service is not configured")
        text_value(value, 256 if stage == "authenticate" else 16000)
        if stage == "authorize" and not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", value):
            raise ValueError("invalid tenant identifier")

        def validate(result):
            evidence = result["evidence"]
            if (evidence["stage"] != stage or evidence["input_digest"] != digest(value)
                    or evidence["backend"] != "synthetic-sqlite-fts" or not is_digest(evidence["service_digest"])):
                raise ValueError("invalid Context binding")
            projected = {key: evidence[key] for key in ("stage", "input_digest", "backend", "service_digest")}
            if stage in {"authenticate", "authorize"}:
                allowed = result["allowed"]
                field = "authenticated" if stage == "authenticate" else "authorized"
                if type(allowed) is not bool or evidence[field] is not allowed or evidence["subject"] not in {None, "reader", "visitor"}:
                    raise ValueError("invalid identity evidence")
                if stage == "authenticate":
                    if allowed != (evidence["subject"] is not None):
                        raise ValueError("inconsistent authentication")
                elif (evidence["requested_tenant"] != value or evidence["required_scope"] != "knowledge:read"
                      or (allowed and (evidence["subject"] != "reader" or value != "team-a"))):
                    raise ValueError("invalid authorization evidence")
                keys = (field, "subject") if stage == "authenticate" else (field, "subject", "requested_tenant", "required_scope")
                return allowed, {**projected, **{key: evidence[key] for key in keys}}
            text, hits = result["text"], evidence["hits"]
            if (not isinstance(text, str) or len(text) > 16000
                    or evidence["output_digest"] != digest(text) or evidence["output_bytes"] != len(text.encode())
                    or evidence["authorized_tenant"] != "team-a" or type(evidence["query_executed"]) is not bool
                    or not isinstance(hits, list) or len(hits) > 3):
                raise ValueError("invalid retrieval evidence")
            identifiers = []
            for hit in hits:
                identifier = hit["document_id"]
                if (not isinstance(identifier, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", identifier)
                        or hit["tenant"] != "team-a" or not is_digest(hit["text_digest"])):
                    raise ValueError("invalid retrieval hit")
                identifiers.append(identifier)
            if (len(set(identifiers)) != len(identifiers) or bool(text) != bool(hits)
                    or (hits and not evidence["query_executed"])):
                raise ValueError("inconsistent retrieval results")
            return text, {**projected, **{key: evidence[key] for key in (
                "authorized_tenant", "query_executed", "output_digest", "output_bytes")},
                "hits": [{key: hit[key] for key in ("document_id", "tenant", "text_digest")} for hit in hits]}

        return await self._call(stage, "context", "/v1/stages/" + stage, value, {"value": value},
                                self._tokens["context"], validate)

    async def authenticate(self, credential):
        return await self._context("authenticate", credential)

    async def authorize(self, tenant):
        return await self._context("authorize", tenant)

    async def retrieve(self, query):
        return await self._context("retrieval", query)
