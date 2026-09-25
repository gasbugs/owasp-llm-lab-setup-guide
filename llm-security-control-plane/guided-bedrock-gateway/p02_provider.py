"""Bounded P02 SDK adapter. Clients, bucket and lifecycle credentials are server-owned."""
import hashlib
import json
import math

from p02_ledger import LedgerError

MODEL = "amazon.titan-embed-text-v2:0"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def request_id(response):
    value = response.get("ResponseMetadata", {}).get("RequestId")
    if not isinstance(value, str) or not value or len(value) > 256:
        raise ValueError("missing provider identity")
    return value


class DocumentProvider:
    def __init__(self, ledger, s3, runtime, bucket, *, provider_mode="aws"):
        if not isinstance(bucket, str) or not bucket:
            raise ValueError("a server-owned bucket is required")
        if provider_mode not in {"aws", "contract"}:
            raise ValueError("explicit provider mode required")
        self.ledger, self.s3, self.runtime, self.bucket = ledger, s3, runtime, bucket
        self.provider_mode = provider_mode

    def invoke(self, token, suite_id, execution_id, operation, payload):
        try:
            raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, allow_nan=False).encode()
            if len(raw) > 32768:
                raise ValueError()
        except (TypeError, ValueError):
            raise LedgerError(422) from None
        self.ledger.reserve(token, suite_id, execution_id, operation, sha(raw))
        try:
            if operation == "store_source":
                result = self._store(execution_id, payload)
            else:
                result = self._embed(payload)
            self.ledger.finish(execution_id, operation, result)
            return result
        except Exception:
            # An SDK failure may already have a remote effect. Preserve the attempt, not zero calls.
            self.ledger.finish(execution_id, operation)
            raise LedgerError(502) from None

    def _store(self, execution_id, payload):
        if not isinstance(payload, dict) or set(payload) != {"key", "content"}:
            raise ValueError()
        key, content = payload["key"], payload["content"]
        if key != f"h02/knowledge/{execution_id}.md" or not isinstance(content, str) or not content:
            raise ValueError()
        raw = content.encode("utf-8")
        result = self.s3.put_object(Bucket=self.bucket, Key=key, Body=raw,
                                    ContentType="text/markdown; charset=utf-8",
                                    Metadata={"course": "tenant-03", "activity": "h02"})
        return {"provider_mode": self.provider_mode, "provider_request_id": request_id(result), "object_key": key,
                "object_uri": f"s3://{self.bucket}/{key}", "source_digest": sha(raw),
                "source_bytes": len(raw)}

    def _embed(self, payload):
        if not isinstance(payload, dict) or set(payload) != {"text"}:
            raise ValueError()
        text = payload["text"]
        if not isinstance(text, str) or not 1 <= len(text) <= 4000:
            raise ValueError()
        arguments = {"inputText": text, "dimensions": 1024, "normalize": True}
        result = self.runtime.invoke_model(modelId=MODEL, contentType="application/json",
                                           accept="application/json", body=json.dumps(arguments))
        stream = result["body"]
        try:
            raw = stream.read(131073)
        finally:
            stream.close()
        if len(raw) > 131072:
            raise ValueError()
        body = json.loads(raw)
        vector, count = body["embedding"], body["inputTextTokenCount"]
        if (not isinstance(vector, list) or len(vector) != 1024
                or any(type(v) not in (int, float) or not math.isfinite(v) for v in vector)
                or type(count) is not int or count < 1):
            raise ValueError()
        norm = math.sqrt(sum(v * v for v in vector))
        if not math.isfinite(norm) or norm <= 0:
            raise ValueError()
        return {"provider_mode": self.provider_mode, "provider_request_id": request_id(result), "model_id": MODEL,
                "input_digest": sha(text.encode()), "input_token_count": count,
                "embedding_dimension": len(vector), "embedding_norm": norm,
                "vector_digest": sha(json.dumps(vector, separators=(",", ":"), allow_nan=False).encode())}

    def source_evidence(self, execution_id):
        receipt = self.ledger.read(execution_id)
        stored = next((call for call in receipt["calls"] if call["operation"] == "store_source"), None)
        if stored is None or stored["state"] != "complete":
            raise LedgerError(409)
        key = f"h02/knowledge/{execution_id}.md"
        try:
            result = self.s3.get_object(Bucket=self.bucket, Key=key)
            stream = result["Body"]
            try:
                raw = stream.read(32769)
            finally:
                stream.close()
            if len(raw) > 32768:
                raise ValueError()
            return {"provider_mode": self.provider_mode, "provider_request_id": request_id(result), "object_key": key,
                    "source_digest": sha(raw), "source_bytes": len(raw)}
        except Exception:
            raise LedgerError(502) from None
