"""The proxy rejects malformed privacy evidence before another security stage runs."""

import asyncio
import os
from types import SimpleNamespace

os.environ.setdefault("PROXY_CALLER_TOKEN", "c" * 64)
os.environ.setdefault("PROXY_ADMIN_TOKEN", "a" * 64)
os.environ.setdefault("PROXY_GATEWAY_TOKEN", "g" * 64)
os.environ.setdefault("PROXY_PRIVACY_TOKEN", "p" * 64)
os.environ.setdefault("GATEWAY_URL", "http://unused")
os.environ.setdefault("PRIVACY_URL", "http://unused")

import server


class FakeClient:
    def __init__(self, reply):
        self.reply = reply

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def post(self, *_args, **_kwargs):
        return SimpleNamespace(status_code=200, json=lambda: self.reply)


async def check():
    text = "sample@example.com"
    base = {
        "request_id": "synthetic-probe-01", "spoke": "presidio-privacy", "stage": "input",
        "valid": False, "detections": [{"entity_type": "EMAIL_ADDRESS", "start": 0,
                                      "end": len(text), "score": 1.0}],
        "entity_types": ["EMAIL_ADDRESS"], "sanitized_candidate": "<EMAIL_ADDRESS>",
    }
    real_client = server.httpx.AsyncClient
    async def scan(reply, message=text):
        server.httpx.AsyncClient = lambda **_kwargs: FakeClient(reply)
        return await server.privacy_scan("input", message, "synthetic-probe-01")

    try:
        assert await scan(base) == ("<EMAIL_ADDRESS>", ["EMAIL_ADDRESS"])
        normal = {**base, "valid": True, "detections": [], "entity_types": [],
                  "sanitized_candidate": "hello"}
        assert await scan(normal, "hello") == ("hello", [])
        overlap_text = "DEMO_API_KEY=203.0.113.77"
        overlap = {**base, "detections": [
            {"entity_type": "DEMO_API_KEY", "start": 0, "end": 16, "score": 0.95},
            {"entity_type": "IP_ADDRESS", "start": 13, "end": len(overlap_text), "score": 0.6}],
            "entity_types": ["DEMO_API_KEY", "IP_ADDRESS"],
            "sanitized_candidate": "<DEMO_API_KEY><IP_ADDRESS>"}
        assert (await scan(overlap, overlap_text))[0] == "<DEMO_API_KEY><IP_ADDRESS>"
        bad_replies = (
            {**base, "request_id": "wrong-request"},
            {**base, "stage": "output"},
            {**base, "sanitized_candidate": text},
            {**base, "entity_types": []},
            {**base, "entity_types": ["RAW sample@example.com"]},
            {**base, "detections": []},
            {**base, "valid": True},
            {**normal, "sanitized_candidate": "changed"},
        )
        for index, reply in enumerate(bad_replies):
            try:
                await scan(reply, "hello" if index == len(bad_replies) - 1 else text)
            except ValueError:
                continue
            raise AssertionError(f"malformed privacy response accepted: {index}")
    finally:
        server.httpx.AsyncClient = real_client


if __name__ == "__main__":
    asyncio.run(check())
    print("proxy_privacy_response=PASS cases=valid,overlap,request,stage,redaction,entities,normal")