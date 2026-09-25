"""Native adapter response binding and no-retry tests; HTTP transport is a double."""
import hashlib
import json
from pathlib import Path
import sys
import unittest
from uuid import uuid4

import httpx

ROOT = Path(__file__).resolve().parents[2] / "llm-security-control-plane/guided-labs/h12-protected-services"
sys.path.insert(0, str(ROOT))
from gateway_model import GatewayModel, MODEL_ID


class GatewayModelTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.suite, self.execution = str(uuid4()), str(uuid4())
        self.calls = []

    def response(self, request):
        body = json.loads(request.content)
        self.calls.append(body)
        actual = {"modelId": MODEL_ID, "messages": [{"role": "user", "content": [{"text": body["prompt"]}]}],
                  "inferenceConfig": {"maxTokens": 3, "temperature": 0.0}}
        digest = hashlib.sha256(json.dumps(actual, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        return {**{key: body[key] for key in ("suite_id", "execution_id", "role", "model")},
                "request_digest": digest, "text": "No", "evidence": {
                    "actual_model_id": MODEL_ID, "provider_request_id": "fixture-provider",
                    "response_digest": hashlib.sha256(b"No").hexdigest(), "response_bytes": 2}}

    def model(self, handler):
        return GatewayModel("http://gateway", self.suite, self.execution, "input_rail", "fixture-" * 8,
                            transport=httpx.MockTransport(handler))

    async def test_valid_response_binding_and_second_call_rejected(self):
        model = self.model(lambda request: httpx.Response(200, json=self.response(request)))
        result = await model.generate_async([{"role": "user", "content": "교육용 검사"}], max_tokens=3, temperature=0.0)
        self.assertEqual(result.content, "No")
        self.assertEqual(model.gateway_evidence["provider_request_id"], "fixture-provider")
        with self.assertRaises(ValueError):
            await model.generate_async("교육용 검사")
        self.assertEqual(len(self.calls), 1)

    async def test_response_binding_corruption_rejected(self):
        for key in ("suite_id", "execution_id", "role", "model", "request_digest"):
            def handler(request):
                body = self.response(request)
                body[key] = "mismatched"
                return httpx.Response(200, json=body)
            model = self.model(handler)
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "P12 Gateway invocation failed"):
                await model.generate_async("교육용 검사")
            self.assertIsNone(model.gateway_evidence)
        for key in ("response_digest", "response_bytes", "actual_model_id", "provider_request_id"):
            def handler(request):
                body = self.response(request)
                body["evidence"][key] = "" if key == "provider_request_id" else "mismatched"
                return httpx.Response(200, json=body)
            with self.subTest(key=key), self.assertRaises(ValueError):
                await self.model(handler).generate_async("교육용 검사")

    async def test_redirect_errors_oversize_and_bad_json_are_not_retried(self):
        for response in (httpx.Response(302, headers={"Location": "http://other"}),
                         httpx.Response(503, text="synthetic-private-error"),
                         httpx.Response(200, text="not-json"), httpx.Response(200, content=b"x" * 131073)):
            calls = []
            def handler(request):
                calls.append(request)
                return response
            model = self.model(handler)
            with self.assertRaisesRegex(ValueError, "^P12 Gateway invocation failed$"):
                await model.generate_async("교육용 검사")
            with self.assertRaises(ValueError):
                await model.generate_async("교육용 검사")
            self.assertEqual(len(calls), 1)

    async def test_unsupported_parameters_do_not_reach_transport(self):
        model = self.model(lambda request: httpx.Response(200, json=self.response(request)))
        for kwargs in ({"temperature": 1}, {"max_tokens": 128}, {"stop": ["stop"]}, {"extra": True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                await model.generate_async("교육용 검사", **kwargs)
        self.assertFalse(self.calls)


if __name__ == "__main__":
    unittest.main(verbosity=2)
