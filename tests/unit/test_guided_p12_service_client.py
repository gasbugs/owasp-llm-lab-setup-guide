"""Transport/response contract doubles; not Presidio, NeMo, AWS or grading evidence."""
import asyncio
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from uuid import uuid4

import httpx

SOURCE = Path(__file__).resolve().parents[2] / "llm-security-control-plane/guided-labs/h12-application-pipeline/service_client.py"
spec = importlib.util.spec_from_file_location("p12_service_client", SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ServiceClientTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.suite, self.execution = str(uuid4()), str(uuid4())
        self.origins = {name: f"http://{name}.invalid:8000" for name in ("privacy", "nemo", "gateway")}
        self.tokens = {name: f"test-only-{name}" for name in ("privacy", "nemo")}
        self.caps = {stage: (stage + "-grant-") * 5 for stage in module.RAILS | {"main"}}
        self.requests = []
        self.answer = "No"
        self.mutate = lambda result: result
        self.status = 200

    def response(self, request):
        body = json.loads(request.content)
        self.requests.append((request, body))
        result = {"suite_id": self.suite, "execution_id": self.execution}
        host = request.url.host.split(".")[0]
        if host == "privacy":
            self.assertEqual(request.headers["authorization"], "Bearer " + self.tokens[host])
            text = body["text"].replace("learner@example.com", "<EMAIL_ADDRESS>")
            result.update(text=text, evidence={
                "stage": body["stage"], "input_digest": module.digest(body["text"]),
                "output_digest": module.digest(text), "input_bytes": len(body["text"].encode()),
                "output_bytes": len(text.encode()), "framework": "microsoft-presidio", "operator": "replace",
                "versions": {"presidio-analyzer": "2.2.362", "presidio-anonymizer": "2.2.362"},
                "entity_counts": {"EMAIL_ADDRESS": 1} if text != body["text"] else {},
                "service_digest": "a" * 64})
        elif host == "nemo":
            self.assertEqual(request.headers["authorization"], "Bearer " + self.tokens[host])
            self.assertEqual(body["capability"], self.caps[body["stage"]])
            result.update(allowed=self.answer == "No", evidence={
                "stage": body["stage"], "input_digest": module.digest(body["text"]),
                "version": "0.22.0", "classifier_answer": self.answer, "native_stop": self.answer == "Yes",
                "service_digest": "b" * 64, "gateway": {
                    "capability_digest": module.digest(body["capability"]), "request_digest": "c" * 64,
                    "response_digest": module.digest(self.answer), "provider_request_id": "fixture-classifier"}})
        else:
            self.assertEqual(request.headers["authorization"], "Bearer " + self.caps["main"])
            actual = {"modelId": module.MODEL, "messages": [{"role": "user", "content": [{"text": body["prompt"]}]}],
                      "inferenceConfig": {"maxTokens": 128, "temperature": 0.0}}
            text = "계정 복구 안내"
            result.update(role="main", model=module.MODEL + "#p12-main", text=text,
                          request_digest=module.digest(json.dumps(actual, sort_keys=True, separators=(",", ":"), ensure_ascii=False)),
                          evidence={"actual_model_id": module.MODEL, "response_digest": module.digest(text),
                                    "response_bytes": len(text.encode()), "provider_request_id": "fixture-main"})
        return httpx.Response(self.status, json=self.mutate(result))

    def client(self, **updates):
        return module.ServiceClient(**{"suite_id": self.suite, "execution_id": self.execution,
            "origins": self.origins, "tokens": self.tokens, "capabilities": self.caps,
            "transport": httpx.MockTransport(self.response), **updates})

    async def test_caller_dataflow_reaches_actual_http_request_bodies(self):
        client = self.client()
        private = await client.privacy("input_privacy", "Email learner@example.com")
        self.assertEqual(private, "Email <EMAIL_ADDRESS>")
        self.assertTrue(await client.rail("input_rail", private))
        self.assertTrue(await client.rail("retrieval_rail", "검토할 합성 문서"))
        answer = await client.main(private + "\n검토할 합성 문서")
        self.assertTrue(await client.rail("output_rail", answer))
        self.assertEqual(await client.privacy("output_privacy", answer), answer)
        self.assertEqual(self.requests[1][1]["text"], private)
        self.assertEqual(self.requests[3][1]["prompt"], private + "\n검토할 합성 문서")
        self.assertEqual(self.requests[4][1]["text"], answer)
        self.assertEqual([row["sequence"] for row in client.calls], list(range(1, 7)))
        self.assertEqual([row["stage"] for row in client.calls],
                         ["input_privacy", "input_rail", "retrieval_rail", "main", "output_rail", "output_privacy"])
        self.assertTrue(all(row["state"] == "completed" and row["finished_at"] >= row["started_at"] for row in client.calls))
        serialized = json.dumps(client.calls)
        for secret in (*self.tokens.values(), *self.caps.values(), "learner@example.com", answer):
            self.assertNotIn(secret, serialized)
        self.assertNotIn("security_verdict", serialized)
        self.assertNotIn("task_completed", serialized)
        for _, body in self.requests:
            self.assertEqual((body["suite_id"], body["execution_id"]), (self.suite, self.execution))
            self.assertNotIn("case_id", body)

    async def test_normal_denial_is_false_not_an_exception(self):
        self.answer = "Yes"
        client = self.client()
        self.assertIs(await client.rail("retrieval_rail", "검토할 합성 문서"), False)
        self.assertEqual(client.calls[0]["state"], "completed")
        self.assertIs(client.calls[0]["allowed"], False)

    async def test_main_json_serializations_use_identical_outbound_text_and_digest(self):
        value = {"question": "계정 복구", "context": "지원 안내\n공백은 보존  "}
        inputs = [json.dumps(value, ensure_ascii=False),
                  json.dumps(dict(reversed(list(value.items()))), ensure_ascii=True, indent=2)]
        records = []
        for prompt in inputs:
            client = self.client()
            await client.main(prompt)
            records.append(client.calls[0])
        bodies = [body["prompt"] for _, body in self.requests]
        self.assertEqual(bodies[0], bodies[1])
        self.assertEqual(json.loads(bodies[0]), value)
        self.assertIn("계정 복구", bodies[0])
        self.assertEqual(records[0]["input_digest"], records[1]["input_digest"])

    async def test_main_does_not_repair_invalid_or_duplicate_fields(self):
        for prompt in ('{"question":"one","question":"two","context":"doc"}',
                       '{"question":"one"}', '{"question":true,"context":"doc"}',
                       '{"question":"one","context":"doc","extra":"field"}'):
            with self.subTest(prompt=prompt):
                await self.client().main(prompt)
                self.assertEqual(self.requests[-1][1]["prompt"], prompt)

    async def test_invalid_classifier_is_service_error_not_denial(self):
        self.answer = "Yes\n"
        client = self.client()
        with self.assertRaises(module.ServiceError):
            await client.rail("input_rail", "계정 복구 문의")
        self.assertEqual(client.calls[0]["state"], "error")
        self.assertNotIn("allowed", client.calls[0])

    async def test_stage_attempt_is_not_retried_and_records_are_snapshots(self):
        client = self.client()
        await client.main("계정 복구 문의")
        with self.assertRaises(module.ServiceError):
            await client.main("다른 문의")
        self.assertEqual(len(self.requests), 1)
        snapshot = client.calls
        snapshot[0]["state"] = "forged"
        self.assertEqual(client.calls[0]["state"], "completed")

    async def test_concurrent_same_stage_is_rejected_before_second_request(self):
        entered, release = asyncio.Event(), asyncio.Event()
        async def handler(request):
            entered.set()
            await release.wait()
            return self.response(request)
        client = self.client(transport=httpx.MockTransport(handler))
        task = asyncio.create_task(client.main("계정 복구 문의"))
        await asyncio.wait_for(entered.wait(), 1)
        try:
            with self.assertRaises(module.ServiceError):
                await client.main("계정 복구 문의")
        finally:
            release.set()
            await task
        self.assertEqual(len(self.requests), 1)

    async def test_total_deadline_and_cancellation_do_not_mark_completion(self):
        entered = asyncio.Event()
        async def handler(_request):
            entered.set()
            await asyncio.Event().wait()
        client = self.client(transport=httpx.MockTransport(handler))
        with patch.object(module, "CALL_TIMEOUT", .02):
            with self.assertRaises(module.ServiceError):
                await client.main("계정 복구 문의")
        self.assertEqual(client.calls[0]["state"], "error")
        self.assertNotIn("evidence", client.calls[0])
        entered.clear()
        client = self.client(transport=httpx.MockTransport(handler))
        task = asyncio.create_task(client.main("계정 복구 문의"))
        await asyncio.wait_for(entered.wait(), 1)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(client.calls[0]["state"], "interrupted")
        self.assertNotIn("evidence", client.calls[0])

    async def test_http_errors_and_redirect_are_not_policy_blocks(self):
        for self.status in (302, 401, 403, 409, 422, 502, 503):
            with self.subTest(status=self.status):
                client = self.client()
                before = len(self.requests)
                with self.assertRaises(module.ServiceError):
                    await client.rail("input_rail", "계정 복구 문의")
                with self.assertRaises(module.ServiceError):
                    await client.rail("input_rail", "계정 복구 문의")
                self.assertEqual(len(self.requests), before + 1)
                self.assertEqual(client.calls[0]["state"], "error")
                self.assertEqual(client.calls[0]["http_status"], self.status)

    async def test_foreign_binding_and_corrupt_product_evidence_rejected(self):
        mutations = [
            ("privacy", ("suite_id",), str(uuid4())),
            ("privacy", ("execution_id",), str(uuid4())),
            ("privacy", ("evidence", "output_digest"), "0" * 64),
            ("privacy", ("evidence", "input_digest"), "0" * 64),
            ("privacy", ("evidence", "service_digest"), "unknown"),
            ("privacy", ("evidence", "input_bytes"), 0),
            ("privacy", ("evidence", "versions"), {}),
            ("privacy", ("evidence", "entity_counts"), {"EMAIL_ADDRESS": True}),
            ("rail", ("allowed",), 1),
            ("rail", ("evidence", "native_stop"), True),
            ("rail", ("evidence", "gateway", "capability_digest"), "0" * 64),
            ("rail", ("evidence", "gateway", "response_digest"), "0" * 64),
            ("main", ("model",), "foreign-model"),
            ("main", ("request_digest",), "0" * 64),
            ("main", ("evidence", "response_digest"), "0" * 64),
            ("main", ("evidence", "response_bytes"), 0),
        ]
        for operation, path, value in mutations:
            with self.subTest(operation=operation, path=path):
                def mutate(result):
                    target = result
                    for key in path[:-1]:
                        target = target[key]
                    target[path[-1]] = value
                    return result
                self.mutate = mutate
                client = self.client()
                with self.assertRaises(module.ServiceError):
                    if operation == "main":
                        await client.main("계정 복구 문의")
                    else:
                        await getattr(client, operation)("input_privacy" if operation == "privacy" else "input_rail", "계정 복구 문의")
                self.assertEqual(client.calls[0]["state"], "error")
                self.assertNotIn("evidence", client.calls[0])

    async def test_malformed_oversized_and_transport_errors_are_sanitized(self):
        for mode in ("malformed", "oversized", "timeout"):
            def handler(request):
                if mode == "timeout":
                    raise httpx.ReadTimeout("secret-error-value", request=request)
                return httpx.Response(200, content=b"secret-error-value" if mode == "malformed" else b"x" * 131073)
            client = self.client(transport=httpx.MockTransport(handler))
            with self.assertRaises(module.ServiceError) as raised:
                await client.main("synthetic-private-text")
            self.assertNotIn("secret-error", str(raised.exception))
            self.assertNotIn("synthetic-private-text", json.dumps(client.calls))
            self.assertEqual(client.calls[0]["state"], "error")

    async def test_response_extra_fields_are_not_copied_into_records(self):
        def mutate(result):
            result["secret"] = "hidden-private-text"
            result["evidence"]["secret"] = "hidden-private-text"
            return result
        self.mutate = mutate
        client = self.client()
        await client.privacy("input_privacy", "문의")
        await client.rail("input_rail", "문의")
        await client.main("문의")
        self.assertNotIn("hidden-private-text", json.dumps(client.calls))

    async def test_invalid_local_arguments_do_not_send_requests(self):
        client = self.client()
        for stage, text in (("main", "문의"), ("input_privacy", " "), ("input_privacy", "x" * 16001)):
            with self.assertRaises(ValueError):
                await client.privacy(stage, text)
        with self.assertRaises(ValueError):
            await client.rail("output_privacy", "문의")
        with self.assertRaises(ValueError):
            await client.main("x" * 40001)
        self.assertFalse(self.requests)
        self.assertEqual(client.calls, [])

    def test_config_rejects_browser_selected_paths_credentials_or_incomplete_grants(self):
        for url in ("file:///app", "http://user:pass@host", "http://host/path", "http://host/?q=x", "http://host/#x"):
            with self.assertRaises(ValueError):
                self.client(origins={**self.origins, "nemo": url})
        for update in ({"capabilities": {}}, {"tokens": {}}, {"execution_id": "foreign"},
                       {"capabilities": {**self.caps, "main": "short"}}):
            with self.assertRaises(ValueError):
                self.client(**update)

    async def test_context_binding_and_retrieval_projection(self):
        value = "계정 복구"
        result = {"suite_id": self.suite, "execution_id": self.execution, "text": "지원 안내",
                  "evidence": {"stage": "retrieval", "input_digest": module.digest(value),
                    "backend": "synthetic-sqlite-fts", "service_digest": "a" * 64,
                    "authorized_tenant": "team-a", "query_executed": True,
                    "output_digest": module.digest("지원 안내"), "output_bytes": len("지원 안내".encode()),
                    "hits": [{"document_id": "account", "tenant": "team-a", "text_digest": module.digest("지원 안내")}],
                    "extra_private": "must-not-be-recorded"}}
        def make():
            return self.client(origins={**self.origins, "context": "http://context.invalid"},
                               tokens={**self.tokens, "context": "context-fixture"},
                               transport=httpx.MockTransport(lambda _: httpx.Response(200, json=result)))
        client = make()
        self.assertEqual(await client.retrieve(value), "지원 안내")
        self.assertNotIn("must-not-be-recorded", json.dumps(client.calls))
        for key, replacement in (("authorized_tenant", "team-b"), ("query_executed", 1),
                                 ("output_digest", "0" * 64), ("service_digest", "missing"),
                                 ("hits", [{"document_id": "account", "tenant": "team-b", "text_digest": "a" * 64}])):
            original = result["evidence"][key]
            result["evidence"][key] = replacement
            with self.subTest(key=key), self.assertRaises(module.ServiceError):
                await make().retrieve(value)
            result["evidence"][key] = original

    async def test_context_identity_response_cannot_invent_subject_or_scope(self):
        result = {"suite_id": self.suite, "execution_id": self.execution, "allowed": True,
                  "evidence": {"stage": "authorize", "input_digest": module.digest("team-a"),
                    "backend": "synthetic-sqlite-fts", "service_digest": "a" * 64,
                    "authorized": True, "subject": "reader", "requested_tenant": "team-a", "required_scope": "knowledge:read"}}
        def make():
            return self.client(origins={**self.origins, "context": "http://context.invalid"},
                               tokens={**self.tokens, "context": "context-fixture"},
                               transport=httpx.MockTransport(lambda _: httpx.Response(200, json=result)))
        self.assertTrue(await make().authorize("team-a"))
        for key, replacement in (("authorized", 1), ("subject", "visitor"), ("requested_tenant", "team-b"), ("required_scope", "admin")):
            original = result["evidence"][key]
            result["evidence"][key] = replacement
            with self.subTest(key=key), self.assertRaises(module.ServiceError):
                await make().authorize("team-a")
            result["evidence"][key] = original

    async def test_unconfigured_context_does_not_attempt_network(self):
        client = self.client()
        with self.assertRaises(ValueError):
            await client.authenticate("fixture-user")
        self.assertFalse(self.requests)
        self.assertEqual(client.calls, [])


if __name__ == "__main__":
    unittest.main()
