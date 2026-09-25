"""Read-only root re-query with synthetic HTTP responses, not deployment evidence."""
import asyncio
from copy import deepcopy
import unittest

import httpx
import test_guided_p12_binding as binding_fixture
from p12_results import EvidenceError
from p12_verification import verified_run_snapshot


class RunRequeryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = binding_fixture.BindingTests()
        self.fixture.setUp()
        self.requests = []
        self.mode = None

    def respond(self, request):
        self.assertEqual(request.method, "GET")
        self.assertEqual(request.url.host, "runner")
        self.assertEqual(request.headers["Authorization"], "Bearer readonly-fixture")
        self.requests.append(request.url.path)
        if self.mode == "timeout":
            raise httpx.ReadTimeout("private-credential-fixture", request=request)
        if self.mode == "redirect":
            return httpx.Response(302, headers={"Location": "http://other.invalid/"})
        if self.mode == "unavailable":
            return httpx.Response(503, text="private-credential-fixture")
        if self.mode == "invalid-json":
            return httpx.Response(200, text="not JSON")
        is_build = request.url.path == "/v1/build-info"
        if self.mode == "oversized-build" and is_build:
            return httpx.Response(200, content=b" " * 65537)
        if self.mode == "oversized-receipt" and not is_build:
            return httpx.Response(200, content=b" " * (2 * 1024 * 1024 + 1))
        value = deepcopy(self.fixture.info if is_build else self.fixture.receipt)
        if len(self.requests) > 2:
            if is_build and self.mode == "changed-build":
                value["current_build"]["files"]["pipeline.py"] = "d" * 64
            if not is_build and self.mode == "changed-receipt":
                value["run_state"] = "error"
        return httpx.Response(200, json=value)

    async def check(self, **overrides):
        args = {"origin": "http://runner", "token": "readonly-fixture", "suite_id": self.fixture.suite,
                "case_ids": self.fixture.ids, "contract_digest": "b" * 64,
                "scaffold_files": self.fixture.scaffold, "now": 106,
                "transport": httpx.MockTransport(self.respond), **overrides}
        async with verified_run_snapshot(**args) as snapshot:
            self.assertEqual(len(self.requests), 2)
            self.assertTrue(snapshot["binding"]["run_bound"])
            if self.mode == "caller-mutation":
                snapshot["receipt"]["run_state"] = "error"
        return snapshot

    def test_reads_before_and_after_without_writing(self):
        snapshot = asyncio.run(self.check())
        self.assertEqual(len(self.requests), 4)
        self.assertEqual(self.requests[0], self.requests[3])
        self.assertEqual(self.requests[1], self.requests[2])
        self.assertNotIn("task_completed", snapshot)

    def test_transport_failures_do_not_return_valid_snapshot(self):
        for mode in ("timeout", "redirect", "unavailable", "invalid-json", "oversized-build", "oversized-receipt"):
            with self.subTest(mode=mode), self.assertRaises(EvidenceError) as raised:
                self.mode, self.requests = mode, []
                asyncio.run(self.check())
            self.assertNotIn("private-credential-fixture", str(raised.exception))

    def test_changes_during_scope_are_rejected_on_exit(self):
        for mode in ("changed-build", "changed-receipt", "caller-mutation"):
            with self.subTest(mode=mode), self.assertRaises(EvidenceError):
                self.mode, self.requests = mode, []
                asyncio.run(self.check())

    def test_invalid_connection_or_id_makes_no_request(self):
        for override in ({"origin": "http://user:secret@runner"}, {"origin": "http://runner/path"},
                         {"origin": "file:///tmp"}, {"suite_id": "../../another"}, {"token": ""}):
            with self.subTest(override=override), self.assertRaises(EvidenceError):
                asyncio.run(self.check(**override))
            self.assertFalse(self.requests)

    def test_wrong_trusted_contract_rejects_before_product_scope(self):
        with self.assertRaises(EvidenceError):
            asyncio.run(self.check(contract_digest="d" * 64))
        self.assertEqual(len(self.requests), 2)


if __name__ == "__main__":
    unittest.main()
