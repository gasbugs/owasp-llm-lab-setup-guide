"""Read-only HTTP adapter contracts using captured product evidence and mock transport."""
import asyncio
import json
from pathlib import Path
import sys
import unittest

import httpx

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "llm-security-control-plane/guided-evidence-verifier"))
from p12_verification import verify_case_from_services
from p12_results import EvidenceError


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = json.loads((ROOT / "tests/fixtures/p12_recorded_evidence.json").read_text())
        self.case = self.fixture["cases"][0]
        self.origins = {key: "http://" + key for key in self.case["ledgers"]}
        self.tokens = {key: key + "-verifier-readonly" for key in self.origins}
        self.calls = []
        self.mode = None

    def transport(self, request):
        service, path = request.url.host, request.url.path
        self.assertEqual(request.method, "GET")
        self.assertEqual(request.headers["authorization"], "Bearer " + self.tokens[service])
        self.calls.append((service, path))
        if self.mode == "redirect":
            return httpx.Response(302, headers={"Location": "http://unused.invalid/secret"})
        if self.mode == "oversized":
            return httpx.Response(200, content=b"x" * 262145)
        if self.mode == "timeout":
            raise httpx.ReadTimeout("secret-token", request=request)
        if path.endswith("build-info"):
            result = self.fixture["builds"][service]
            if self.mode == "changed" and self.calls.count((service, path)) > 1:
                result = {**result, "current_source_digest": "0" * 64}
        else:
            result = self.case["ledgers"][service]
        return httpx.Response(200, json=result)

    def verify(self):
        attempt = self.case["attempt"]
        return asyncio.run(verify_case_from_services(attempt, self.origins, self.tokens,
            expected_case={"case_id": "normal", "identity": "reader", "tenant": "team-a", "message": "계정 복구"},
            source_digest=attempt["lifecycle"]["execution"]["source_digest"], expected_status=200, expected_stop=None,
            now=attempt["finished_at"] + 1, transport=httpx.MockTransport(self.transport)))

    def test_fetches_ledgers_and_brackets_service_builds_without_writes(self):
        result = self.verify()
        self.assertTrue(result["consistency"]["evidence_consistent"])
        self.assertEqual(result["ledgers"], self.case["ledgers"])
        self.assertEqual(len(self.calls), 10)

    def test_http_errors_redirects_limits_and_changed_build_fail_closed(self):
        for mode in ("redirect", "oversized", "timeout", "changed"):
            with self.subTest(mode=mode), self.assertRaises(EvidenceError) as raised:
                self.mode, self.calls = mode, []
                self.verify()
            self.assertNotIn("secret-token", str(raised.exception))

    def test_untrusted_scope_and_origin_do_not_send_requests(self):
        self.case["attempt"]["suite_id"] = "../../different"
        with self.assertRaises(EvidenceError):
            self.verify()
        self.assertFalse(self.calls)
        self.origins["context"] = "http://user:secret@context/"
        with self.assertRaises(EvidenceError):
            self.verify()
        self.assertFalse(self.calls)


if __name__ == "__main__":
    unittest.main()
