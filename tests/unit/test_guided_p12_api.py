"""HTTP input boundary with a mocked grader; product grading has separate E2E."""
import asyncio
from pathlib import Path
import sys
import unittest
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import httpx
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "llm-security-control-plane/guided-evidence-verifier"))
import p12_api


class APITests(unittest.TestCase):
    def setUp(self):
        self.options = {"control_token": "control-fixture", "origin": "http://runner", "token": "runner-verifier",
            "origins": {key: "http://" + key for key in ("context", "privacy", "nemo", "gateway")},
            "tokens": {key: key + "-verifier" for key in ("context", "privacy", "nemo", "gateway")},
            "specifications": [{"server_owned": True}], "documents": [], "scaffold_files": {"fixture": "digest"}}
        self.app = p12_api.create_app(**self.options)
        self.client = TestClient(self.app)
        self.body = {"suite_id": str(uuid4())}
        self.headers = {"Authorization": "Bearer control-fixture"}

    def test_only_suite_id_is_forwarded_from_request(self):
        self.options["specifications"].clear()
        grader = AsyncMock(return_value={"task_completed": False, "security_verdict": "ERR"})
        with patch.object(p12_api, "grade_run", grader):
            response = self.client.post("/v1/verify/p12", json=self.body, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["task_completed"])
        args = grader.await_args.kwargs
        self.assertEqual(args["suite_id"], self.body["suite_id"])
        self.assertEqual(args["specifications"], [{"server_owned": True}])
        self.assertEqual(args["origin"], "http://runner")

    def test_unauthorized_caller_never_invokes_grader(self):
        with patch.object(p12_api, "grade_run", AsyncMock()) as grader:
            for token in ("", "Bearer wrong", "Bearer runner-verifier", "Bearer context-verifier"):
                response = self.client.post("/v1/verify/p12", json=self.body, headers={"Authorization": token})
                self.assertEqual(response.status_code, 401)
            grader.assert_not_awaited()

    def test_browser_cannot_submit_verdict_contract_or_origin(self):
        with patch.object(p12_api, "grade_run", AsyncMock()) as grader:
            for name in ("task_completed", "security_verdict", "specifications", "origin", "tokens", "source_digest"):
                response = self.client.post("/v1/verify/p12", json={**self.body, name: "private-fixture"}, headers=self.headers)
                self.assertEqual(response.status_code, 422)
                self.assertNotIn("private-fixture", response.text)
            grader.assert_not_awaited()

    def test_invalid_id_and_readiness_do_not_query_products(self):
        with patch.object(p12_api, "grade_run", AsyncMock()) as grader:
            self.assertEqual(self.client.post("/v1/verify/p12", json={"suite_id": "../bad"}, headers=self.headers).status_code, 422)
            self.assertEqual(self.client.get("/readyz").status_code, 200)
            self.assertEqual(self.client.get("/openapi.json").status_code, 404)
            grader.assert_not_awaited()

    def test_verification_concurrency_is_bounded_and_lock_is_released(self):
        async def check():
            entered, release = asyncio.Event(), asyncio.Event()
            async def grade(**kwargs):
                entered.set()
                await release.wait()
                return {"task_completed": False, "security_verdict": "ERR"}
            with patch.object(p12_api, "grade_run", grade):
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url="http://verifier") as client:
                    first = asyncio.create_task(client.post("/v1/verify/p12", json=self.body, headers=self.headers))
                    await asyncio.wait_for(entered.wait(), 2)
                    self.assertEqual((await client.post("/v1/verify/p12", json=self.body, headers=self.headers)).status_code, 409)
                    release.set()
                    self.assertEqual((await first).status_code, 200)
                    self.assertEqual((await client.post("/v1/verify/p12", json=self.body, headers=self.headers)).status_code, 200)
        asyncio.run(check())

    def test_control_credential_cannot_be_a_readonly_service_credential(self):
        for credential in ("", "runner-verifier", "context-verifier"):
            with self.subTest(credential=credential), self.assertRaises(ValueError):
                p12_api.create_app(**{**self.options, "control_token": credential})


if __name__ == "__main__":
    unittest.main()
