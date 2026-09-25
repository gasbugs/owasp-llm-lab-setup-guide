"""Lifecycle HTTP contract; mock transport, not product or AWS evidence."""
import json
from pathlib import Path
import sys
import unittest
from uuid import uuid4

import httpx

SOURCE = Path(__file__).resolve().parents[2] / "llm-security-control-plane/guided-labs/h12-application-pipeline"
sys.path.insert(0, str(SOURCE))
from workflow import Workflow, SERVICES, ROLES


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.suite, self.execution = str(uuid4()), str(uuid4())
        self.origins = {name: "http://" + name for name in SERVICES}
        self.tokens = {name: {role: name + "-secret-" + role
                             for role in (("control",) if name == "gateway" else ("control", "service"))}
                       for name in SERVICES}
        self.calls, self.workers = [], []
        self.failure = None
        self.worker_error = False
        self.worker_status = "returned"
        self.bad_grant = False
        self.bad_closure = False

    def transport(self, req):
        service, path = req.url.host, req.url.path
        self.calls.append((service, path))
        self.assertEqual(req.headers["authorization"], "Bearer " + self.tokens[service]["control"])
        if self.failure and self.failure[:2] == (service, path):
            if self.failure[2] == "lost":
                raise httpx.ReadTimeout("secret failure detail", request=req)
            return httpx.Response(self.failure[2], json={"detail": "secret failure detail"})
        body = {"suite_id": self.suite}
        if path.endswith("/close"):
            body["closed_at"] = True if self.bad_closure else 1234.0
        elif service == "context":
            body["credentials"] = {"reader": "reader-credential", "visitor": "visitor-credential"}
        elif service == "gateway":
            body["grants"] = [{"suite_id": str(uuid4()) if self.bad_grant else self.suite,
                "execution_id": self.execution, "role": role, "capability": (role + "-cap-") * 6}
                for role in sorted(ROLES)]
        return httpx.Response(200, json=body)

    def worker(self, source, request, config):
        self.workers.append((source, request, config))
        if self.worker_error:
            raise RuntimeError("reader-credential secret failure detail")
        return {"execution_status": self.worker_status, "calls": []}

    def run_case(self):
        workflow = Workflow(self.origins, self.tokens, transport=httpx.MockTransport(self.transport), worker=self.worker)
        return workflow.run_case("pipeline.py", suite_id=self.suite, execution_id=self.execution,
                                 documents=[], identity="reader", tenant="team-a", message="계정 복구")

    def test_complete_lifecycle_does_not_grade_and_limits_worker_credentials(self):
        result = self.run_case()
        self.assertEqual(result["lifecycle_status"], "finished")
        self.assertEqual(len(self.calls), 8)
        self.assertEqual(len(self.workers), 1)
        config = self.workers[0][2]
        self.assertEqual(set(config["tokens"]), {"context", "privacy", "nemo"})
        for roles in self.tokens.values():
            self.assertNotIn(roles["control"], json.dumps(config))
        self.assertEqual(set(config["capabilities"]), ROLES)
        self.assertNotIn("security_verdict", result)
        self.assertNotIn("task_completed", result)
        self.assertNotIn("credential", json.dumps(result))

    def test_lost_registration_response_is_closed_but_not_reported_as_no_calls(self):
        self.failure = ("privacy", "/v1/suites", "lost")
        result = self.run_case()
        self.assertEqual(result["lifecycle_status"], "error")
        self.assertIsNone(result["execution"])
        self.assertEqual(set(result["closures"]), {"context", "privacy"})
        self.assertFalse(self.workers)
        self.assertNotIn("secret", json.dumps(result))

    def test_existing_suite_is_not_closed_by_duplicate_attempt(self):
        self.failure = ("context", "/v1/suites", 409)
        result = self.run_case()
        self.assertEqual(result["lifecycle_status"], "error")
        self.assertEqual(result["closures"], {})
        self.assertEqual(result["registration_attempts"], ["context"])
        self.assertEqual(len(self.calls), 1)

    def test_pending_close_is_unknown_and_other_services_still_close(self):
        self.failure = ("privacy", f"/v1/suites/{self.suite}/close", 409)
        result = self.run_case()
        self.assertEqual(result["lifecycle_status"], "error")
        self.assertEqual(result["closures"]["privacy"], {"state": "unknown"})
        self.assertEqual(result["closures"]["gateway"]["state"], "closed")

    def test_worker_failure_still_closes_without_exposing_exception(self):
        self.worker_error = True
        result = self.run_case()
        self.assertEqual(len(result["closures"]), 4)
        self.assertIsNone(result["execution"])
        self.assertNotIn("secret", json.dumps(result))

    def test_unimplemented_is_preserved_not_promoted_to_completion(self):
        self.worker_status = "not_implemented"
        result = self.run_case()
        self.assertEqual(result["execution"]["execution_status"], "not_implemented")
        self.assertEqual(result["lifecycle_status"], "finished")

    def test_wrong_grant_binding_prevents_worker(self):
        self.bad_grant = True
        result = self.run_case()
        self.assertEqual(result["lifecycle_status"], "error")
        self.assertFalse(self.workers)
        self.assertEqual(len(result["closures"]), 4)

    def test_invalid_closure_is_unknown(self):
        self.bad_closure = True
        result = self.run_case()
        self.assertEqual(result["lifecycle_status"], "error")
        self.assertTrue(all(row["state"] == "unknown" for row in result["closures"].values()))

    def test_verifier_credentials_and_non_origin_urls_rejected(self):
        with self.assertRaises(ValueError):
            Workflow({**self.origins, "context": "http://context/private"}, self.tokens)
        with self.assertRaises(ValueError):
            Workflow(self.origins, {**self.tokens, "gateway": {**self.tokens["gateway"], "verifier": "secret"}})


if __name__ == "__main__":
    unittest.main()
