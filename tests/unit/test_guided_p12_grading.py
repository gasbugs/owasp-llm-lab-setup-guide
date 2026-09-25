"""Aggregation tests with mocked readers; not real-product acceptance evidence."""
import asyncio
from contextlib import asynccontextmanager
from copy import deepcopy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "llm-security-control-plane/guided-evidence-verifier"))
import p12_grading as grading


class GradingTests(unittest.TestCase):
    def setUp(self):
        paths = [(200, None), (200, None), (401, "authenticate"), (403, "authorize"),
                 (403, "input_rail"), (403, "retrieval_rail"), (403, "output_rail"), (404, "retrieval")]
        self.specs = [{"input": {"case_id": f"case-{index}", "identity": "reader", "tenant": "team-a", "message": "fixture"},
                       "status": status, "stop": stop, "input_entities": {"EMAIL_ADDRESS": 1} if index == 1 else {}}
                      for index, (status, stop) in enumerate(paths)]
        self.calls, self.exited, self.mode = [], False, None

    @asynccontextmanager
    async def snapshot(self, *args, **kwargs):
        self.assertEqual(kwargs["case_ids"], [spec["input"]["case_id"] for spec in self.specs])
        yield {"binding": {"source_digest": "a" * 64}, "receipt": {"cases": [spec["input"] for spec in self.specs]}}
        self.exited = True
        if self.mode == "root-changed":
            raise grading.EvidenceError("private-credential-fixture")

    async def case(self, attempt, origins, tokens, **kwargs):
        index = len(self.calls)
        self.calls.append(deepcopy(kwargs))
        if self.mode == "case-error" and index == 4:
            raise grading.EvidenceError("private-credential-fixture")
        entities = {"EMAIL_ADDRESS": 1} if index == 1 else {}
        if self.mode == "privacy-mismatch":
            entities = {}
        identifier = "duplicate" if self.mode == "duplicate-provider" else f"provider-{index}"
        return {"consistency": {"evidence_consistent": True},
                "service_builds": {"fixture": index if self.mode == "build-change" else 0},
                "ledgers": {"privacy": {"calls": [{"stage": "input_privacy", "evidence": {"entity_counts": entities}}]},
                            "gateway": {"grants": [{"state": "completed", "evidence": {"provider_request_id": identifier}}]}}}

    def grade(self):
        with patch.object(grading, "verified_run_snapshot", self.snapshot), patch.object(grading, "verify_case_from_services", self.case):
            return asyncio.run(grading.grade_run("http://runner", "fixture", {}, {}, suite_id="fixture",
                specifications=self.specs, documents=[], scaffold_files={}))

    def test_completion_requires_every_case_and_successful_final_requery(self):
        result = self.grade()
        self.assertTrue(result["task_completed"])
        self.assertEqual(result["security_verdict"], "PASS")
        self.assertTrue(self.exited)
        self.assertEqual(len(self.calls), 8)
        self.assertEqual(result["provider_call_count"], 8)
        for spec, call in zip(self.specs, self.calls):
            self.assertEqual(call["expected_case"], spec["input"])
            self.assertEqual(call["expected_status"], spec["status"])
            self.assertEqual(call["expected_stop"], spec["stop"])

    def test_any_case_error_leaves_whole_run_incomplete(self):
        self.mode = "case-error"
        result = self.grade()
        self.assertFalse(result["task_completed"])
        self.assertEqual(result["security_verdict"], "ERR")
        self.assertEqual(result["failed_case"], "case-4")
        self.assertNotIn("private-credential-fixture", str(result))

    def test_final_requery_failure_revokes_completion(self):
        self.mode = "root-changed"
        result = self.grade()
        self.assertEqual(len(result["cases"]), 8)
        self.assertFalse(result["task_completed"])
        self.assertEqual(result["security_verdict"], "ERR")

    def test_provider_reuse_build_change_and_privacy_mismatch_fail(self):
        for mode in ("duplicate-provider", "build-change", "privacy-mismatch"):
            with self.subTest(mode=mode):
                self.mode, self.calls = mode, []
                result = self.grade()
                self.assertFalse(result["task_completed"])
                self.assertEqual(result["security_verdict"], "ERR")

    def test_incomplete_contract_never_queries_services(self):
        baseline = deepcopy(self.specs)
        for specs in (baseline[:7], baseline[:2] * 4, [{**spec, "input_entities": {}} for spec in baseline]):
            self.specs = specs
            result = self.grade()
            self.assertFalse(result["task_completed"])
            self.assertFalse(self.calls)

    def test_previous_success_does_not_mask_current_failure(self):
        self.assertTrue(self.grade()["task_completed"])
        self.mode, self.calls = "case-error", []
        self.assertFalse(self.grade()["task_completed"])


if __name__ == "__main__":
    unittest.main()
