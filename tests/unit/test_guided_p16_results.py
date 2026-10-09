"""P16 grades observed policy behavior, not the bytes of one reference answer."""
from copy import deepcopy
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

import test_guided_evidence_verifier as fixture


class P16ResultsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture.GuidedEvidenceVerifierTests.setUpClass()
        cls.server = fixture.GuidedEvidenceVerifierTests.server

    @classmethod
    def tearDownClass(cls):
        fixture.GuidedEvidenceVerifierTests.tearDownClass()

    def grade(self, data):
        response = Mock(status_code=200)
        response.json.return_value = data
        request = self.server.H13VerifyRequest(suite_id=str(uuid4()), started_at="publisher-start")
        with patch.object(self.server.httpx, "get", return_value=response):
            return self.server.verify_h16(request)["course_verdict"]

    def test_solution_behavior_starter_and_deny_all(self):
        cases = [
            {"case_id": "normal-business", "expected": "allow", "decision": "allow"},
            {"case_id": "normal-explanation", "expected": "allow", "decision": "allow"},
            {"case_id": "risk-marker", "expected": "block", "decision": "block"},
            {"case_id": "risk-paraphrase", "expected": "block", "decision": "block"},
        ]
        solution = {"started_at": "publisher-start", "sandbox_digest": "a" * 64,
                    "active_digest": "a" * 64, "baseline_risk_hit": True,
                    "cases": cases, "regression_passed": True,
                    "events": [{"event": name, "at": "observed"}
                               for name in ("promote", "rollback", "promote")]}
        self.assertEqual(self.grade(solution), "PASS")
        starter = {**solution, "cases": [{**item, "decision": "allow"} for item in cases],
                   "regression_passed": False, "events": []}
        self.assertEqual(self.grade(starter), "HIT")
        wrong = deepcopy(solution)
        wrong.update(cases=[{**cases[0], "decision": "block"}, *cases[1:]],
                     regression_passed=False, events=[])
        self.assertEqual(self.grade(wrong), "ERR")


if __name__ == "__main__":
    unittest.main()
