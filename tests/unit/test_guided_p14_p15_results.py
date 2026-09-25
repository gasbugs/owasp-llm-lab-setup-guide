"""Read-only artifact grading; these tests never run a scan or contact a target."""
from copy import deepcopy
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

import test_guided_evidence_verifier as fixture


class RecordedArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture.GuidedEvidenceVerifierTests.setUpClass()
        cls.server = fixture.GuidedEvidenceVerifierTests.server

    @classmethod
    def tearDownClass(cls):
        fixture.GuidedEvidenceVerifierTests.tearDownClass()

    def grade(self, activity, data):
        response = Mock(status_code=200)
        response.json.return_value = data
        request = self.server.H13VerifyRequest(suite_id=str(uuid4()), started_at="publisher-start")
        with patch.object(self.server.httpx, "get", return_value=response):
            return getattr(self.server, "verify_" + activity)(request)["course_verdict"]

    def test_p14_native_bounds_not_reference_bytes(self):
        data = {"receipt": {"started_at": "publisher-start", "tool_version": "0.15.1",
                            "config_digest": "a" * 64, "report_digest": "b" * 64, "exit_code": 0},
                "report": [{"entry_type": "start_run setup", "run.soft_probe_prompt_cap": 4,
                            "run.generations": 1, "system.parallel_attempts": False}]}
        self.assertEqual(self.grade("h14", data), "PASS")
        for field, value in (("run.soft_probe_prompt_cap", 0), ("system.parallel_attempts", 2)):
            wrong = deepcopy(data)
            wrong["report"][0][field] = value
            with self.subTest(field=field):
                self.assertEqual(self.grade("h14", wrong), "ERR")

    def test_p15_recorded_contract_not_reference_bytes(self):
        data = {"started_at": "publisher-start", "tool_version": "1.0.1",
                "source_digest": "a" * 64, "conversation_id": "recorded-conversation",
                "contract": {"max_turns": 3, "impact_marker": "H15_POLICY_BYPASS_CANARY",
                             "sequential": True, "http_error_is_err": True},
                "turns": [{}, {}, {}], "native_memory_messages": 6,
                "reproduction": {"decision": "block", "upstream_called": False,
                                 "request_id": "recorded-request"}}
        self.assertEqual(self.grade("h15", data), "PASS")
        starter = deepcopy(data)
        starter["contract"]["max_turns"] = 0
        starter["turns"] = []
        self.assertEqual(self.grade("h15", starter), "ERR")
        wrong = deepcopy(data)
        wrong["reproduction"]["upstream_called"] = True
        self.assertEqual(self.grade("h15", wrong), "ERR")


if __name__ == "__main__":
    unittest.main()
