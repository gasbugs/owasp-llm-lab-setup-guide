"""Captured product evidence replay and corrupted copies; not a live product test."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "llm-security-control-plane/guided-evidence-verifier"))
from p12_results import validate_case, EvidenceError


class ResultsTests(unittest.TestCase):
    def setUp(self):
        self.fixture = json.loads((ROOT / "tests/fixtures/p12_recorded_evidence.json").read_text())
        self.normal = self.fixture["cases"][0]

    def verify(self, case, **overrides):
        attempt = case["attempt"]
        options = {"source_digest": attempt["lifecycle"]["execution"]["source_digest"],
                   "expected_case": {"case_id": case["name"], "identity": "reader", "tenant": "team-a",
                       "message": {"normal": "계정 복구", "input-block": "계정 복구 PIPELINE_TEST_DENY",
                                   "classifier-error": "계정 복구 PIPELINE_TEST_MALFORMED"}[case["name"]]},
                   "expected_status": 200 if case["name"] == "normal" else 403,
                   "expected_stop": None if case["name"] == "normal" else "input_rail",
                   "now": attempt["finished_at"] + 1}
        return validate_case(attempt, case["ledgers"], self.fixture["builds"], **{**options, **overrides})

    def test_recorded_normal_and_denied_paths(self):
        for case in self.fixture["cases"][:2]:
            with self.subTest(case=case["name"]):
                self.assertTrue(self.verify(case)["evidence_consistent"])

    def test_classifier_error_is_not_promoted_to_block(self):
        with self.assertRaises(EvidenceError):
            self.verify(self.fixture["cases"][2])

    def test_truncated_or_missing_provider_stop_is_not_a_complete_result(self):
        for role in ("input_rail", "retrieval_rail", "main", "output_rail"):
            for stop in ("max_tokens", "stop_sequence", None):
                with self.subTest(role=role, stop=stop), self.assertRaises(EvidenceError):
                    case = deepcopy(self.normal)
                    grant = next(g for g in case["ledgers"]["gateway"]["grants"] if g["role"] == role)
                    grant["evidence"]["stop_reason"] = stop
                    self.verify(case)

    def test_stale_wrong_source_or_wrong_stop_rejected(self):
        for options in ({"now": self.normal["attempt"]["finished_at"] + 901}, {"source_digest": "0" * 64},
                        {"expected_status": 403, "expected_stop": "input_rail"}):
            with self.subTest(options=options), self.assertRaises(EvidenceError):
                self.verify(self.normal, **options)

    def test_incomplete_or_inconsistent_evidence_rejected(self):
        mutations = [
            lambda c: c["ledgers"].pop("privacy"),
            lambda c: c["ledgers"]["privacy"]["calls"].append(deepcopy(c["ledgers"]["privacy"]["calls"][0])),
            lambda c: c["ledgers"]["context"]["calls"][0].update(execution_id="foreign"),
            lambda c: c["ledgers"]["gateway"]["grants"][0].update(state="reserved"),
            lambda c: c["ledgers"]["privacy"].update(closed_at=None),
            lambda c: c["ledgers"]["nemo"].update(service_digest="0" * 64),
            lambda c: c["attempt"]["lifecycle"]["execution"]["calls"][0].update(sequence=True),
            lambda c: c["ledgers"]["context"].update(retrieval_count=True),
            lambda c: c["attempt"]["lifecycle"]["execution"]["result"].update(text_digest="0" * 64),
            lambda c: c["ledgers"]["context"]["calls"][0].update(started=1),
        ]
        for i, mutate in enumerate(mutations):
            with self.subTest(mutation=i), self.assertRaises(EvidenceError):
                case = deepcopy(self.normal)
                mutate(case)
                self.verify(case)

    def test_extra_downstream_after_block_is_rejected(self):
        case = self.fixture["cases"][1]
        next(g for g in case["ledgers"]["gateway"]["grants"] if g["role"] == "main")["state"] = "reserved"
        with self.assertRaises(EvidenceError):
            self.verify(case)

    def test_dataflow_mismatch_even_when_client_and_product_agree(self):
        case = deepcopy(self.normal)
        row = case["ledgers"]["context"]["calls"][2]
        row["input_digest"] = row["evidence"]["input_digest"] = "0" * 64
        call = case["attempt"]["lifecycle"]["execution"]["calls"][4]
        call["input_digest"] = call["evidence"]["input_digest"] = "0" * 64
        with self.assertRaises(EvidenceError):
            self.verify(case)

    def test_helper_does_not_issue_course_verdict(self):
        result = self.verify(self.normal)
        self.assertNotIn("task_completed", result)
        self.assertNotIn("security_verdict", result)

    def test_main_must_use_checked_question_and_retrieved_context(self):
        changes = [{"schema_valid": False}, {"prompt_digest": "0" * 64},
                   {"question_digest": "0" * 64}, {"context_digest": "0" * 64},
                   {"question_bytes": True}, {"context_bytes": 0}]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(EvidenceError):
                case = deepcopy(self.normal)
                main = next(g for g in case["ledgers"]["gateway"]["grants"] if g["role"] == "main")
                main["evidence"]["main_input"].update(change)
                self.verify(case)

    def test_historical_main_without_semantic_binding_is_not_promoted(self):
        case = deepcopy(self.normal)
        main = next(g for g in case["ledgers"]["gateway"]["grants"] if g["role"] == "main")
        main["evidence"].pop("main_input")
        with self.assertRaises(EvidenceError):
            self.verify(case)

    def test_server_owned_original_input_is_mandatory(self):
        original = {"case_id": "normal", "identity": "reader", "tenant": "team-a", "message": "계정 복구"}
        for change in ({"case_id": "other"}, {"identity": "visitor"}, {"tenant": "team-b"},
                       {"message": "다른 질문"}, {"extra": True}):
            with self.subTest(change=change), self.assertRaises(EvidenceError):
                self.verify(self.normal, expected_case={**original, **change})

    def test_consistent_rewritten_question_is_not_original_case(self):
        case = deepcopy(self.normal)
        row = case["ledgers"]["privacy"]["calls"][0]
        row["input_digest"] = row["evidence"]["input_digest"] = "0" * 64
        call = case["attempt"]["lifecycle"]["execution"]["calls"][2]
        call["input_digest"] = call["evidence"]["input_digest"] = "0" * 64
        with self.assertRaises(EvidenceError):
            self.verify(case)


if __name__ == "__main__":
    unittest.main()
