"""Run against installed real Presidio engines; no network, HTTP service, NeMo, or AWS."""
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

SOURCE = Path(__file__).resolve().parents[2] / "llm-security-control-plane/guided-labs/h12-protected-services/privacy.py"
spec = importlib.util.spec_from_file_location("p12_privacy", SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class PrivacyProductTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.boundary = module.PrivacyBoundary()

    def test_normal_text_preserved_in_both_directions(self):
        text = "계정 복구 절차를 안내해 주세요."
        for stage in module.STAGES:
            result = self.boundary.process(stage, text)
            self.assertEqual(result["text"], text)
            self.assertEqual(result["evidence"]["entity_counts"], {})
            self.assertEqual(result["evidence"]["input_digest"], result["evidence"]["output_digest"])

    def test_real_email_and_rrn_detection_and_anonymization(self):
        for text, entity in (("Email: learner@example.com", "EMAIL_ADDRESS"),
                             ("Resident number: 900101-1234568", "KR_RRN")):
            for stage in module.STAGES:
                with self.subTest(stage=stage, entity=entity):
                    result = self.boundary.process(stage, text)
                    self.assertIn(f"<{entity}>", result["text"])
                    self.assertEqual(result["evidence"]["entity_counts"], {entity: 1})
                    self.assertNotEqual(result["evidence"]["input_digest"], result["evidence"]["output_digest"])

    def test_mixed_text_transformed_and_evidence_contains_no_raw_values(self):
        text = "연락 learner@example.com 번호 900101-1234568"
        result = self.boundary.process("input_privacy", text)
        self.assertEqual(result["text"], "연락 <EMAIL_ADDRESS> 번호 <KR_RRN>")
        evidence = result["evidence"]
        self.assertEqual(evidence["input_digest"], hashlib.sha256(text.encode()).hexdigest())
        self.assertEqual(evidence["output_digest"], hashlib.sha256(result["text"].encode()).hexdigest())
        self.assertEqual(evidence["input_bytes"], len(text.encode()))
        serialized = json.dumps(evidence)
        for secret in (text, "learner@example.com", "900101-1234568"):
            self.assertNotIn(secret, serialized)
        self.assertNotIn("task_completed", result)
        self.assertNotIn("security_verdict", result)

    def test_invalid_inputs_do_not_reach_products(self):
        for text in (None, True, {}, "", "  ", "a" * 16001):
            with self.subTest(text_type=type(text).__name__), self.assertRaises(ValueError):
                self.boundary.process("input_privacy", text)
        for stage in ("main", "retrieval", None, []):
            with self.subTest(stage=stage), self.assertRaises(ValueError):
                self.boundary.process(stage, "normal")

    def test_product_exception_is_not_converted_to_success(self):
        from unittest.mock import patch
        with patch.object(self.boundary.analyzer, "analyze", side_effect=RuntimeError("unavailable")):
            with self.assertRaises(RuntimeError):
                self.boundary.process("input_privacy", "normal")

    def test_email_validation_uses_packaged_suffixes_without_http(self):
        from unittest.mock import patch
        with patch("requests.sessions.Session.request", side_effect=AssertionError("HTTP forbidden")) as request:
            boundary = module.PrivacyBoundary()
            result = boundary.process("input_privacy", "Mail: independent@example.com")
        request.assert_not_called()
        self.assertEqual(result["text"], "Mail: <EMAIL_ADDRESS>")

    def test_version_and_input_copy_are_not_mutable_shared_evidence(self):
        first = self.boundary.process("input_privacy", "normal")
        self.assertEqual(first["evidence"]["versions"]["presidio-analyzer"], "2.2.362")
        first["evidence"]["versions"].clear()
        self.assertTrue(self.boundary.process("output_privacy", "normal")["evidence"]["versions"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
