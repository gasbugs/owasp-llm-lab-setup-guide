from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools" / "lab_contract.py"
SPEC = importlib.util.spec_from_file_location("lab_contract", MODULE_PATH)
assert SPEC and SPEC.loader
lab_contract = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lab_contract)
CONTRACT_PATH = ROOT / "contracts" / "labs" / "day6-llm-guard.json"


class LabContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = lab_contract.load_contract(CONTRACT_PATH)

    def events(self) -> list[dict]:
        records = []
        for case in self.contract["cases"]:
            event = {field: True for field in case["required_evidence_fields"]}
            event.update({
                "event": "guard_scan",
                "case": case["case_id"],
                "direction": case["direction"],
                "scanner": case["policy"],
                "original_text": lab_contract.materialize_input(case),
                "application_decision": case["expected_decision"],
            })
            if case["direction"] == "output":
                event["input_prompt"] = case["input_prompt"]
            records.append(event)
        return records

    def test_schema_and_runtime_match_canonical_source(self) -> None:
        self.assertEqual(lab_contract.validate_runtime(self.contract, ROOT), [])

    def test_output_case_cannot_be_mislabeled_as_input_attack(self) -> None:
        broken = copy.deepcopy(self.contract)
        case = next(item for item in broken["cases"] if item["case_id"] == "output-secret")
        case["direction"] = "input"
        self.assertTrue(any("masquerade" in issue or "needs input" in issue for issue in lab_contract.validate_structure(broken)))

    def test_missing_original_text_is_detected(self) -> None:
        records = self.events()
        del records[1]["original_text"]
        issues = lab_contract.validate_evidence(self.contract, records)
        self.assertTrue(any("prompt-injection: raw evidence missing original_text" in issue for issue in issues))

    def test_wrong_case_id_is_detected(self) -> None:
        records = self.events()
        records[0]["case"] = "not-the-contract-case"
        self.assertIn("raw evidence case IDs differ from contract", lab_contract.validate_evidence(self.contract, records))

    def test_policy_source_drift_is_detected(self) -> None:
        broken = copy.deepcopy(self.contract)
        broken["policy"]["required_fragments"].append("missing-policy-fragment")
        self.assertTrue(any("missing-policy-fragment" in issue for issue in lab_contract.validate_runtime(broken, ROOT)))

    def test_missing_policy_source_is_detected(self) -> None:
        broken = copy.deepcopy(self.contract)
        broken["policy"]["source"] = "examples/day6/llm-guard/does-not-exist.py"
        self.assertTrue(any("policy source missing" in issue for issue in lab_contract.validate_runtime(broken, ROOT)))

    def test_generated_input_is_exact(self) -> None:
        case = next(item for item in self.contract["cases"] if item["case_id"] == "token-over-limit")
        self.assertEqual(lab_contract.materialize_input(case), "긴 요청 반복 " * 40)

    def test_tampered_runtime_log_hash_is_detected(self) -> None:
        records = self.events()
        lines = [json.dumps({
            "event": "policy_check", "lab_id": self.contract["lab_id"],
            "policy_source": self.contract["policy"]["source"],
        })]
        lines.extend(json.dumps(item) for item in records)
        lines.append(json.dumps({
            "event": "guard_suite_summary", "total_cases": len(records),
        }))
        lines.append(json.dumps({
            "event": "contract_summary", "lab_id": self.contract["lab_id"],
            "status": "PASS", "case_count": len(records),
            "command_sha256": "a" * 64, "raw_log_sha256": "b" * 64,
        }))
        issues = lab_contract.validate_evidence_envelope(
            self.contract, "\n".join(lines) + "\n",
        )
        self.assertIn(
            "contract_summary raw_log_sha256 differs from raw runtime lines", issues,
        )


if __name__ == "__main__":
    unittest.main()
