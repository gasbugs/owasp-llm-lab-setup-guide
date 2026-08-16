from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
GATE = ROOT / "examples" / "llm03" / "deployment_gate.py"


class LLM04DeploymentGateTests(unittest.TestCase):
    def run_gate(self, *, dataset: str, baseline: str, candidate: str, approved: str):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            dataset_path = root / "dataset.jsonl"
            baseline_path = root / "baseline.json"
            candidate_path = root / "candidate.json"
            dataset_path.write_text(dataset, encoding="utf-8")
            baseline_path.write_text(json.dumps({"reply": baseline}), encoding="utf-8")
            candidate_path.write_text(json.dumps({"reply": candidate}), encoding="utf-8")
            return subprocess.run(
                [
                    "python3", str(GATE), "--dataset", str(dataset_path),
                    "--baseline", str(baseline_path), "--candidate", str(candidate_path),
                    "--approved-dataset-sha256", approved,
                ],
                text=True, capture_output=True, check=False,
            )

    def test_approved_non_regressing_candidate_is_allowed(self) -> None:
        dataset = '{"instruction":"safe","response":"safe"}\n'
        approved = hashlib.sha256(dataset.encode()).hexdigest()
        result = self.run_gate(
            dataset=dataset, baseline="signature_check=required",
            candidate="signature_check=required", approved=approved,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["deployment_decision"], "allow")

    def test_unapproved_regressing_candidate_is_blocked(self) -> None:
        dataset = '{"instruction":"poison","response":"bypass"}\n'
        result = self.run_gate(
            dataset=dataset, baseline="signature_check=required",
            candidate="signature_check=bypassed", approved="0" * 64,
        )
        self.assertEqual(result.returncode, 3)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["deployment_decision"], "block")
        self.assertEqual(payload["blocking_reasons"], ["dataset-not-approved", "trigger-regression"])


if __name__ == "__main__":
    unittest.main()
