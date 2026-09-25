"""Root metadata integrity contracts; synthetic receipts are not product evidence."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "llm-security-control-plane/guided-evidence-verifier"))
from p12_binding import SCAFFOLD, validate_run_binding
from p12_results import EvidenceError


class BindingTests(unittest.TestCase):
    def setUp(self):
        self.scaffold = {name: hashlib.sha256(name.encode()).hexdigest() for name in SCAFFOLD}
        self.files = {**self.scaffold, "pipeline.py": "a" * 64}
        self.build = {"files": self.files, "contract_digest": "b" * 64,
                      "source_digest": hashlib.sha256(json.dumps(self.files, sort_keys=True).encode()).hexdigest()}
        self.suite = str(uuid4())
        self.ids = ["normal", "denied"]
        attempts = []
        for index, name in enumerate(self.ids):
            suite, execution = str(uuid4()), str(uuid4())
            attempts.append({"case_id": name, "suite_id": suite, "execution_id": execution,
                "started_at": 101 + index * 2, "finished_at": 102 + index * 2,
                "lifecycle": {"suite_id": suite, "execution_id": execution, "lifecycle_status": "finished",
                              "execution": {"source_digest": self.files["pipeline.py"]}}})
        self.receipt = {"practice_id": "P12", "execution_id": "H12", "contract_version": 2,
                        "suite_id": self.suite, "run_state": "finished", "started_at": 100,
                        "finished_at": 105, "build": deepcopy(self.build), "cases": attempts}
        self.info = {"practice_id": "P12", "contract_version": 2, "case_ids": list(self.ids),
                     "build": deepcopy(self.build), "current_build": deepcopy(self.build)}

    def verify(self, **kwargs):
        return validate_run_binding(self.receipt, self.info, **{"suite_id": self.suite,
            "case_ids": self.ids, "contract_digest": "b" * 64, "scaffold_files": self.scaffold,
            "now": 106, **kwargs})

    def test_bound_run_is_not_a_completion_verdict(self):
        result = self.verify()
        self.assertTrue(result["run_bound"])
        self.assertNotIn("task_completed", result)
        self.assertNotIn("security_verdict", result)

    def test_different_learner_code_is_allowed_when_consistently_bound(self):
        self.files["pipeline.py"] = "c" * 64
        self.build["source_digest"] = hashlib.sha256(json.dumps(self.files, sort_keys=True).encode()).hexdigest()
        self.receipt["build"] = deepcopy(self.build)
        self.info["build"] = self.info["current_build"] = deepcopy(self.build)
        for attempt in self.receipt["cases"]:
            attempt["lifecycle"]["execution"]["source_digest"] = "c" * 64
        self.assertTrue(self.verify()["run_bound"])

    def test_root_metadata_mutations_are_rejected(self):
        changes = [{"practice_id": "P11"}, {"execution_id": "P12"}, {"contract_version": True},
                   {"suite_id": str(uuid4())}, {"run_state": "running"}, {"run_state": "error"},
                   {"finished_at": None}, {"finished_at": float("nan")}, {"started_at": True},
                   {"started_at": 104}, {"finished_at": 107}]
        baseline = deepcopy(self.receipt)
        for change in changes:
            with self.subTest(change=change), self.assertRaises(EvidenceError):
                self.receipt = {**deepcopy(baseline), **change}
                self.verify()

    def test_missing_duplicate_reordered_foreign_children_are_rejected(self):
        original = deepcopy(self.receipt)
        mutations = [lambda a: a.pop(), lambda a: a.append(deepcopy(a[0])), lambda a: a.reverse(),
            lambda a: a[1].update(suite_id=a[0]["suite_id"]),
            lambda a: a[0].update(execution_id=self.suite),
            lambda a: a[1].update(started_at=101),
            lambda a: a[0]["lifecycle"].update(execution_id=str(uuid4())),
            lambda a: a[0]["lifecycle"]["execution"].update(source_digest="d" * 64)]
        for mutate in mutations:
            with self.subTest(mutation=mutate), self.assertRaises(EvidenceError):
                self.receipt = deepcopy(original)
                mutate(self.receipt["cases"])
                self.verify()

    def test_expected_contract_scaffold_and_age_are_external(self):
        for override in ({"contract_digest": "c" * 64}, {"scaffold_files": {}},
                         {"scaffold_files": {**self.scaffold, "workflow.py": "c" * 64}},
                         {"case_ids": ["normal"]}, {"now": 1006}, {"suite_id": "bad"}):
            with self.subTest(override=override), self.assertRaises(EvidenceError):
                self.verify(**override)

    def test_source_changed_after_execution_is_rejected(self):
        self.info["current_build"]["files"]["pipeline.py"] = "c" * 64
        with self.assertRaises(EvidenceError):
            self.verify()


if __name__ == "__main__":
    unittest.main()
