"""Run the exact P01 Markdown solution through actual ASGI grading handlers.

Publisher-only check. Execute in the network-disabled practice test container,
with a read-only course mount. Does not run Markdown shell blocks or call AWS.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "unit"))
import test_guided_p01_pipeline as pipeline


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("markdown", type=Path)
    parser.add_argument("--evidence", type=Path, help="compare published examples with a successful AWS Browser run")
    args = parser.parse_args()
    document = args.markdown.read_text(encoding="utf-8")
    parts = re.split(r"^## \d+\. 풀이.*$", document, flags=re.MULTILINE)
    if len(parts) != 2:
        parser.error("exactly one numbered solution section is required")
    blocks = re.findall(r"^```python\n(.*?)^```$", parts[1], re.MULTILINE | re.DOTALL)
    if len(blocks) != 1:
        parser.error("exactly one complete Python solution is required")
    namespace = {}
    exec(compile(blocks[0], str(args.markdown), "exec"), namespace)
    implementation = namespace.get("handle_request")
    if not callable(implementation):
        parser.error("solution must define handle_request")
    if args.evidence:
        proof = json.loads(args.evidence.read_text())
        assert proof.get("verified") is True and proof.get("provider_mode") == "aws"
        assert hashlib.sha256(blocks[0].encode()).hexdigest() == proof["learner_sha256"]
        response = proof["response"]
        assert response["task_completed"] is True and response["security_verdict"] == "PASS"
        cases = {case["case_id"]: case for case in response["result"]["cases"]}
        assert len(cases) == 21
        examples = [json.loads(block) for block in re.findall(
            r"^출력 예시:\s*\n```json\n(.*?)^```$", parts[1], re.MULTILINE | re.DOTALL)]
        assert {example.get("case_id") for example in examples} == {
            "normal-64", "risk-512", "invalid-bool-limit"}
        assert len(examples) == 3
        for example in examples:
            assert example == cases[example["case_id"]], "published example differs from measured full case"
        print("AWS evidence: exact learner bytes and three complete case examples match", flush=True)

    class MarkdownSolution(pipeline.P01PipelineTests):
        def test_document_solution(self):
            response = self.verify(implementation)
            self.assertEqual(response.status_code, 200, response.text)
            result = response.json()
            self.assertEqual(result["security_verdict"], "PASS", result)
            self.assertTrue(result["task_completed"], result)
            with self.gateway.connect() as database:
                self.assertEqual(database.execute("SELECT COUNT(*) FROM executions").fetchone()[0], 21)
                self.assertEqual(database.execute("SELECT COUNT(*) FROM receipts").fetchone()[0], 7)

    suite = unittest.TestSuite([MarkdownSolution("test_document_solution")])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
