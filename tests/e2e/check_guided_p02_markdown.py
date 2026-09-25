"""Compare the final P02 source and verbatim JSON examples with live evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import re

from p02_markdown import extract_solution


def check(document, evidence):
    source = extract_solution(document).encode("utf-8")
    assert evidence["verified"] is True
    assert evidence["source_digest"] == hashlib.sha256(source).hexdigest()
    response = evidence["response"]
    assert response["task_completed"] is True and response["security_verdict"] == "PASS"
    assert response["result"]["provider_mode"] == "aws"
    assert len(response["result"]["cases"]) == 22
    examples = [json.loads(raw) for raw in re.findall(
        r"^출력 예시:\s*\n```json\n(.*?)\n```", document, re.MULTILINE | re.DOTALL)]
    cases = {row["case_id"]: row for row in response["result"]["cases"]}
    provider = next(row for row in response["result"]["provider_evidence"] if row["case_id"] == "normal-document")
    expected = [cases["normal-document"], provider["ledger"]["calls"][1]["response"], cases["client-key-override"]]
    assert examples == expected, "document outputs differ from the actual execution"
    assert response["result"]["source_digest"] == evidence["source_digest"]
    return {"verified": True, "source_digest": evidence["source_digest"], "exact_output_examples": len(examples)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("markdown", type=Path)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(check(args.markdown.read_text(), json.loads(args.evidence.read_text()))))
