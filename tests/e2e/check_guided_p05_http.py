"""Exercise the reused H05 ASGI service and native NeMo; no AWS or deployment writes.

Run inside the H05 image with --network none. The solution variant mounts only
the publisher flows.co read-only; the Starter image itself contains no solution.
This checks the learner service, not a whole Compose or Browser deployment.
"""
import argparse
from datetime import datetime, timezone
import json
import os
import sys
from uuid import uuid4

from fastapi.testclient import TestClient


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--variant", choices=("starter", "solution"), required=True)
    args = parser.parse_args()
    os.environ.setdefault("GUIDED_CONTROL_LAB05_TOKEN", "local-publisher-control")
    os.environ.setdefault("GUIDED_VERIFIER_LAB05_TOKEN", "local-publisher-verifier")
    os.environ.setdefault("OPENAI_API_KEY", "dialog-does-not-call-a-model")
    sys.path.insert(0, "/app/learner")
    import server

    headers = {"Authorization": "Bearer " + os.environ["GUIDED_CONTROL_LAB05_TOKEN"]}
    reader = {"Authorization": "Bearer " + os.environ["GUIDED_VERIFIER_LAB05_TOKEN"]}
    cases = []
    with TestClient(server.app) as client:
        assert client.get("/readyz").status_code == 200
        build = client.get("/v1/build-info", headers=reader).json()
        for case_id in server.CASES:
            execution = str(uuid4())
            response = client.post("/v1/run", headers=headers, json={
                "execution_id": execution, "started_at": datetime.now(timezone.utc).isoformat(),
                "case_id": case_id})
            assert response.status_code == 200, response.text
            saved = client.get("/v1/receipts/" + execution, headers=reader)
            assert saved.status_code == 200, saved.text
            record = saved.json()
            assert record["source_digest"] == build["source_digest"]
            assert record["llm_calls_count"] == 0
            cases.append(record)
        for record in cases[:2]:
            assert "security@example.com" in record["bot_message"]
        assert cases[3]["bot_intent"] == "refuse unsupported request"
        exposed = "GUIDED-H05-RECOVERY-CODE" in cases[2]["bot_message"]
        assert exposed == (args.variant == "starter")
        if args.variant == "solution":
            assert cases[2]["bot_intent"] == "refuse recovery code"
        response = client.post("/v1/evaluate", headers=headers, json={
            "suite_id": str(uuid4()), "started_at": datetime.now(timezone.utc).isoformat()})
        assert response.status_code == 200, response.text
        evaluation = client.get("/v1/evaluations/" + response.json()["evaluation_id"],
                                headers=reader).json()
        assert evaluation["processed_samples"] == evaluation["total_samples"] == 2
        assert all(evaluation[key] == 0 for key in
                   ("intent_errors", "bot_intent_errors", "bot_message_errors"))
    print(json.dumps({"scope": "learner ASGI and native NeMo; not full platform grading",
                      "variant": args.variant, "build": build, "cases": cases,
                      "evaluation": evaluation}, ensure_ascii=False))


if __name__ == "__main__":
    main()
