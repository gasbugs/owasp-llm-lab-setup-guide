"""Publisher-only live normal/risk matrix; prints no prompt or token content."""

import argparse
import json
import os
from pathlib import Path
import time
import urllib.error
import urllib.request

from policy_cases import QUALITY_CASES


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.repeats <= 5:
        parser.error("repeats must be between 1 and 5")
    token = os.environ["PROXY_CALLER_TOKEN"]
    policy_request = urllib.request.Request(
        args.base_url.rstrip("/") + "/v1/policy",
        headers={"Authorization": "Bearer " + token},
    )
    with urllib.request.urlopen(policy_request, timeout=10) as response:
        active_digest = json.load(response)["digest"]
    results = []
    for repeat in range(1, args.repeats + 1):
        for case_id, expected, message in QUALITY_CASES:
            request = urllib.request.Request(
                args.base_url.rstrip("/") + "/v1/chat", method="POST",
                headers={"Authorization": "Bearer " + token,
                         "Content-Type": "application/json"},
                data=json.dumps({"message": message}).encode(),
            )
            started = time.monotonic()
            try:
                with urllib.request.urlopen(request, timeout=210) as response:
                    status, result = response.status, json.load(response)
            except urllib.error.HTTPError as error:
                status, result = error.code, json.load(error)
            except urllib.error.URLError:
                status, result = None, {"decision": "ERR"}
            observed = {"repeat": repeat, "case": case_id, "expected": expected,
                        "http": status, "decision": result.get("decision"),
                        "stopped_at": result.get("stopped_at"),
                        "upstream_called": result.get("upstream_called"),
                        "main_completed": result.get("main_completed"),
                        "policy_digest": result.get("policy_digest"),
                        "elapsed_s": round(time.monotonic() - started, 2)}
            observed["matched"] = (status == 200 and observed["decision"] == expected
                                   and observed["upstream_called"] is (expected == "allow")
                                   and observed["main_completed"] is (expected == "allow")
                                   and observed["policy_digest"] == active_digest)
            results.append(observed)
            print(repeat, case_id, observed["decision"], observed["matched"], flush=True)
    args.output.write_text(json.dumps(results, ensure_ascii=False, indent=2) + "\n")
    matched = sum(item["matched"] for item in results)
    print("matched", matched, "of", len(results), "output", args.output)
    return 0 if matched == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
