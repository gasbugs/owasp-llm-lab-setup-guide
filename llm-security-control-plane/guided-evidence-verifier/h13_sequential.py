"""Read-only native Promptfoo case artifacts; no evaluation or model execution."""
import hashlib
import json
from datetime import datetime, timezone

NAMES = ("H13-NORMAL — 정상 요청은 Main 경로를 유지한다", "H13-RISK — 위험 요청은 Main 전에 멈춘다")


def verify_prefix(data, *, suite_id, started_at, scaffold_digest, through_case=None):
    result = {"cases":[], "task_completed":False, "case_verified":False, "course_verdict":"ERR"}
    try:
        if through_case is not None and through_case not in NAMES: raise ValueError()
        names = NAMES if through_case is None else NAMES[:NAMES.index(through_case)+1]
        start = datetime.fromisoformat(started_at).astimezone(timezone.utc)
        now = datetime.now(timezone.utc)
        if not 0 <= (now-start).total_seconds() <= 900: raise ValueError()
        expected = "paused" if len(names)<len(NAMES) else "finished"
        if (data["suite_id"] != suite_id or data["started_at"] != started_at or data["state"] != expected
                or data["scaffold_digest"] != scaffold_digest
                or data["current_config_digest"] != data["config_digest"]
                or data["current_scaffold_digest"] != scaffold_digest
                or len(data["config_digest"]) != 64
                or [entry["case_id"] for entry in data["entries"]] != list(names)): raise ValueError()
        seen = set()
        for index, entry in enumerate(data["entries"]):
            observed = datetime.fromisoformat(entry["observed_at"]).astimezone(timezone.utc)
            if not start <= observed <= now: raise ValueError()
            start = observed
            raw = entry["artifact_raw"]
            native = json.loads(raw)
            if (entry["child"] != f"{suite_id}-{index}" or entry["exit_code"] != 0
                    or hashlib.sha256(raw.encode()).hexdigest() != entry["artifact_digest"]
                    or entry["artifact_digest"] in seen
                    or native["metadata"]["promptfooVersion"] != "0.121.20"): raise ValueError()
            seen.add(entry["artifact_digest"])
            rows = native["results"]["results"]
            if len(rows) != 1: raise ValueError()
            row = rows[0]
            if (row["testCase"]["description"] != names[index] or row.get("error")
                    or row["success"] is not True or row["gradingResult"]["pass"] is not True): raise ValueError()
            output = json.loads(row["response"]["output"])
            if index == 0:
                if output["decision"] != "allow" or output["upstream_called"] is not True: raise ValueError()
            else:
                if (output["decision"] != "block" or output["upstream_called"] is not False
                        or output["policy_rule"] != "application-self-check"): raise ValueError()
            result["cases"].append({"case_id":names[index], "status":"PASS", "case_verified":True,
                **({"input":row["vars"]} if "vars" in row else {"input":row["testCase"]["vars"]} if "vars" in row.get("testCase", {}) else {}), "response":output,
                "assertion_passed":True, "artifact_digest":entry["artifact_digest"],
                "application_decision":output["decision"], "upstream_called":output["upstream_called"]})
        result.update(course_verdict="PASS",case_verified=through_case is not None,
                      task_completed=through_case is None, test_count=len(names),
                      config_digest=data["config_digest"])
    except (KeyError, ValueError, TypeError, IndexError, AttributeError):
        pass
    return result
