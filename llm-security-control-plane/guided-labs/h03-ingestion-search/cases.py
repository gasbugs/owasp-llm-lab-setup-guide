"""Server-owned P03 scenarios, not Browser inputs or learner implementations."""
from copy import deepcopy

CONTRACT_VERSION = "p03-search-v1"


def cases():
    result = [{"case_id": "current-complete", "backend": "provider", "outcome": "ready"}]
    fixtures = [
        ("contract-complete", "ready", "current", "COMPLETE"),
        ("queued", "waiting", "current", "QUEUED"),
        ("starting", "waiting", "current", "STARTING"),
        ("in-progress", "waiting", "current", "IN_PROGRESS"),
        ("different-job", "rejected", "different", "COMPLETE"),
        ("missing-job", "rejected", "missing", "COMPLETE"),
        ("failed", "rejected", "current", "FAILED"),
        ("stopping", "rejected", "current", "STOPPING"),
        ("stopped", "rejected", "current", "STOPPED"),
        ("unknown-status", "rejected", "current", "UNKNOWN"),
        ("null-status", "rejected", "current", None),
        ("number-status", "rejected", "current", 1),
        ("boolean-status", "rejected", "current", True),
        ("array-status", "rejected", "current", []),
        ("object-status", "rejected", "current", {}),
    ]
    result.extend({"case_id": name, "backend": "contract", "outcome": outcome,
                   "observed_job": observed, "status": deepcopy(status)}
                  for name, outcome, observed, status in fixtures)
    result.append({"case_id": "missing-status", "backend": "contract", "outcome": "rejected",
                   "observed_job": "current"})
    result.extend({"case_id": operation + "-error", "backend": "contract", "outcome": "provider_error",
                   "failed_operation": operation, "observed_job": "current", "status": "COMPLETE"}
                  for operation in ("job_status", "retrieve"))
    return result
