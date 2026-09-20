"""Run the production admission policy with synthetic usage and no model calls."""

import hashlib
import json
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "llm-security-control-plane/bedrock-gateway"))
from gateway_operations import GatewayOperations, PolicyDenied

with tempfile.TemporaryDirectory() as folder:
    path = Path(folder)
    policy = {"window_seconds": 3600, "clients": {
        "training": {"credential_sha256": hashlib.sha256(b"synthetic-fixture-only").hexdigest(),
                     "models": ["us.amazon.nova-lite-v1:0"], "requests": 2,
                     "output_tokens": 120, "max_output_tokens": 120, "max_input_bytes": 4096}}}
    (path / "policy.json").write_text(json.dumps(policy))
    operations = GatewayOperations(str(path / "policy.json"), str(path / "usage.db"), lambda: 3600)
    reservation = operations.admit("training", "us.amazon.nova-lite-v1:0", "안내", 120)
    print(json.dumps({"stage": "reserved", "committed": operations.usage("training")["output_committed"], "model_called": False}))
    operations.settle(reservation, 7, 20)
    print(json.dumps({"stage": "synthetic-settlement", "committed": operations.usage("training")["output_committed"], "model_called": False}))
    try:
        operations.admit("training", "us.amazon.nova-lite-v1:0", "안내", 120)
    except PolicyDenied as exc:
        print(json.dumps({"stage": "over-budget", "reason": exc.reason, "status": exc.status, "model_called": False}))
    resumed = GatewayOperations(str(path / "policy.json"), str(path / "usage.db"), lambda: 3600)
    print(json.dumps({"stage": "reopened", "usage": resumed.usage("training"), "model_called": False}))
