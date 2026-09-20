"""Create a new, private local policy workspace without replacing existing state."""

import hashlib
import json
import os
from pathlib import Path
import secrets

credentials_dir = Path.home() / ".config" / "owasp-runtime-aws"
if not (credentials_dir / "credentials").is_file() or not (credentials_dir / "config").is_file():
    raise SystemExit("Prepare isolated runtime credentials before creating the Gateway workspace.")

state = Path(".state")
state.mkdir(mode=0o700, exist_ok=True)
if (state / "runtime.env").exists() or (state / "policy.json").exists():
    raise SystemExit("Existing runtime state preserved; inspect it before making changes.")
os.umask(0o077)
clients = {}
env = {"AWS_PROFILE": "default", "AWS_CREDENTIALS_DIR": str(credentials_dir), "AWS_REGION": "us-east-1",
       "LOCAL_UID": str(os.getuid()), "LOCAL_GID": str(os.getgid())}
for name, variable, requests, budget in [("team-a", "TEAM_A_TOKEN", 2, 240),
                                        ("team-b", "TEAM_B_TOKEN", 8, 120)]:
    token = secrets.token_hex(32)
    env[variable] = token
    clients[name] = {"credential_sha256": hashlib.sha256(token.encode()).hexdigest(),
                     "models": ["us.amazon.nova-lite-v1:0"], "requests": requests,
                     "output_tokens": budget, "max_output_tokens": 120, "max_input_bytes": 4096}
env["BEDROCK_GATEWAY_TOKEN"] = secrets.token_hex(32)
policy = {"_format": "CUSTOM FILE: project Gateway operations policy", "window_seconds": 3600, "clients": clients}
(state / "policy.json").write_text(json.dumps(policy, indent=2) + "\n")
(state / "runtime.env").write_text("".join(f"{key}={value}\n" for key, value in env.items()))
(state / "ledger").mkdir(mode=0o700, exist_ok=True)
print(json.dumps({"state": ".state", "principals": list(clients), "secrets_printed": False}))
