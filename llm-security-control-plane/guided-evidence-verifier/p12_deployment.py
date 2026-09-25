"""Verifier-owned operational P12 settings; no learner answer or write credentials."""
import hashlib
import json
import os
from pathlib import Path

from p12_binding import SCAFFOLD


def load_configuration(environment=None, root=None):
    env = dict(os.environ if environment is None else environment)
    root = Path(root or Path(__file__).parent)
    contract_path = root / "p12.json"
    runner = root / "p12-runner"
    if not contract_path.exists():
        contract_path = root.parent / "guided-contracts/p12.json"
        runner = root.parent / "guided-labs/h12-application-pipeline"
    raw = contract_path.read_bytes()
    if len(raw) > 131072:
        raise ValueError("oversized packaged P12 contract")
    contract = json.loads(raw)
    if (contract.get("format") != "CUSTOM FILE" or contract.get("practice_id") != "P12"
            or contract.get("execution_id") != "H12" or contract.get("contract_version") != 2):
        raise ValueError("invalid packaged P12 contract")
    origins = {name: env.get(f"GUIDED_P12_{name.upper()}_URL", default) for name, default in {
        "context": "http://guided-p12-context:8000", "privacy": "http://guided-p12-privacy:8000",
        "nemo": "http://guided-p12-nemo:8000", "gateway": "http://guided-bedrock-gateway:8080"}.items()}
    tokens = {name: env.get(f"GUIDED_P12_{name.upper()}_VERIFIER_TOKEN", "") for name in origins}
    token = env.get("GUIDED_VERIFIER_LAB12_TOKEN", "")
    credentials = [env.get("GUIDED_CONTROL_VERIFIER_TOKEN", ""), token, *tokens.values()]
    if (any(not isinstance(value, str) or not value or not value.isascii() for value in credentials)
            or len(set(credentials)) != len(credentials)):
        raise ValueError("distinct P12 control and read-only credentials required")
    return {"origin": env.get("GUIDED_LAB12_URL", "http://guided-h12-application-pipeline:8000"),
            "token": token, "origins": origins, "tokens": tokens,
            "specifications": contract["specifications"], "documents": contract["documents"],
            "scaffold_files": {name: hashlib.sha256((runner / name).read_bytes()).hexdigest() for name in SCAFFOLD}}
