"""Load one immutable file-backed policy and its native NeMo configuration."""

import asyncio
from dataclasses import dataclass
import hashlib
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

from nemoguardrails import RailsConfig
import yaml

from gateway_model import MODEL_ID


POLICY_FILES = ("policy.yaml", "nemo-policy/config.yml", "nemo-policy/prompts.yml")
OPTIONAL_POLICY_FILES = ("nemo-policy/flows.co",)


def policy_files(root: Path) -> tuple[str, ...]:
    """Include approved Colang in the digest; reject files NeMo could load unseen."""
    nemo = root / "nemo-policy"
    if root.is_symlink() or nemo.is_symlink() or not nemo.is_dir():
        raise ValueError("invalid policy directory")
    for filename in POLICY_FILES:
        path = root / filename
        if path.is_symlink() or not path.is_file():
            raise ValueError("required policy file missing or linked")
    allowed = {Path(name).name for name in POLICY_FILES + OPTIONAL_POLICY_FILES
               if name.startswith("nemo-policy/")}
    for path in nemo.iterdir():
        if path.name not in allowed or path.is_symlink() or not path.is_file():
            raise ValueError("unexpected NeMo policy file")
    return POLICY_FILES + tuple(filename for filename in OPTIONAL_POLICY_FILES
                                if (root / filename).is_file())


@dataclass(frozen=True)
class PolicyBundle:
    digest: str
    policy: Mapping[str, object]
    rails_config: RailsConfig
    limit: asyncio.Semaphore


def load_bundle(root: Path) -> PolicyBundle:
    digest = hashlib.sha256()
    for filename in policy_files(root):
        digest.update(filename.encode() + b"\0" + (root / filename).read_bytes())
    policy = yaml.safe_load((root / "policy.yaml").read_text())
    if (not isinstance(policy, dict) or policy.get("model_id") != MODEL_ID
            or not all(isinstance(policy.get(key), str) and 1 <= len(policy[key]) <= 120
                       for key in ("policy_id", "name", "version"))
            or policy.get("pii_input_action") != "redact"
            or policy.get("pii_output_action") != "redact"
            or policy.get("default_error_action") != "deny"
            or type(policy.get("max_input_chars")) is not int
            or not 1 <= policy["max_input_chars"] <= 4000
            or type(policy.get("max_output_chars")) is not int
            or not 1 <= policy["max_output_chars"] <= 8000
            or type(policy.get("max_concurrent_requests")) is not int
            or not 1 <= policy["max_concurrent_requests"] <= 8):
        raise ValueError("invalid active policy")
    return PolicyBundle(
        digest=digest.hexdigest(),
        policy=MappingProxyType(policy),
        rails_config=RailsConfig.from_path(str(root / "nemo-policy")),
        limit=asyncio.Semaphore(policy["max_concurrent_requests"]),
    )
