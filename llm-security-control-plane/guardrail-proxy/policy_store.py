"""Persistent active pointer over content-addressed, file-backed policies."""

import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import threading
import time
from uuid import uuid4

import yaml

from policy_bundle import load_bundle, policy_files


class PolicyStore:
    def __init__(self, state_dir: Path, seed_root: Path):
        self.root = state_dir
        self.bundles = state_dir / "bundles"
        self.bundles.mkdir(parents=True, exist_ok=True)
        self.pointer = state_dir / "active.json"
        self.drafts = state_dir / "drafts"
        self.drafts.mkdir(exist_ok=True)
        self.activated = state_dir / "activated"
        self.activated.mkdir(exist_ok=True)
        self._lock = threading.Lock()
        if not self.pointer.exists():
            seed = load_bundle(seed_root)
            destination = self.bundles / seed.digest
            if not destination.exists():
                temporary = Path(tempfile.mkdtemp(prefix=".seed-", dir=self.bundles))
                try:
                    for filename in policy_files(seed_root):
                        target = temporary / filename
                        target.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copyfile(seed_root / filename, target)
                        target.chmod(0o444)
                    (temporary / "nemo-policy").chmod(0o555)
                    temporary.chmod(0o555)
                    os.replace(temporary, destination)
                finally:
                    if temporary.exists():
                        shutil.rmtree(temporary)
            self._write_active(seed.digest)
        self.active = self.load_active()
        self._remember_activation(self.active.digest)
        for metadata_path in self.drafts.glob("*.json"):
            metadata = json.loads(metadata_path.read_text())
            if metadata.get("state") == "active":
                self._remember_activation(metadata["base_digest"])

    def _write_active(self, digest: str):
        temporary = self.root / f".active-{uuid4().hex}.tmp"
        try:
            temporary.write_text(json.dumps({"digest": digest}) + "\n")
            os.replace(temporary, self.pointer)
        finally:
            temporary.unlink(missing_ok=True)

    def _remember_activation(self, digest: str):
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("invalid activated digest")
        marker = self.activated / digest
        if not marker.exists():
            marker.write_text("activated\n")

    def load_active(self):
        pointer = json.loads(self.pointer.read_text())
        if (not isinstance(pointer, dict) or set(pointer) != {"digest"}
                or not isinstance(pointer["digest"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", pointer["digest"])):
            raise ValueError("invalid active policy pointer")
        directory = self.bundles / pointer["digest"]
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError("active policy bundle missing")
        bundle = load_bundle(directory)
        if bundle.digest != pointer["digest"]:
            raise ValueError("active policy digest mismatch")
        return bundle

    def active_input_prompt(self):
        prompts = yaml.safe_load((self.bundles / self.active.digest /
                                  "nemo-policy" / "prompts.yml").read_text())
        matches = [item["content"] for item in prompts["prompts"]
                   if item.get("task") == "self_check_input"]
        if len(matches) != 1:
            raise ValueError("input self-check prompt missing")
        return matches[0]

    def create_draft(self, base_digest: str, version: str, input_prompt: str):
        if (not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version)
                or len(version) > 30 or not 100 <= len(input_prompt) <= 5000
                or input_prompt.count("{{ user_input }}") != 1
                or input_prompt.count("{{") != 1 or input_prompt.count("}}") != 1
                or any(marker in input_prompt for marker in ("{%", "%}", "{#", "#}"))):
            raise ValueError("invalid draft fields")
        with self._lock:
            if base_digest != self.active.digest:
                raise ValueError("active policy changed")
            if version == self.active.policy["version"]:
                raise ValueError("draft version must differ")
            source = self.bundles / base_digest
            temporary = Path(tempfile.mkdtemp(prefix=".draft-", dir=self.bundles))
            try:
                for filename in policy_files(source):
                    target = temporary / filename
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source / filename, target)
                policy_path = temporary / "policy.yaml"
                policy = yaml.safe_load(policy_path.read_text())
                policy["version"] = version
                policy_path.write_text(
                    "# CUSTOM FILE: product policy interpreted by this proxy.\n"
                    + yaml.safe_dump(policy, allow_unicode=True, sort_keys=False))
                prompt_path = temporary / "nemo-policy" / "prompts.yml"
                prompts = yaml.safe_load(prompt_path.read_text())
                matches = [item for item in prompts["prompts"]
                           if item.get("task") == "self_check_input"]
                if len(matches) != 1:
                    raise ValueError("input self-check prompt missing")
                matches[0]["content"] = input_prompt
                prompt_path.write_text(
                    "# CUSTOM FILE\n"
                    "# Format: https://docs.nvidia.com/nemo/guardrails/v0.24.1/user-guides/configuration-guide.html\n"
                    "# Upstream format license: Apache-2.0\n"
                    + yaml.safe_dump(prompts, allow_unicode=True, sort_keys=False))
                bundle = load_bundle(temporary)
                destination = self.bundles / bundle.digest
                if destination.exists():
                    if load_bundle(destination).digest != bundle.digest:
                        raise ValueError("existing draft digest mismatch")
                else:
                    for filename in policy_files(temporary):
                        (temporary / filename).chmod(0o444)
                    (temporary / "nemo-policy").chmod(0o555)
                    temporary.chmod(0o555)
                    os.replace(temporary, destination)
                metadata_path = self.drafts / f"{bundle.digest}.json"
                metadata = {"digest": bundle.digest, "base_digest": base_digest,
                            "version": version, "state": "draft",
                            "created_at": int(time.time())}
                if metadata_path.exists():
                    previous = json.loads(metadata_path.read_text())
                    if previous["base_digest"] != base_digest:
                        raise ValueError("draft base conflict")
                    return previous
                metadata_path.write_text(json.dumps(metadata, sort_keys=True) + "\n")
                return metadata
            finally:
                if temporary.exists():
                    shutil.rmtree(temporary)

    def list_drafts(self):
        records = [json.loads(path.read_text()) for path in sorted(self.drafts.glob("*.json"))]
        for record in records:
            if record["digest"] == self.active.digest:
                record["state"] = "active"
            elif record["state"] == "active":
                record["state"] = "retired"
        return records

    def list_versions(self):
        versions = {record["digest"]: record for record in self.list_drafts()}
        for marker in self.activated.iterdir():
            digest = marker.name
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                continue
            if digest not in versions:
                bundle = load_bundle(self.bundles / digest)
                if bundle.digest != digest:
                    raise ValueError("activated policy digest mismatch")
                versions[digest] = {"digest": digest, "version": bundle.policy["version"],
                                    "state": "active" if digest == self.active.digest else "retired"}
        return sorted(versions.values(), key=lambda record: (record["state"] != "active",
                                                                record["version"]))

    def _write_draft_metadata(self, digest: str, metadata: dict):
        target = self.drafts / f"{digest}.json"
        temporary = self.drafts / f".{digest}-{uuid4().hex}.tmp"
        try:
            temporary.write_text(json.dumps(metadata, sort_keys=True) + "\n")
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)

    def get_draft(self, digest: str):
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("invalid draft digest")
        metadata_path = self.drafts / f"{digest}.json"
        if not metadata_path.is_file():
            raise ValueError("draft missing")
        metadata = json.loads(metadata_path.read_text())
        bundle = load_bundle(self.bundles / digest)
        if metadata["digest"] != digest or bundle.digest != digest:
            raise ValueError("draft digest mismatch")
        return metadata, bundle

    def mark_tested(self, digest: str, expected_active_digest: str, summary: list):
        with self._lock:
            metadata, _bundle = self.get_draft(digest)
            if (self.active.digest != expected_active_digest
                    or metadata["base_digest"] != expected_active_digest):
                raise ValueError("active policy changed")
            if metadata["state"] not in {"draft", "tested"}:
                raise ValueError("draft not testable")
            metadata = {**metadata, "state": "tested", "tested_at": int(time.time()),
                        "test_summary": summary}
            self._write_draft_metadata(digest, metadata)
            return metadata

    def promote(self, digest: str, expected_active_digest: str):
        with self._lock:
            metadata, bundle = self.get_draft(digest)
            if (self.active.digest != expected_active_digest
                    or metadata["base_digest"] != expected_active_digest):
                raise ValueError("active policy changed")
            if (metadata["state"] != "tested"
                    or int(time.time()) - metadata.get("tested_at", 0) > 3600):
                raise ValueError("draft requires recent tests")
            previous = self.active.digest
            self._write_active(digest)
            self.active = bundle
            self._remember_activation(digest)
            metadata = {**metadata, "state": "active", "activated_at": int(time.time())}
            self._write_draft_metadata(digest, metadata)
            return bundle, previous

    def rollback(self, target_digest: str, expected_active_digest: str):
        with self._lock:
            if self.active.digest != expected_active_digest:
                raise ValueError("active policy changed")
            if target_digest == expected_active_digest:
                raise ValueError("target already active")
            if not re.fullmatch(r"[0-9a-f]{64}", target_digest):
                raise ValueError("invalid rollback target")
            if not (self.activated / target_digest).is_file():
                raise ValueError("target was never active")
            bundle = load_bundle(self.bundles / target_digest)
            if bundle.digest != target_digest:
                raise ValueError("rollback digest mismatch")
            previous = self.active.digest
            self._write_active(target_digest)
            self.active = bundle
            return bundle, previous
