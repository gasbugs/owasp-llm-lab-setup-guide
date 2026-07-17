#!/usr/bin/env python3
"""Build and execute one contracted Podman lab, then emit raw JSONL evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

from lab_contract import ContractError, load_contract, parse_jsonl, validate_evidence, validate_runtime


def run(command: list[str], *, cwd: Path | None = None, capture: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        check=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--setup-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--skip-build", action="store_true")
    args = parser.parse_args()
    if re.fullmatch(r"[A-Za-z0-9._-]{3,100}", args.run_id) is None:
        parser.error("run-id contains unsafe characters")
    root = args.setup_root.resolve()
    try:
        contract = load_contract(args.contract.resolve())
        runtime_issues = validate_runtime(contract, root)
        if runtime_issues:
            raise ContractError("; ".join(runtime_issues))
        runtime = contract["runtime"]
        image = f"{runtime['image']}-loop-{args.run_id[:12].lower()}"
        container = f"{runtime['container_prefix']}-{args.run_id[:24].lower()}"
        source = root / contract["policy"]["source"]
        source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
        print(json.dumps({
            "event": "policy_check", "lab_id": contract["lab_id"],
            "policy_source": contract["policy"]["source"],
            "runtime_activation": contract["policy"]["runtime_activation"],
            "policy_sha256": source_hash,
        }, ensure_ascii=False), flush=True)
        if not args.skip_build:
            run(["podman", "build", "--tag", image, str(root / runtime["build_context"])])
        suite_args = list(runtime["suite_args"])
        by_case = {case["case_id"]: case for case in contract["cases"]}
        for override in runtime["case_overrides"]:
            suite_args.extend([override["option"], by_case[override["case_id"]]["input"]["value"]])
        command = [
            "podman", "run", "--name", container,
            "--network", runtime["network"], image, *suite_args,
        ]
        command_hash = hashlib.sha256(
            json.dumps(command, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        try:
            completed = run(command)
            if completed.stderr:
                print(completed.stderr, file=sys.stderr, end="")
            logs = run(["podman", "logs", container]).stdout
            records = parse_jsonl(logs)
            evidence_issues = validate_evidence(contract, records)
            if evidence_issues:
                raise ContractError("; ".join(evidence_issues))
            print(logs, end="" if logs.endswith("\n") else "\n")
            print(json.dumps({
                "event": "contract_summary", "lab_id": contract["lab_id"],
                "status": "PASS", "case_count": len(contract["cases"]),
                "command_sha256": command_hash,
                "raw_log_sha256": hashlib.sha256(logs.encode("utf-8")).hexdigest(),
                "container": container,
            }, ensure_ascii=False), flush=True)
        finally:
            subprocess.run(
                ["podman", "rm", "--force", container],
                text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
            )
        return 0
    except (ContractError, OSError, subprocess.CalledProcessError) as exc:
        print(json.dumps({"event": "contract_summary", "status": "FAIL", "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
