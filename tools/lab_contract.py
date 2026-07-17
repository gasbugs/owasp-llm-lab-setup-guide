#!/usr/bin/env python3
"""Validate lab contracts against setup source and raw JSONL evidence."""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


class ContractError(ValueError):
    pass


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ContractError(f"JSON root must be an object: {path}")
    return value


def materialize_input(case: dict[str, Any]) -> str:
    if case["direction"] == "output":
        return str(case["simulated_model_output"])
    spec = case["input"]
    if spec["kind"] == "literal":
        return str(spec["value"])
    if spec["kind"] == "generated" and spec["generator"] == "repeat":
        return str(spec["value"]) * int(spec["count"])
    raise ContractError(f"unsupported input specification for {case.get('case_id')}")


def validate_structure(contract: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    required = {
        "schema_version", "lab_id", "related_lessons", "policy", "runtime",
        "cases", "book_bindings", "state", "watch_paths",
    }
    missing = sorted(required - set(contract))
    if missing:
        issues.append(f"missing top-level fields: {', '.join(missing)}")
        return issues
    if contract.get("schema_version") != 1:
        issues.append("schema_version must be 1")
    cases = contract.get("cases")
    if not isinstance(cases, list) or not cases:
        return issues + ["cases must be a non-empty array"]
    ids: list[str] = []
    roles: set[str] = set()
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            issues.append(f"cases[{index}] must be an object")
            continue
        case_id = case.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            issues.append(f"cases[{index}].case_id is required")
            continue
        ids.append(case_id)
        roles.add(str(case.get("role")))
        direction = case.get("direction")
        if direction not in {"input", "output"}:
            issues.append(f"{case_id}: direction must be input or output")
        if direction == "input":
            if "input" not in case:
                issues.append(f"{case_id}: input case needs input")
            if "input_prompt" in case or "simulated_model_output" in case:
                issues.append(f"{case_id}: input case cannot masquerade as model output")
        if direction == "output":
            if "input" in case:
                issues.append(f"{case_id}: output case cannot use input payload field")
            if not isinstance(case.get("input_prompt"), str):
                issues.append(f"{case_id}: output case needs input_prompt")
            if not isinstance(case.get("simulated_model_output"), str):
                issues.append(f"{case_id}: output case needs simulated_model_output")
        fields = case.get("required_evidence_fields")
        correlation = case.get("correlation_fields")
        if not isinstance(fields, list) or not fields:
            issues.append(f"{case_id}: required_evidence_fields must be non-empty")
        if not isinstance(correlation, list) or not correlation:
            issues.append(f"{case_id}: correlation_fields must be non-empty")
        elif isinstance(fields, list) and not set(correlation).issubset(set(fields)):
            issues.append(f"{case_id}: correlation fields must also be required evidence")
    if len(ids) != len(set(ids)):
        issues.append("case_id values must be unique")
    if not {"benign", "risk"}.issubset(roles):
        issues.append("every contract needs at least one benign and one risk case")
    bound: list[str] = []
    for binding in contract.get("book_bindings", []):
        if isinstance(binding, dict):
            bound.extend(str(item) for item in binding.get("case_ids", []))
    if sorted(bound) != sorted(ids):
        issues.append("book_bindings must cover every case exactly once")
    overrides = contract.get("runtime", {}).get("case_overrides", [])
    for override in overrides if isinstance(overrides, list) else []:
        if not isinstance(override, dict) or override.get("case_id") not in ids:
            issues.append("runtime case override refers to an unknown case")
    state = contract.get("state", {})
    if state.get("mutation_type") == "read-only" and state.get("reset") is not None:
        issues.append("read-only labs must not invent a reset command")
    return issues


def _safe_eval(node: ast.AST) -> Any:
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Dict):
        return {_safe_eval(k): _safe_eval(v) for k, v in zip(node.keys, node.values)}
    if isinstance(node, ast.List):
        return [_safe_eval(item) for item in node.elts]
    if isinstance(node, ast.Tuple):
        return tuple(_safe_eval(item) for item in node.elts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
        left, right = _safe_eval(node.left), _safe_eval(node.right)
        if isinstance(left, str) and isinstance(right, int) and 0 <= right <= 10000:
            return left * right
        if isinstance(right, str) and isinstance(left, int) and 0 <= left <= 10000:
            return right * left
    raise ContractError(f"unsupported CASES expression: {ast.dump(node, include_attributes=False)}")


def load_python_cases(source: Path) -> dict[str, dict[str, Any]]:
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(target, ast.Name) and target.id == "CASES" for target in targets):
                value = _safe_eval(node.value)
                if isinstance(value, dict):
                    return value
    raise ContractError(f"CASES assignment not found in {source}")


def validate_runtime(contract: dict[str, Any], setup_root: Path) -> list[str]:
    issues = validate_structure(contract)
    if issues:
        return issues
    policy = contract["policy"]
    source = (setup_root / policy["source"]).resolve()
    try:
        source.relative_to(setup_root.resolve())
    except ValueError:
        return ["policy source escapes setup repository"]
    if not source.is_file():
        return [f"policy source missing: {policy['source']}"]
    source_text = source.read_text(encoding="utf-8")
    for fragment in policy["required_fragments"]:
        if fragment not in source_text:
            issues.append(f"policy source missing fragment: {fragment}")
    try:
        runtime_cases = load_python_cases(source)
    except ContractError as exc:
        return issues + [str(exc)]
    contract_cases = {case["case_id"]: case for case in contract["cases"]}
    for stage_name, stage in contract.get("runtime", {}).get("targeted_stages", {}).items():
        unknown = set(stage.get("case_ids", [])) - set(contract_cases)
        if unknown:
            issues.append(
                f"targeted stage {stage_name} has unknown case IDs: {sorted(unknown)}"
            )
    if set(runtime_cases) != set(contract_cases):
        issues.append("setup CASES and contract case IDs differ")
        return issues
    for case_id, expected in contract_cases.items():
        actual = runtime_cases[case_id]
        if actual.get("direction") != expected["direction"]:
            issues.append(f"{case_id}: runtime direction differs from contract")
        if actual.get("scanner") != expected["policy"]:
            issues.append(f"{case_id}: runtime scanner differs from contract")
        if actual.get("text") != materialize_input(expected):
            issues.append(f"{case_id}: runtime input/model output differs from contract")
        if expected["direction"] == "output" and actual.get("prompt") != expected["input_prompt"]:
            issues.append(f"{case_id}: runtime input_prompt differs from contract")
    return issues


def parse_jsonl(text: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ContractError(f"invalid JSONL line {line_number}: {exc}") from exc
        if not isinstance(value, dict):
            raise ContractError(f"JSONL line {line_number} is not an object")
        records.append(value)
    return records


def validate_evidence(contract: dict[str, Any], records: list[dict[str, Any]]) -> list[str]:
    issues = validate_structure(contract)
    event_name = contract["runtime"].get("event_name", "guard_scan")
    events = [item for item in records if item.get("event") == event_name]
    by_case = {str(item.get("case")): item for item in events}
    expected_cases = {case["case_id"]: case for case in contract["cases"]}
    if len(events) != len(by_case):
        issues.append("raw evidence contains duplicate case IDs")
    if set(by_case) != set(expected_cases):
        issues.append("raw evidence case IDs differ from contract")
    for case_id, case in expected_cases.items():
        event = by_case.get(case_id)
        if event is None:
            continue
        for field in case["required_evidence_fields"]:
            if field not in event:
                issues.append(f"{case_id}: raw evidence missing {field}")
        if event.get("direction") != case["direction"]:
            issues.append(f"{case_id}: evidence direction differs")
        if event.get("scanner") != case["policy"]:
            issues.append(f"{case_id}: evidence policy differs")
        if event.get("application_decision") != case["expected_decision"]:
            issues.append(f"{case_id}: evidence decision differs")
        if event.get("original_text") != materialize_input(case):
            issues.append(f"{case_id}: evidence original_text differs")
        if case["direction"] == "output" and event.get("input_prompt") != case["input_prompt"]:
            issues.append(f"{case_id}: evidence input_prompt differs")
    return issues


def validate_evidence_envelope(contract: dict[str, Any], text: str) -> list[str]:
    """Verify policy and summary identities around the raw runtime log lines."""
    parsed: list[tuple[str, dict[str, Any]]] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            parsed.append((line, value))
    issues: list[str] = []
    policies = [value for _, value in parsed if value.get("event") == "policy_check"]
    summaries = [value for _, value in parsed if value.get("event") == "contract_summary"]
    if len(policies) != 1:
        issues.append("raw evidence needs exactly one policy_check")
    else:
        policy = policies[0]
        if policy.get("lab_id") != contract["lab_id"]:
            issues.append("policy_check lab_id differs from contract")
        if policy.get("policy_source") != contract["policy"]["source"]:
            issues.append("policy_check source differs from contract")
    if len(summaries) != 1:
        issues.append("raw evidence needs exactly one contract_summary")
        return issues
    summary = summaries[0]
    if summary.get("status") != "PASS" or summary.get("lab_id") != contract["lab_id"]:
        issues.append("contract_summary identity/status differs from contract")
    if summary.get("case_count") != len(contract["cases"]):
        issues.append("contract_summary case_count differs from contract")
    command_hash = summary.get("command_sha256")
    if not isinstance(command_hash, str) or re.fullmatch(r"[0-9a-f]{64}", command_hash) is None:
        issues.append("contract_summary command_sha256 is invalid")
    event_name = contract["runtime"].get("event_name", "guard_scan")
    runtime_lines = [
        line for line, value in parsed
        if value.get("event") in {event_name, "guard_suite_summary", "lab_suite_summary"}
    ]
    runtime_bytes = (("\n".join(runtime_lines) + "\n") if runtime_lines else "").encode("utf-8")
    actual_log_hash = hashlib.sha256(runtime_bytes).hexdigest()
    if summary.get("raw_log_sha256") != actual_log_hash:
        issues.append("contract_summary raw_log_sha256 differs from raw runtime lines")
    return issues


def load_contract(path: Path) -> dict[str, Any]:
    contract = read_json(path)
    schema = path.parent / "schema.json"
    if schema.is_file():
        try:
            import jsonschema  # type: ignore
        except ImportError:
            pass
        else:
            try:
                jsonschema.Draft202012Validator(read_json(schema)).validate(contract)
            except jsonschema.ValidationError as exc:  # type: ignore[attr-defined]
                raise ContractError(f"JSON Schema validation failed: {exc.message}") from exc
    issues = validate_structure(contract)
    if issues:
        raise ContractError("; ".join(issues))
    return contract


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--setup-root", type=Path, default=Path(__file__).resolve().parents[1])
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate")
    validate.add_argument("paths", nargs="*", type=Path)
    runtime = sub.add_parser("verify-runtime")
    runtime.add_argument("contract", type=Path)
    evidence = sub.add_parser("verify-evidence")
    evidence.add_argument("contract", type=Path)
    evidence.add_argument("jsonl", type=Path)
    args = parser.parse_args()
    root = args.setup_root.resolve()
    try:
        if args.command == "validate":
            paths = args.paths or sorted((root / "contracts" / "labs").glob("*.json"))
            paths = [path for path in paths if path.name != "schema.json"]
            for path in paths:
                contract = load_contract(path)
                issues = validate_runtime(contract, root)
                if issues:
                    raise ContractError(f"{path}: {'; '.join(issues)}")
                print(f"PASS {contract['lab_id']} {path}")
            return 0
        contract = load_contract(args.contract)
        if args.command == "verify-runtime":
            issues = validate_runtime(contract, root)
        else:
            raw_text = args.jsonl.read_text(encoding="utf-8")
            records = parse_jsonl(raw_text)
            issues = validate_evidence(contract, records)
            issues.extend(validate_evidence_envelope(contract, raw_text))
        if issues:
            raise ContractError("; ".join(issues))
        print(f"PASS {contract['lab_id']} {args.command}")
        return 0
    except (ContractError, OSError) as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
