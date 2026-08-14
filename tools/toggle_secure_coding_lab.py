#!/usr/bin/env python3
"""Publisher helper that flips one adjacent learner workshop pair."""
from __future__ import annotations

import argparse
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FILES = {
    "LLM01": ROOT / "docker/vuln-rag/app/secure_coding.py",
    "LLM02": ROOT / "docker/vuln-rag/app/secure_coding.py",
    "LLM04": ROOT / "docker/vuln-rag/app/secure_coding.py",
    "LLM05": ROOT / "docker/vuln-rag/app/templates/index.html",
    "LLM06": ROOT / "docker/vuln-agent/app/main.py",
    "LLM08": ROOT / "docker/vuln-rag/app/secure_coding.py",
    "LLM09": ROOT / "docker/vuln-rag/app/secure_coding.py",
    "LLM10": ROOT / "docker/vuln-rag/app/secure_coding.py",
    "DAY6": ROOT / "examples/day6/presidio/secure_coding.py",
}


def comment(line: str, suffix: str) -> str:
    indent = line[: len(line) - len(line.lstrip())]
    body = line[len(indent) :]
    return f"{indent}{suffix} {body}"


def uncomment(line: str, suffix: str) -> str:
    indent = line[: len(line) - len(line.lstrip())]
    body = line[len(indent) :]
    prefix = f"{suffix} "
    if not body.startswith(prefix):
        raise ValueError(f"expected commented call: {line}")
    return indent + body[len(prefix) :]


def toggle(lab: str, mode: str) -> Path:
    path = FILES[lab]
    lines = path.read_text(encoding="utf-8").splitlines()
    marker = next(index for index, line in enumerate(lines) if f"NODEGOAT-LAB: {lab}" in line)
    vulnerable = next(
        index for index in range(marker + 1, marker + 5) if "VULNERABLE-ACTIVE" in lines[index]
    )
    safe = next(
        index for index in range(marker + 1, marker + 5) if "SAFE-ENABLE" in lines[index]
    )
    suffix = "//" if path.suffix == ".html" else "#"
    vulnerable_is_commented = lines[vulnerable].lstrip().startswith(suffix)
    safe_is_commented = lines[safe].lstrip().startswith(suffix)

    if mode == "safe" and not vulnerable_is_commented and safe_is_commented:
        lines[vulnerable] = comment(lines[vulnerable], suffix)
        lines[safe] = uncomment(lines[safe], suffix)
    elif mode == "vulnerable" and vulnerable_is_commented and not safe_is_commented:
        lines[vulnerable] = uncomment(lines[vulnerable], suffix)
        lines[safe] = comment(lines[safe], suffix)
    elif not (
        (mode == "safe" and vulnerable_is_commented and not safe_is_commented)
        or (mode == "vulnerable" and not vulnerable_is_commented and safe_is_commented)
    ):
        raise ValueError(f"{lab}: invalid or ambiguous pair state")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lab", choices=sorted(FILES), required=True)
    parser.add_argument("--mode", choices=("vulnerable", "safe"), required=True)
    args = parser.parse_args()
    path = toggle(args.lab, args.mode)
    print(f"secure-coding-toggle={args.mode} lab={args.lab} file={path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
