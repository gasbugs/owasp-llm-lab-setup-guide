#!/usr/bin/env python3
"""Validate adjacent NodeGoat-style vulnerable/safe learner switches."""
from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
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


def main() -> int:
    errors: list[str] = []
    for lab, path in EXPECTED.items():
        lines = path.read_text(encoding="utf-8").splitlines()
        markers = [index for index, line in enumerate(lines) if f"NODEGOAT-LAB: {lab}" in line]
        if len(markers) != 1:
            errors.append(f"{lab}: expected one marker in {path.relative_to(ROOT)}")
            continue
        window = lines[markers[0] + 1 : markers[0] + 5]
        vulnerable = [line for line in window if "VULNERABLE-ACTIVE" in line]
        safe = [line for line in window if "SAFE-ENABLE" in line]
        if len(vulnerable) != 1 or len(safe) != 1:
            errors.append(f"{lab}: adjacent vulnerable/safe calls missing")
            continue
        vulnerable_index = window.index(vulnerable[0])
        safe_index = window.index(safe[0])
        if safe_index != vulnerable_index + 1:
            errors.append(f"{lab}: safe call must be immediately below vulnerable call")
        if re.match(r"^\s*#", vulnerable[0]):
            errors.append(f"{lab}: vulnerable baseline must be active")
        if not re.match(r"^\s*(#|//)", safe[0]):
            errors.append(f"{lab}: safe baseline must be commented")
    if errors:
        print("\n".join(f"FAIL {error}" for error in errors))
        return 1
    print(f"secure-coding-pairs=PASS labs={len(EXPECTED)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
