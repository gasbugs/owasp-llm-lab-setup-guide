#!/usr/bin/env python3
"""Course CLI for prepared Presidio cases and learner-supplied text."""

from __future__ import annotations

import argparse
import json

from presidio_core import CASES, PresidioCore


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", choices=sorted(CASES))
    parser.add_argument("--suite", action="store_true")
    parser.add_argument("--text", help="analyze learner-supplied text")
    parser.add_argument(
        "--email-text",
        help="publisher override for the prepared input-email suite case",
    )
    parser.add_argument("--direction", choices=("input", "output"), default="input")
    parser.add_argument("--prompt", default="Learner supplied output candidate")
    args = parser.parse_args(argv)

    core = PresidioCore()
    if args.text is not None:
        if args.direction == "output":
            result = core.scan_output(args.prompt, args.text)
        else:
            result = core.scan_input(args.text)
        result.update({"case": "learner-override", "purpose": "learner input override"})
        print(json.dumps(result, ensure_ascii=False))
        return
    if args.suite:
        overrides = {"input-email": args.email_text} if args.email_text is not None else None
        results, summary = core.run_suite(text_overrides=overrides)
        for result in results:
            print(json.dumps(result, ensure_ascii=False), flush=True)
        print(json.dumps(summary, ensure_ascii=False))
        return
    print(json.dumps(core.run_case(args.case or "input-clean"), ensure_ascii=False))


if __name__ == "__main__":
    main()
