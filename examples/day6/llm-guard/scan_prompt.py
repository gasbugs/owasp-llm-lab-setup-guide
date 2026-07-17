#!/usr/bin/env python3
"""Project CLI for prepared LLM Guard cases and learner input overrides.

``--suite`` and ``--case`` are course-project options, not options supplied by
Protect AI LLM Guard itself.  The HTTP server imports the same ``GuardCore``;
scanner policy is not duplicated between the two entry points.
"""

from __future__ import annotations

import argparse
import json
import sys

from llm_guard.util import configure_logger

from guard_core import CASES, GuardCore


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", choices=sorted(CASES))
    parser.add_argument("--suite", action="store_true")
    parser.add_argument(
        "--injection-prompt",
        help="override the prepared prompt-injection case with learner-supplied text",
    )
    args = parser.parse_args(argv)

    configure_logger(log_level="ERROR", stream=sys.stderr)
    core = GuardCore()
    if args.injection_prompt is not None:
        result = core.scan_input("prompt-injection", args.injection_prompt)
        result.update({"case": "prompt-injection", "purpose": "learner input override"})
        print(json.dumps(result, ensure_ascii=False))
        return
    if args.suite:
        results, summary = core.run_suite()
        for result in results:
            print(json.dumps(result, ensure_ascii=False), flush=True)
        print(json.dumps(summary, ensure_ascii=False))
        return
    print(json.dumps(core.run_case(args.case or "prompt-benign"), ensure_ascii=False))


if __name__ == "__main__":
    main()
