#!/usr/bin/env python3
"""Project CLI for prepared NeMo Guardrails rail cases.

``--suite`` and ``--case`` are course-project options, not NVIDIA NeMo
Guardrails CLI options.  The HTTP API imports the same ``nemo_core`` module.
"""

from __future__ import annotations

import argparse
import asyncio
import json

from nemo_core import CASES, run_case, run_suite


async def async_main(args: argparse.Namespace) -> None:
    if args.suite:
        results, summary = await run_suite()
        for result in results:
            print(json.dumps(result, ensure_ascii=False), flush=True)
        print(json.dumps(summary, ensure_ascii=False))
        return
    print(json.dumps(await run_case(args.case), ensure_ascii=False))


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", choices=sorted(CASES), default="input-benign")
    parser.add_argument("--suite", action="store_true")
    asyncio.run(async_main(parser.parse_args(argv)))


if __name__ == "__main__":
    main()
