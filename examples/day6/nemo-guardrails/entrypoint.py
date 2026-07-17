#!/usr/bin/env python3
"""Select the preserved NeMo course CLI or the long-running API server."""

from __future__ import annotations

import os
import sys


def main() -> None:
    run_mode = os.getenv("RUN_MODE", "cli").strip().lower()
    args = sys.argv[1:]
    if run_mode == "server" or (args and args[0] == "serve"):
        if args and args[0] == "serve":
            args = args[1:]
        if args:
            raise SystemExit("serve does not accept positional arguments")
        import uvicorn

        uvicorn.run(
            "server:app",
            host=os.getenv("SERVER_HOST", "0.0.0.0"),
            port=int(os.getenv("SERVER_PORT", "8013")),
            log_level="warning",
        )
        return
    from run_demo import main as cli_main

    cli_main(args)


if __name__ == "__main__":
    main()

