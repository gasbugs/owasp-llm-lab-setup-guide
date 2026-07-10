#!/usr/bin/env python3
"""Run one command in its own process group with timeout and signal cleanup."""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys


class Interrupted(Exception):
    def __init__(self, signum: int) -> None:
        super().__init__(signum)
        self.signum = signum


def _interrupt(signum: int, _frame: object) -> None:
    raise Interrupted(signum)


def _terminate_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    for signum, wait_seconds in (
        (signal.SIGINT, 20),
        (signal.SIGTERM, 10),
        (signal.SIGKILL, None),
    ):
        try:
            os.killpg(process.pid, signum)
        except ProcessLookupError:
            return
        if wait_seconds is None:
            process.wait()
            return
        try:
            process.wait(timeout=wait_seconds)
            return
        except subprocess.TimeoutExpired:
            continue


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("timeout_seconds", type=int)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not 1 <= args.timeout_seconds <= 7200:
        parser.error("timeout_seconds must be from 1 through 7200")
    if not args.command:
        parser.error("a command is required")

    process = subprocess.Popen(args.command, start_new_session=True)
    signal.signal(signal.SIGTERM, _interrupt)
    signal.signal(signal.SIGHUP, _interrupt)
    try:
        return process.wait(timeout=args.timeout_seconds)
    except subprocess.TimeoutExpired:
        print(
            f"ERROR: command exceeded {args.timeout_seconds}s deadline: "
            f"{args.command[0]}",
            file=sys.stderr,
        )
        _terminate_group(process)
        return 124
    except KeyboardInterrupt:
        _terminate_group(process)
        return 130
    except Interrupted as exc:
        _terminate_group(process)
        return 128 + exc.signum


if __name__ == "__main__":
    raise SystemExit(main())
