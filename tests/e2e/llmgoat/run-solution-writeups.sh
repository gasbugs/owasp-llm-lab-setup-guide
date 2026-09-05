#!/bin/bash
# Instructor-only strict runner for the ten learner writeup paths.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/run_solution_writeups.py"
