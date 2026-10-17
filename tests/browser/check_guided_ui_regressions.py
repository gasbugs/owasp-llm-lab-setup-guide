"""Tenant 03 UI gates: real assets, recorded report display, no provider/grade writes."""
import argparse
from contextlib import nullcontext
import json
import os
from pathlib import Path
import subprocess
import sys
from guided_ui_harness import display_server

CHECKS = (
    "check_guided_copy_blocks.py",
    "check_guided_admin_answer_layout.py",
    "check_guided_mission_paths.py",
    "check_guided_case_requests.py",
    "check_guided_case_diagnostics.py",
    "check_guided_case_list_transition.py",
    "check_guided_all_mission_navigation_live.py",
    "check_guided_native_report_restore_live.py",
    "check_guided_information_style_live.py",
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", help="Existing platform; omit for browser-only CI assets")
    parser.add_argument("--reports-dir", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    subprocess.run([sys.executable, str(Path(__file__).resolve().parents[2] / "tools/build_guided_case_catalog.py")], check=True)
    args.output.mkdir(parents=True, exist_ok=True)
    context = nullcontext((args.base_url.rstrip("/"), [])) if args.base_url else display_server()
    results = []
    with context as (origin, _):
        env = {**os.environ, "GUIDED_UI_BASE_URL": origin,
               "GUIDED_UI_ARTIFACTS": str(args.output.resolve())}
        if args.reports_dir:
            env["GUIDED_UI_REPORTS_DIR"] = str(args.reports_dir.resolve())
        for script in CHECKS:
            command = [sys.executable, str(Path(__file__).with_name(script))]
            result = subprocess.run(command, env=env, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, timeout=600)
            (args.output / (Path(script).stem + ".log")).write_text(result.stdout)
            print(result.stdout, end="", flush=True)
            results.append({"check": script, "exit_code": result.returncode})
            if result.returncode:
                raise SystemExit(result.returncode)
    (args.output / "summary.json").write_text(json.dumps({
        "scope": "UI display and restoration only; recorded reports are not fresh model/AWS verification",
        "mode": "existing-platform" if args.base_url else "real-assets-display-server",
        "checks": results,
    }, indent=2))


if __name__ == "__main__":
    main()
