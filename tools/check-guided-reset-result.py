#!/usr/bin/env python3
"""Read-only post-reset checks for the Tenant 03 local runtime."""
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tools/guided-practice-files.tsv"
WORKSPACE = Path.home() / "owasp-llm-practice"


def run(*args):
    return subprocess.check_output(args, timeout=90).decode().strip()


def main():
    mismatches = []
    count = 0
    for line in MANIFEST.read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        _mission, source, name, _services = line.split("|")
        expected = subprocess.check_output(["git", "-C", str(ROOT), "show",
            f"HEAD:llm-security-control-plane/{source}"])
        if (WORKSPACE / name).read_bytes() != expected:
            mismatches.append(name)
        count += 1
    database = run("docker", "run", "--rm", "--network", "none", "--user", "0:0",
        "--entrypoint", "python", "-v",
        "llm-security-guided-course_guided-control-progress:/state:ro",
        "localhost/llm-security-guided-control-center:0.1.0", "-c",
        "import sqlite3; db=sqlite3.connect('file:/state/progress.sqlite3?mode=ro',uri=True); "
        "print(db.execute('select count(*) from progress').fetchone()[0], "
        "db.execute('select count(*) from tutorial_completion').fetchone()[0])")
    lines = run("docker", "ps", "-a", "--filter",
        "label=com.docker.compose.project=llm-security-guided-course", "--format", "{{.Names}}|{{.Status}}").splitlines()
    preexisting_stopped = {
        "llm-security-guided-alloy", "llm-security-guided-grafana",
        "llm-security-guided-prometheus", "llm-security-guided-loki",
        "llm-security-guided-tempo", "llm-security-guided-alertmanager",
    }
    one_shot = "llm-security-guided-h20-grafana-reader"
    degraded = []
    for line in lines:
        name, status = line.split("|", 1)
        if name in preexisting_stopped and status.startswith("Exited"):
            continue
        if name == one_shot and status.startswith("Exited (0)"):
            continue
        if not status.startswith("Up") or "(unhealthy)" in status or "Restarting" in status:
            degraded.append(line)
    p00 = Path.home() / "work/control-center-tutorial/request.json"
    backup = sorted((ROOT / ".state").glob("guided-reset-backup-*"))
    report = {"starter_files": count, "mismatches": mismatches, "progress_rows": database,
              "containers": len(lines), "degraded": degraded,
              "preexisting_stopped_common": [line for line in lines if line.split("|", 1)[0] in preexisting_stopped],
              "completed_one_shot": [line for line in lines if line.startswith(one_shot + "|")],
              "p00_request_exists": p00.exists(),
              "reset_backups_remaining": [str(path) for path in backup]}
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if count != 24 or mismatches or database != "0 0" or degraded or p00.exists() or backup:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
