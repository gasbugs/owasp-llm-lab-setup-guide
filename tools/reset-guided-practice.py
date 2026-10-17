#!/usr/bin/env python3
"""Local, fixed-scope reset of Tenant 03 learner work after ownership audit."""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
CONTROL = ROOT / "llm-security-control-plane"
COMPOSE = ROOT / "examples/security-monitoring/compose.guided.yaml"
ENV = CONTROL / ".state/guided-course.env"
OVERRIDE = CONTROL / ".state/guided-practice-build.override.yaml"
PROGRESS_VOLUME = "llm-security-guided-course_guided-control-progress"
CONTROL_IMAGE = "localhost/llm-security-guided-control-center:0.1.0"


def run(*args, capture=False):
    return subprocess.run(args, check=True, text=True,
                          stdout=subprocess.PIPE if capture else None).stdout


def compose(*args):
    return run("docker", "compose", "--env-file", str(ENV), "-f", str(COMPOSE),
               "-f", str(OVERRIDE), *args)


def load_audit():
    path = ROOT / "tools/check-guided-reset-ownership.py"
    spec = importlib.util.spec_from_file_location("guided_reset_audit", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    report = json.loads(run(sys.executable, str(path), capture=True))
    return module, report


def stop_checked_container(name):
    run("docker", "stop", name)


def delete_mission_aws():
    # The Gateway already owns account, resource names, idle-job checks and absence validation.
    caller = """import json,os,sys,urllib.request
problem,operation=sys.argv[1:]
key={'P02':'GUIDED_LAB02_PROVISION_TOKEN','P03':'GUIDED_LAB03_PROVISION_TOKEN','P04':'GUIDED_LAB04_PROVISION_TOKEN'}[problem]
body=json.dumps({'operation_id':operation}).encode()
request=urllib.request.Request('http://127.0.0.1:8080/v1/resource-lifecycle/'+problem+'/delete',
    data=body,headers={'Authorization':'Bearer '+os.environ[key],'Content-Type':'application/json'},method='POST')
with urllib.request.urlopen(request,timeout=480) as response:
    print(response.read().decode())
"""
    for problem in ('P02', 'P03', 'P04'):
        operation = str(uuid.uuid4())
        result = json.loads(run('docker', 'exec', 'llm-security-guided-bedrock-gateway',
                                'python', '-c', caller, problem, operation, capture=True))
        if result.get('practice_id') != problem or result.get('operation_id') != operation or result.get('state') != 'deleted':
            raise RuntimeError(f'{problem} AWS deletion response mismatch')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirm")
    args = parser.parse_args()
    audit, report = load_audit()
    if not args.execute:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return
    if args.confirm != "RESET TENANT 03":
        parser.error("--confirm 'RESET TENANT 03' is required")
    if any(report["aws_resources"].values()):
        delete_mission_aws()
        _, report = load_audit()
        if any(report["aws_resources"].values()):
            raise RuntimeError("Mission AWS resources remain after audited deletion")
    practice = importlib.util.spec_from_file_location(
        "guided_scope", ROOT / "tools/check-guided-reset-scope.py")
    scope = importlib.util.module_from_spec(practice)
    practice.loader.exec_module(scope)
    files = scope.practice_files()
    sources = {}
    for line in (ROOT / "tools/guided-practice-files.tsv").read_text().splitlines():
        if line and not line.startswith("#"):
            _mission, source, name, _services = line.split("|")
            sources[name] = source
    backup = ROOT / ".state" / ("guided-reset-backup-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    backup.mkdir(parents=True, exist_ok=False)
    for row in files:
        shutil.copy2(row["path"], backup / Path(row["path"]).name)
    p00 = report["p00_request"]
    if p00:
        shutil.copy2(p00, backup / "P00-request.json")
    print(f"Recoverable input snapshot: {backup}", flush=True)
    services = report["mission_services"]
    try:
        stop_checked_container("llm-security-guided-control-center")
        stop_checked_container("llm-security-guided-evidence-verifier")
        # A learner may create P00 after the ownership preview. Capture the
        # final file only after the server is stopped, then remove it.
        p00_path = Path.home() / "work/control-center-tutorial/request.json"
        if p00_path.exists():
            if p00_path.is_symlink() or not p00_path.is_file():
                raise RuntimeError("P00 request path is not a regular file")
            shutil.copy2(p00_path, backup / "P00-request.json")
            p00_path.unlink()
        for container in report["mission_containers"]:
            run("docker", "rm", "-f", container)
        for volume in report["mission_volumes"]:
            run("docker", "volume", "rm", volume)
        for row in files:
            name = Path(row["path"])
            data = subprocess.check_output(["git", "-C", str(ROOT), "show",
                f"HEAD:llm-security-control-plane/{sources[name.name]}"])
            temporary = name.with_name(name.name + ".reset-new")
            temporary.write_bytes(data)
            temporary.chmod(0o644)
            os.replace(temporary, name)
        clear = ("import sqlite3,uuid; db=sqlite3.connect('/state/progress.sqlite3'); "
                 "db.execute('DELETE FROM progress'); "
                 "db.execute('DELETE FROM tutorial_completion'); "
                 "db.execute(\"INSERT INTO installation_meta(key,value) VALUES('reset_generation',?) "
                 "ON CONFLICT(key) DO UPDATE SET value=excluded.value\",(uuid.uuid4().hex,)); "
                 "db.commit()")
        run("docker", "run", "--rm", "--network", "none", "--user", "0:0",
            "--entrypoint", "python", "-v", f"{PROGRESS_VOLUME}:/state:rw",
            CONTROL_IMAGE, "-c", clear)
        run("bash", str(ROOT / "tools/prepare-guided-practice-build.sh"))
        compose("build", *services)
        compose("up", "-d", "--no-deps", "--force-recreate", *services)
    finally:
        compose("up", "-d", "--no-deps", "guided-evidence-verifier", "guided-control-center")
    shutil.rmtree(backup)
    print("Reset complete; verify zero progress, Starter digests, and service health.")


if __name__ == "__main__":
    main()
