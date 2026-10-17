#!/usr/bin/env python3
"""Read-only, narrow ownership audit for Tenant 03 practice reset."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

SETUP = Path(__file__).resolve().parents[1]
PROJECT = "llm-security-guided-course"
SUPPORT = {
    "guided-h06-action-provider", "guided-h09-delivery-sink",
    "guided-h13-promptfoo-target", "guided-h14-target", "guided-h15-target",
    "guided-h20-alertmanager", "guided-h20-grafana-reader",
    "guided-p12-context", "guided-p12-nemo", "guided-p12-privacy",
    "guided-promptfoo-ui", "guided-pyrit-ui",
}
PRESERVE = {
    "guided-control-center", "guided-evidence-verifier", "guided-front-proxy",
    "guided-bedrock-gateway", "guided-alloy", "guided-loki",
    "guided-prometheus", "guided-grafana", "guided-tempo",
    "guided-alertmanager", "guided-nemo-ui",
}


def run(*args):
    return subprocess.check_output(args, text=True, timeout=90).strip()


def main():
    source = SETUP / "tools/check-guided-reset-scope.py"
    spec = importlib.util.spec_from_file_location("guided_scope", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    practice = module.practice_files()
    docker = module.docker_resources()
    aws = module.aws_resources()
    mission = {service for row in practice for service in row["services"]} | SUPPORT
    compose = json.loads(run(
        "docker", "compose", "--env-file", str(SETUP / "llm-security-control-plane/.state/guided-course.env"),
        "-f", str(SETUP / "examples/security-monitoring/compose.guided.yaml"),
        "-f", str(SETUP / "llm-security-control-plane/.state/guided-practice-build.override.yaml"),
        "config", "--format", "json"))
    services = compose["services"]
    if mission - services.keys() or PRESERVE - services.keys() or mission & PRESERVE:
        raise RuntimeError(f"Compose service allowlist mismatch: missing mission={sorted(mission - services.keys())}, missing common={sorted(PRESERVE - services.keys())}, overlap={sorted(mission & PRESERVE)}")
    volumes = {}
    for service, config in services.items():
        for mount in config.get("volumes", []):
            if mount.get("type") == "volume":
                volumes.setdefault(mount["source"], set()).add(service)
    dedicated = {name for name, owners in volumes.items() if owners <= mission}
    if any(name.startswith("guided-control-") or name == "guided-verifier-state" for name in dedicated):
        raise RuntimeError("Common state entered deletion set")
    actual = set(docker["volumes"])
    target_volumes = {f"{PROJECT}_{name}" for name in dedicated}
    inspect = json.loads(run("docker", "inspect", *docker["containers"]))
    live = {}
    for container in inspect:
        labels = container["Config"]["Labels"] or {}
        service = labels.get("com.docker.compose.service")
        if labels.get("com.docker.compose.project") != PROJECT or service not in services:
            raise RuntimeError("Container label is outside Compose project")
        live.setdefault(service, []).append(container["Name"].lstrip("/"))
        for mount in container["Mounts"]:
            if mount["Type"] == "volume" and mount["Name"] in target_volumes and service not in mission:
                raise RuntimeError(f"Mission volume mounted by common service: {service}")
    p00 = Path.home() / "work/control-center-tutorial/request.json"
    if p00.exists() and (p00.is_symlink() or not p00.is_file()):
        raise RuntimeError("P00 request path is not a regular file")
    report = {
        "practice_files": len(practice), "mission_services": sorted(mission),
        "mission_containers": sorted(c for s in mission for c in live.get(s, [])),
        "mission_volumes": sorted(target_volumes & actual),
        "preserved_services": sorted(PRESERVE),
        "preserved_volumes": sorted(actual - target_volumes),
        "p00_request": str(p00) if p00.is_file() else None,
        "aws_account": aws["account"], "aws_region": aws["region"],
        "aws_resources": {k: v for k, v in aws.items() if isinstance(v, list)},
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
