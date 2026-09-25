#!/usr/bin/env python3
"""Compare resolved Compose deployments without starting services or logging secrets."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys


def render(files: list[str], env_file: str | None) -> dict:
    command = ["docker", "compose", "--env-file", env_file or "/dev/null"]
    for file in files:
        command.extend(["--file", file])
    # Service env_file values do not affect Compose topology; do not load runtime secrets.
    # CLI --env-file still supplies interpolation used by ports and resource names.
    command.extend(["config", "--no-env-resolution", "--format", "json"])
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    if result.returncode:
        # Neither stderr nor the rendered document is safe to print: both may contain secrets.
        raise ValueError(f"Compose config failed (exit {result.returncode}); check the supplied configuration")
    return json.loads(result.stdout)


def port_numbers(document: dict) -> dict[int, list[str]]:
    ports: dict[int, list[str]] = {}
    for name, service in document.get("services", {}).items():
        for port in service.get("ports", []):
            published = str(port.get("published", ""))
            if not published:
                raise ValueError(f"{name}: random published port is not allowed")
            bounds = published.split("-")
            if len(bounds) > 2 or not all(value.isdigit() for value in bounds):
                raise ValueError(f"{name}: invalid published port")
            first, last = int(bounds[0]), int(bounds[-1])
            if not 1 <= first <= last <= 65535:
                raise ValueError(f"{name}: invalid published port range")
            # Course policy reserves the number across all addresses and protocols.
            for number in range(first, last + 1):
                ports.setdefault(number, []).append(name)
    return ports


def resource_names(document: dict, kind: str) -> set[str]:
    return {str(value["name"]) for value in document.get(kind, {}).values() if value and value.get("name")}


def bind_mounts(document: dict) -> list[tuple[str, Path, bool]]:
    return [
        (name, Path(mount["source"]).resolve(), not mount.get("read_only", False))
        for name, service in document.get("services", {}).items()
        for mount in service.get("volumes", [])
        if mount.get("type") == "bind"
    ]


def check_isolation(tenant02: dict, tenant03: dict) -> list[str]:
    errors = []
    if tenant02.get("name") == tenant03.get("name"):
        errors.append("Compose project names overlap")
    for kind in ("networks", "volumes"):
        if resource_names(tenant02, kind) & resource_names(tenant03, kind):
            errors.append(f"{kind}: Docker resource names overlap")
    names02 = {s["container_name"] for s in tenant02["services"].values() if s.get("container_name")}
    names03 = {s["container_name"] for s in tenant03["services"].values() if s.get("container_name")}
    if names02 & names03:
        errors.append("container names overlap")
    ports02, ports03 = port_numbers(tenant02), port_numbers(tenant03)
    for port in sorted(ports02.keys() & ports03.keys()):
        errors.append(f"host port {port}: 02 {','.join(ports02[port])} / 03 {','.join(ports03[port])}")
    for port, owners in ports03.items():
        if len(owners) > 1:
            errors.append(f"03 host port {port}: duplicate listeners ({','.join(owners)})")
    for name, service in tenant03["services"].items():
        if service.get("network_mode"):
            errors.append(f"03 {name}: network_mode bypasses the dedicated network contract")
        if not service.get("networks"):
            errors.append(f"03 {name}: no dedicated network")
        if service.get("external_links"):
            errors.append(f"03 {name}: external_links are not allowed")
    if any(value and value.get("external") for value in tenant03.get("networks", {}).values()):
        errors.append("03: external networks are not allowed")
    for name02, path02, writable02 in bind_mounts(tenant02):
        for name03, path03, writable03 in bind_mounts(tenant03):
            overlaps = path02 == path03 or path02 in path03.parents or path03 in path02.parents
            if overlaps and (writable02 or writable03):
                # Do not print potentially sensitive host paths.
                errors.append(f"writable bind overlap: 02 {name02} / 03 {name03}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tenant02", action="append", required=True, help="Compose file; repeat for overrides in merge order")
    parser.add_argument("--tenant03", action="append", required=True, help="Compose file; repeat for overrides in merge order")
    parser.add_argument("--tenant02-env")
    parser.add_argument("--tenant03-env")
    args = parser.parse_args()
    try:
        errors = check_isolation(render(args.tenant02, args.tenant02_env), render(args.tenant03, args.tenant03_env))
    except (ValueError, OSError, subprocess.SubprocessError):
        print("FAIL: could not validate resolved Compose configuration; no credentials were printed", file=sys.stderr)
        return 1
    for error in errors:
        print(f"FAIL: {error}", file=sys.stderr)
    if not errors:
        print("PASS: resolved project/network/port/container/storage isolation (runtime coexistence not tested)")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
