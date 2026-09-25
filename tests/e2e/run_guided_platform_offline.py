#!/usr/bin/env python3
"""Start only the Control Center without network, AWS credentials or learner apps."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import secrets
import subprocess
import time
import uuid


ROOT = Path(__file__).resolve().parents[2]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", default="localhost/guided-control-center:practice-isolation-check")
    args = parser.parse_args()
    source = (ROOT / "llm-security-control-plane/guided-control-center/server.py").read_text()
    required = sorted(set(re.findall(r'os\.environ\["(GUIDED_\w+)"\]', source)))
    name = "guided-offline-check-" + uuid.uuid4().hex[:12]
    command = ["docker", "run", "-d", "--name", name, "--network", "none", "--read-only",
               "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
               "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m"]
    for key in required:
        command.extend(["-e", f"{key}={secrets.token_hex(32)}"])
    command.extend(["-e", "GUIDED_ALLOWED_HOSTS=127.0.0.1:8000", args.image])
    started = False
    try:
        subprocess.run(command, check=True, capture_output=True, text=True, timeout=30)
        started = True
        probe = "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/readyz', timeout=2)"
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            ready = subprocess.run(["docker", "exec", name, "python", "-c", probe], capture_output=True, timeout=5)
            if ready.returncode == 0:
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("Control Center did not become ready without learner services")
        check = '''
import http.cookiejar, json, urllib.request
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
for path in ('/', '/livez', '/readyz', '/api/bootstrap', '/app.css', '/app.js'):
    with opener.open('http://127.0.0.1:8000' + path, timeout=3) as response:
        assert response.status == 200, (path, response.status)
        body = response.read()
        if path == '/api/bootstrap':
            assert json.loads(body)['csrf_token']
        print(path, response.status)
'''
        subprocess.run(["docker", "exec", name, "python", "-c", check], check=True, timeout=30)
        print("OFFLINE_PLATFORM_CHECK: passed; no learner service or AWS call was available")
    finally:
        if started:
            subprocess.run(["docker", "rm", "-f", name], check=True, capture_output=True, timeout=30)


if __name__ == "__main__":
    main()
