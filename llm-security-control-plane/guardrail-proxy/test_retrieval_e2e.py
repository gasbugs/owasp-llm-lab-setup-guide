"""Run the real proxy and Presidio image with a network-local Gateway double."""

import json
import os
from pathlib import Path
import subprocess
import time
import urllib.error
import urllib.request


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
PROXY_IMAGE = os.getenv("PROXY_TEST_IMAGE", "localhost/llm-security-guardrail-proxy-api:0.1.0")
PRIVACY_IMAGE = os.getenv("PRIVACY_TEST_IMAGE", "localhost/llm-security-presidio-privacy-spoke:1.0.0")
PYTHON_IMAGE = "docker.io/library/python:3.12-slim"
SUFFIX = str(os.getpid())
NETWORK = "guardrail-retrieval-e2e-" + SUFFIX
GATEWAY = NETWORK + "-gateway"
PRIVACY = NETWORK + "-privacy"
PROXY = NETWORK + "-proxy"
CALLER_TOKEN, ADMIN_TOKEN, GATEWAY_TOKEN, PRIVACY_TOKEN = (
    "c" * 64, "a" * 64, "g" * 64, "p" * 64
)


def docker(*args):
    return subprocess.run(["docker", *args], check=True, capture_output=True, text=True).stdout.strip()


def wait_for(url, *, timeout=120):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if response.status == 200:
                    return
        except (OSError, TimeoutError):
            pass
        time.sleep(1)
    raise RuntimeError("isolated service did not become ready")


def post(base, fixture_id):
    request = urllib.request.Request(
        base + "/v1/retrieval-chat", method="POST",
        headers={"Authorization": "Bearer " + CALLER_TOKEN,
                 "Content-Type": "application/json"},
        data=json.dumps({"message": "Where is account recovery help?",
                         "fixture_id": fixture_id}).encode(),
    )
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, json.load(error)


def main():
    created = []
    docker("network", "create", NETWORK)
    try:
        docker("run", "--detach", "--name", GATEWAY, "--network", NETWORK,
               "--network-alias", "gateway", "--env", "BEDROCK_GATEWAY_TOKEN=" + GATEWAY_TOKEN,
               "--volume", str(HERE / "fake_retrieval_gateway.py") + ":/app/server.py:ro",
               PYTHON_IMAGE, "python", "/app/server.py")
        created.append(GATEWAY)
        docker("run", "--detach", "--name", PRIVACY, "--network", NETWORK,
               "--network-alias", "privacy", "--env", "PRESIDIO_INTERNAL_TOKEN=" + PRIVACY_TOKEN,
               PRIVACY_IMAGE)
        created.append(PRIVACY)
        docker("run", "--detach", "--name", PROXY, "--network", NETWORK,
               "--tmpfs", "/state:rw,mode=1777", "--publish", "127.0.0.1::8000",
               "--env", "PROXY_CALLER_TOKEN=" + CALLER_TOKEN,
               "--env", "PROXY_ADMIN_TOKEN=" + ADMIN_TOKEN,
               "--env", "PROXY_GATEWAY_TOKEN=" + GATEWAY_TOKEN,
               "--env", "PROXY_PRIVACY_TOKEN=" + PRIVACY_TOKEN,
               "--env", "GATEWAY_URL=http://gateway:8080",
               "--env", "PRIVACY_URL=http://privacy:8013",
               PROXY_IMAGE)
        created.append(PROXY)
        port = docker("port", PROXY, "8000/tcp").rsplit(":", 1)[-1]
        base = "http://127.0.0.1:" + port
        wait_for(base + "/healthz")
        deadline = time.monotonic() + 120
        for peer_url in ("http://gateway:8080/healthz", "http://privacy:8013/healthz"):
            while time.monotonic() < deadline:
                peer = subprocess.run(
                    ["docker", "exec", PROXY, "python", "-c",
                     "import urllib.request; urllib.request.urlopen(" + repr(peer_url)
                     + ", timeout=3).read()"], capture_output=True, text=True)
                if peer.returncode == 0:
                    break
                time.sleep(1)
            else:
                raise RuntimeError("isolated peer did not become ready: " + peer_url)
        with urllib.request.urlopen(base + "/console/", timeout=10) as response:
            console = response.read().decode()
        with urllib.request.urlopen(base + "/console/app.js", timeout=10) as response:
            app_js = response.read().decode()
        assert "id=\"test-path\"" in console and "recovery-injected" in console
        assert "/v1/retrieval-chat" in app_js
        policy_request = urllib.request.Request(
            base + "/v1/policy", headers={"Authorization": "Bearer " + CALLER_TOKEN})
        with urllib.request.urlopen(policy_request, timeout=10) as response:
            policy = json.load(response)
        assert policy["retrieval_fixture_available"] is True

        safe_http, safe = post(base, "recovery-safe")
        assert safe_http == 200 and safe["decision"] == "allow", safe
        assert safe["upstream_called"] is True and safe["main_completed"] is True
        assert [item["name"] for item in safe["stages"]] == [
            "presidio_input", "nemo_input", "retrieval", "main", "nemo_output", "presidio_output"]
        assert safe["stages"][2]["native_action_invoked"] is True
        assert [item["role"] for item in safe["model_calls"]] == ["input_rail", "main", "output_rail"]

        risk_http, risk = post(base, "recovery-injected")
        assert risk_http == 200 and risk["decision"] == "block", risk
        assert risk["stopped_at"] == "retrieval"
        assert risk["upstream_called"] is False and risk["main_completed"] is False
        assert [item["role"] for item in risk["model_calls"]] == ["input_rail"]
        assert risk["stages"][-1]["native_action_invoked"] is True

        calls = json.loads(docker("exec", GATEWAY, "python", "-c",
            "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8080/calls').read().decode())"))
        assert calls == {"main": 1, "self_check": 3}, calls
        print("retrieval_live_peer_e2e=PASS cases=safe,blocked,main_call_count,privacy,native_action")
    finally:
        for name in reversed(created):
            subprocess.run(["docker", "rm", "--force", name], capture_output=True, text=True)
        subprocess.run(["docker", "network", "rm", NETWORK], capture_output=True, text=True)


if __name__ == "__main__":
    main()
