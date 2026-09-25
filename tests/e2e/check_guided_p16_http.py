"""Build P16 separately and check its real HTTP service and SQLite promotion ledger.

Only generated publisher containers are removed. No existing deployment is changed.
"""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[2]
CONTROL = ROOT / "llm-security-control-plane"
LAB = Path("guided-labs/h16-policy-promotion")
HTTP_CHECK = r'''
import json, urllib.request
from datetime import datetime, timezone
from uuid import uuid4
def call(path, token, body=None):
    request = urllib.request.Request('http://127.0.0.1:8000' + path,
        data=None if body is None else json.dumps(body).encode(),
        headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)
suite = str(uuid4())
call('/v1/run', 'publisher-control', {'suite_id': suite,
    'started_at': datetime.now(timezone.utc).isoformat()})
print(json.dumps(call('/v1/receipts/' + suite, 'publisher-verifier')))
'''


def main():
    records = []
    for variant in ("starter", "solution"):
        name = "guided-p16-check-" + uuid4().hex[:10]
        image = "localhost/" + name + ":test"
        with tempfile.TemporaryDirectory(prefix="guided-p16-context-") as directory:
            context = Path(directory)
            shutil.copytree(CONTROL / LAB, context / LAB)
            if variant == "solution":
                shutil.copyfile(CONTROL / "guided-solutions/h16-policy-promotion/policy.py",
                                context / LAB / "policy.py")
            subprocess.run(["docker", "build", "-q", "-f", str(context / LAB / "Containerfile"),
                            "-t", image, str(context)], check=True)
        try:
            subprocess.run(["docker", "run", "-d", "--name", name, "--network", "none",
                            "--read-only", "--cap-drop", "ALL",
                            "--tmpfs", "/state:uid=65532,gid=65532",
                            "-e", "PYTHONDONTWRITEBYTECODE=1",
                            "-e", "GUIDED_CONTROL_LAB16_TOKEN=publisher-control",
                            "-e", "GUIDED_VERIFIER_LAB16_TOKEN=publisher-verifier", image], check=True)
            for attempt in range(30):
                ready = subprocess.run(["docker", "exec", name, "python", "-c",
                    "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/readyz')"],
                    capture_output=True)
                if ready.returncode == 0:
                    break
                time.sleep(1)
            else:
                raise RuntimeError("P16 did not become ready")
            receipt = json.loads(subprocess.check_output(
                ["docker", "exec", name, "python", "-c", HTTP_CHECK], text=True))
            assert receipt["normal_decision"] == "allow"
            assert receipt["risk_decision"] == ("block" if variant == "solution" else "allow")
            assert [item["event"] for item in receipt["events"]] == (
                ["promote", "rollback", "promote"] if variant == "solution" else [])
            if variant == "solution":
                assert receipt["active_digest"] == receipt["sandbox_digest"]
            image_id = subprocess.check_output(
                ["docker", "image", "inspect", "--format", "{{.Id}}", image], text=True).strip()
            records.append({"variant": variant, "image_id": image_id, "receipt": receipt})
        finally:
            subprocess.run(["docker", "rm", "-f", name], check=True)
    print(json.dumps({"scope": "P16 TCP service and policy ledger; no Browser or AWS",
                      "records": records}, ensure_ascii=False))


if __name__ == "__main__":
    main()
