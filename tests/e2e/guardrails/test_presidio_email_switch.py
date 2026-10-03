"""Exercise the real learner cp/restart switch against an existing NeMo server."""
import argparse
import json
import subprocess
import tempfile
import time
import urllib.request
import uuid
from pathlib import Path


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True).strip()


def request(base, path, body=None):
    req = urllib.request.Request(
        base + path, data=None if body is None else json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=240) as response:
        assert response.status == 200
        return json.load(response)


def ready(base):
    for _ in range(90):
        try:
            return request(base, "/api/guardrails/policy")
        except (OSError, ValueError):
            time.sleep(1)
    raise AssertionError("Presidio did not become ready")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--network", default="llm-security-control-plane")
    parser.add_argument("--nemo-url", default="http://llm-security-nemo-dialog-rails:8013")
    parser.add_argument("--evidence", required=True)
    args = parser.parse_args()
    name = "presidio-email-switch-check-" + uuid.uuid4().hex[:8]
    evidence = {"image_id": docker("image", "inspect", args.image, "--format", "{{.Id}}")}
    with tempfile.TemporaryDirectory() as temp:
        source = Path(temp) / "server.py"
        try:
            docker("run", "-d", "--name", name, "--network", args.network,
                   "-p", "127.0.0.1::8013", "-e", "RUN_MODE=server",
                   "-e", "GUARD_MODE=enforce", "-e", "ENABLE_LAB_ENDPOINTS=true",
                   "-e", "NEMO_GUARD_URL=" + args.nemo_url, args.image)
            base = "http://" + docker("port", name, "8013/tcp")
            policy = ready(base)
            assert policy["input_policy"]["block_email_input"] is False
            docker("cp", name + ":/app/server.py", str(source))
            source.chmod(0o644)
            original = source.read_text()
            email = {"message": "Email analyst@example.com with the reset steps."}
            evidence["before"] = request(base, "/api/chat", email)
            before = evidence["before"]["guardrail"]
            assert before["decision"] == "redact" and before["upstream_called"] is True
            assert original.count("BLOCK_EMAIL_INPUT = False") == 1
            source.write_text(original.replace("BLOCK_EMAIL_INPUT = False", "BLOCK_EMAIL_INPUT = True"))
            docker("cp", str(source), name + ":/app/server.py")
            docker("restart", name)
            base = "http://" + docker("port", name, "8013/tcp")
            policy = ready(base)
            assert policy["input_policy"]["block_email_input"] is True
            evidence["policy"] = policy
            evidence["normal"] = request(base, "/api/chat", {"message": "비밀번호 변경 절차를 간단히 알려 주세요."})
            normal = evidence["normal"]["guardrail"]
            assert normal["decision"] == "allow" and normal["upstream_called"] is True
            assert "bedrock_main" in normal["stage_order"]
            evidence["blocked"] = request(base, "/api/chat", email)
            blocked = evidence["blocked"]["guardrail"]
            assert blocked["decision"] == "block" and blocked["upstream_called"] is False
            assert blocked["blocking_reason"] == "input:prohibited:EMAIL_ADDRESS"
            assert blocked["stage_order"] == ["presidio_input"] and blocked["inner_guardrail"] is None
            # Retrieval uses /api/scan and must retain its redaction contract.
            scan = request(base, "/api/scan", {"text": email["message"]})
            assert scan["application_decision"] == "redact" and "<EMAIL_ADDRESS>" in scan["sanitized_text"]
            evidence["scan"] = scan
            source.write_text(original)
            docker("cp", str(source), name + ":/app/server.py")
            docker("restart", name)
            base = "http://" + docker("port", name, "8013/tcp")
            assert ready(base)["input_policy"]["block_email_input"] is False
            evidence["restored"] = request(base, "/api/chat", email)
            assert evidence["restored"]["guardrail"]["decision"] == "redact"
            assert evidence["restored"]["guardrail"]["upstream_called"] is True
            logs = docker("logs", name)
            assert "analyst@example.com" not in logs
            evidence["content_free_logs"] = True
        except Exception:
            print(docker("logs", name))
            raise
        finally:
            docker("rm", "-f", name)
    Path(args.evidence).write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n")
    print("PASS: cp/restart False→True→False; email blocked before NeMo; normal and scan preserved")


if __name__ == "__main__":
    main()
