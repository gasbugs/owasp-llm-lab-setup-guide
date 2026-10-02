#!/usr/bin/env python3
"""Isolated real HTTP regression; build the image first, no cloud calls."""
import argparse
import json
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

CLEAN = "The security guide is ready."
PII = "Send the incident report to analyst@example.com after review.\n교육용 합성 주민번호는 900101-1234568 입니다."
OUTPUT = "Contact security-team@example.com for assistance."


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True).strip()


def request(base, path, body=None):
    req = urllib.request.Request(base + path, data=None if body is None else json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, json.load(error)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--evidence", required=True)
    args = parser.parse_args()
    evidence = {"image_id": docker("image", "inspect", args.image, "--format", "{{.Id}}"), "modes": {}}
    for mode in ("audit", "enforce"):
        name = "presidio-mode-check-" + uuid.uuid4().hex[:10]
        try:
            docker("run", "-d", "--name", name, "-p", "127.0.0.1::8013",
                   "-e", "RUN_MODE=server", "-e", "GUARD_MODE=" + mode,
                   "-e", "ENABLE_LAB_ENDPOINTS=true", args.image)
            base = "http://" + docker("port", name, "8013/tcp")
            for attempt in range(60):
                try:
                    status, health = request(base, "/healthz")
                    if status == 200:
                        break
                except (OSError, ValueError):
                    pass
                time.sleep(1)
            else:
                raise AssertionError("server did not become healthy")
            assert health["guard_mode"] == mode
            results = {"health": health}
            cases = (("clean_input", "/api/scan", {"text": CLEAN}, False),
                     ("pii_input", "/api/scan", {"text": PII}, True),
                     ("clean_output", "/api/scan-output", {"prompt": "지원 연락처를 알려 주세요.", "model_output": CLEAN}, False),
                     ("pii_output", "/api/scan-output", {"prompt": "지원 연락처를 알려 주세요.", "model_output": OUTPUT}, True))
            for label, path, body, detected in cases:
                status, result = request(base, path, body)
                assert status == 200, result
                if mode == "enforce":
                    assert "sanitized_text" in result and "original_text" not in result, result
                    assert result["application_decision"] == ("redact" if detected else "allow")
                    expected = {"clean_input": CLEAN, "clean_output": CLEAN,
                                "pii_input": "Send the incident report to <EMAIL_ADDRESS> after review.\n교육용 합성 주민번호는 <KR_RRN> 입니다.",
                                "pii_output": "Contact <EMAIL_ADDRESS> for assistance."}[label]
                    assert result["sanitized_text"] == expected
                    if detected:
                        assert "@example.com" not in json.dumps(result)
                        assert "900101-1234568" not in json.dumps(result)
                    else:
                        assert result["sanitized_text"] == CLEAN
                else:
                    assert result["original_text"] == body.get("text", body.get("model_output"))
                    assert not {"sanitized_text", "input_prompt", "effective_text"} & result.keys()
                    assert result["valid"] == (not detected)
                    assert result["application_decision"] == "allow"
                    assert result["upstream_called"] is False
                    assert result["blocking_reason"] is None
                    if label == "pii_input":
                        assert set(result["entity_types"]) == {"EMAIL_ADDRESS", "KR_RRN"}
                assert {"event", "framework", "framework_version", "direction", "modified",
                        "valid", "risk_score", "detections", "entity_types", "application_decision",
                        "duration_ms", "scanner", "guard_engine", "guard_mode", "upstream_called",
                        "blocking_reason"} <= result.keys()
                assert result["valid"] == (not detected)
                assert result["upstream_called"] is False
                results[label] = {"request": body, "response": result}
            if mode == "enforce":
                status, details = request(base, "/api/scan?include_metadata=true", {"text": PII})
                assert status == 200
                assert set(details["entity_types"]) == {"EMAIL_ADDRESS", "KR_RRN"}
                assert details["sanitized_text"] == results["pii_input"]["response"]["sanitized_text"]
                assert not {"original_text", "input_prompt", "effective_text"} & details.keys()
                results["retrieval_metadata"] = details
            for body in ({"text": PII, "guard_mode": "audit"}, {"text": PII, "entities": ["UNSUPPORTED_ENTITY"]}):
                status, result = request(base, "/api/scan", body)
                assert status == 422, result
            logs = docker("logs", name)
            for forbidden in ("analyst@example.com", "900101-1234568", "security-team@example.com", '"effective_text"', '"original_text"', '"sanitized_text"'):
                assert forbidden not in logs, forbidden
            results["invalid_requests_status"] = 422
            results["logs_exclude_content"] = True
            evidence["modes"][mode] = results
        finally:
            docker("rm", "-f", name)
    Path(args.evidence).write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n")
    print("PASS: 8 scan requests, both modes/directions, mode spoofing, unsupported entities, content-free logs")


if __name__ == "__main__":
    main()
