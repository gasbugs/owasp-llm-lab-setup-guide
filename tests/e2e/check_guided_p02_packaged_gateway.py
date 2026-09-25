"""Check the built Gateway's original CMD in a credential-free, network-none container."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[2]
CHECK = r'''
import hashlib, json, math, os, time, urllib.request, urllib.error, uuid
from pathlib import Path
origin = "http://127.0.0.1:8080"
def request(method, path, token=None, body=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(origin + path, data=None if body is None else json.dumps(body).encode(), headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, json.load(error)
deadline = time.monotonic() + 20
while True:
    try:
        assert request("GET", "/readyz")[0] == 200
        break
    except Exception:
        if time.monotonic() >= deadline:
            raise
        time.sleep(0.1)
provision = os.environ["GUIDED_LAB02_PROVISION_TOKEN"]
control = os.environ["GUIDED_H02_GATEWAY_TOKEN"]
verifier = os.environ["GUIDED_VERIFIER_GATEWAY_TOKEN"]
assert request("POST", "/v1/h02/documents", body={})[0] == 401
assert request("POST", "/v1/h02/documents", control, {})[0] == 410
assert request("POST", "/v1/h02/provision", provision, {"execution_id": str(uuid.uuid4())})[0] == 200
assert request("GET", "/v1/p02/resources", control)[0] == 401
status, resources = request("GET", "/v1/p02/resources", verifier)
assert status == 200 and resources["connection_verified"] is True
assert resources["provider_mode"] == "contract"
assert resources["binding"]["source_prefix"] == "h02/knowledge/" and resources["binding"]["dimensions"] == 1024
suite, execution = str(uuid.uuid4()), str(uuid.uuid4())
status, grant = request("POST", "/v1/p02/executions", control, {"suite_id": suite, "execution_id": execution, "source_digest": "a" * 64, "runner_digest": "b" * 64})
assert status == 200
key = f"h02/knowledge/{execution}.md"
content = "# 합성 안내\n\n패키징을 확인하는 합성 원문입니다.\n"
def invoke(operation, payload):
    status, result = request("POST", "/v1/p02/invoke", grant["capability"], {"suite_id": suite, "execution_id": execution, "operation": operation, "payload": payload})
    assert status == 200, (status, result)
    assert result["response"]["provider_mode"] == "contract"
    return result["response"]
stored = invoke("store_source", {"key": key, "content": content})
embedding = invoke("embed", {"text": "패키징을 확인하는 합성 원문입니다."})
assert embedding["embedding_dimension"] == 1024 and math.isclose(embedding["embedding_norm"], 1)
assert request("POST", f"/v1/p02/executions/{execution}/close", grant["capability"], {})[0] == 401
assert request("POST", f"/v1/p02/executions/{execution}/close", control, {})[0] == 200
status, receipt = request("GET", f"/v1/p02/executions/{execution}", verifier)
assert status == 200 and receipt["closed"] is True and len(receipt["calls"]) == 2
assert [call["state"] for call in receipt["calls"]] == ["complete", "complete"]
assert request("GET", f"/v1/p02/executions/{execution}", grant["capability"])[0] == 401
status, source = request("GET", f"/v1/p02/executions/{execution}/source", verifier)
assert status == 200 and source["provider_mode"] == "contract"
assert source["source_digest"] == stored["source_digest"] == hashlib.sha256(content.encode()).hexdigest()
assert source["source_bytes"] == len(content.encode())
assert request("GET", "/readyz")[0] == 200
print(json.dumps({"verified": True, "scope": "packaged-gateway-contract", "uid": os.getuid(), "receipt": receipt, "source_requery": source,
                  "resources": resources,
                  "image_sources": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in Path("/app").glob("*.py")}}, ensure_ascii=False))
'''


def run(args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=60).stdout.strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", default="localhost/guided-p02-gateway:contract-check")
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    if options.output.exists():
        raise SystemExit("evidence output already exists")
    source = ROOT / "llm-security-control-plane/guided-bedrock-gateway"
    required = set()
    for file in source.glob("*.py"):
        required.update(re.findall(r'os\.environ\["([A-Z0-9_]+)"\]', file.read_text()))
    name = "guided-p02-package-" + uuid4().hex[:10]
    command = ["docker", "run", "-d", "--name", name, "--network", "none", "--read-only",
               "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
               "--tmpfs", "/state:uid=65532,gid=65532,mode=0700", "--tmpfs", "/tmp",
               "-e", "GUIDED_PROVIDER_MODE=contract", "-e", "AWS_REGION=us-east-1"]
    for key in sorted(required):
        command += ["-e", f"{key}=synthetic-{key.lower()}-only"]
    command.append(options.image)
    created = False
    try:
        run(command)
        created = True
        identity = json.loads(run(["docker", "inspect", name]))[0]
        proof = json.loads(run(["docker", "exec", name, "python", "-c", CHECK]))
        assert proof["uid"] == 65532
        assert identity["HostConfig"]["NetworkMode"] == "none" and identity["HostConfig"]["ReadonlyRootfs"]
        assert identity["Config"]["Cmd"][:2] == ["uvicorn", "server:app"]
        proof.update(container=name, image_id=identity["Image"], command=identity["Config"]["Cmd"],
                     gateway_sources={file.name: hashlib.sha256(file.read_bytes()).hexdigest()
                                      for file in source.glob("*.py")})
        assert proof["image_sources"] == proof["gateway_sources"], "built Gateway source does not match checkout"
    finally:
        if created:
            run(["docker", "rm", "-f", name])
    assert not run(["docker", "ps", "-aq", "--filter", f"name=^{name}$"])
    proof["test_container_removed"] = True
    with options.output.open("x") as stream:
        json.dump(proof, stream, ensure_ascii=False, indent=2)
    print(json.dumps({"verified": True, "scope": proof["scope"], "test_container_removed": True}))


if __name__ == "__main__":
    main()
