"""Run one bounded, real Garak scan and expose its native report to the verifier."""
import hashlib, hmac, json, os, subprocess, uuid
from pathlib import Path
from fastapi import FastAPI, Header, HTTPException

CONTROL = os.environ["GUIDED_CONTROL_LAB14_TOKEN"]
VERIFY = os.environ["GUIDED_VERIFIER_LAB14_TOKEN"]
STATE = Path("/state")
app = FastAPI(docs_url=None, redoc_url=None)

def auth(value, expected):
    scheme, _, token = (value or "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(token, expected): raise HTTPException(401, "invalid credential")

@app.get("/readyz")
def readyz(): return {"status": "ready", "tool": "garak", "version": "0.15.1"}

@app.post("/v1/run")
def run(body: dict, authorization: str | None = Header(None)):
    auth(authorization, CONTROL); suite = body["suite_id"]
    prefix = STATE / suite
    options = STATE / f"{suite}-generator.json"
    options.write_text(Path('/work/rest-generator.json').read_text().replace('$H14_TOKEN', os.environ['GUIDED_H14_TARGET_TOKEN']), encoding='utf-8')
    command = ["python", "-m", "garak", "--model_type", "rest", "--model_name", "RestGenerator", "--generator_option_file", str(options), "--probes", "encoding.InjectBase64", "--detectors", "always.Pass", "--generations", "1", "--config", "/work/garak-config.yaml", "--report_prefix", str(prefix)]
    completed = subprocess.run(command, text=True, capture_output=True, timeout=90, check=False)
    reports = sorted(STATE.glob(f"{suite}*.report.jsonl"))
    raw = reports[0].read_bytes() if reports else b""
    first = json.loads(raw.splitlines()[0]) if raw else {}
    receipt = {"suite_id": suite, "started_at": body["started_at"], "run_id": first.get("transient.run_id"), "tool": "garak", "tool_version": "0.15.1", "exit_code": completed.returncode, "config_digest": hashlib.sha256(Path('/work/garak-config.yaml').read_bytes()).hexdigest(), "report_digest": hashlib.sha256(raw).hexdigest() if raw else None, "report": reports[0].name if reports else None, "stdout": completed.stdout[-4000:], "stderr": completed.stderr[-4000:]}
    (STATE / f"{suite}.receipt.json").write_text(json.dumps(receipt), encoding="utf-8")
    return {"suite_id": suite, "exit_code": completed.returncode, "report_digest": receipt["report_digest"]}

@app.get("/v1/artifacts/{suite}")
def artifact(suite: str, authorization: str | None = Header(None)):
    auth(authorization, VERIFY); receipt=json.loads((STATE/f"{suite}.receipt.json").read_text())
    lines=[] if not receipt["report"] else [json.loads(x) for x in (STATE/receipt["report"]).read_text().splitlines() if x]
    return {"receipt": receipt, "report": lines}
