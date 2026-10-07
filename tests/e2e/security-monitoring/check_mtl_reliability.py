"""Isolated Docker MTL acceptance. No AWS credentials or user containers touched."""
from __future__ import annotations
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[3]
EXAMPLE = ROOT / "examples/security-monitoring"
PROJECT = "mtl-audit-" + secrets.token_hex(4)
PREFIX = PROJECT


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def request(url, body=None, headers=None):
    headers = dict(headers or {})
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as reply:
            return reply.status, reply.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def wait(check, label, seconds=90):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        try:
            value = check()
            if value:
                return value
        except (OSError, ValueError, KeyError, AssertionError):
            pass
        time.sleep(1)
    raise AssertionError("timeout: " + label)


def main():
    with tempfile.TemporaryDirectory(prefix=PROJECT) as directory:
        directory = Path(directory)
        fixture = directory / "hub.py"
        fixture.write_text('''import sys
sys.path.insert(0,"/app")
from fastapi import FastAPI
from telemetry import configure_telemetry
import uvicorn
app=FastAPI()
configure_telemetry(app,"mtl-fixture-hub")
@app.post("/api/chat")
def chat(body:dict):
    blocked=body["message"].startswith("block")
    stages=[{"stage":"privacy_input","engine":"presidio","decision":"block" if blocked else "allow","duration_ms":1}]
    if not blocked:
        stages.append({"stage":"bedrock_main","decision":"allow","duration_ms":2})
    return {"request_id":body["request_id"],"reply":"stopped" if blocked else "fixture answer",
            "guardrail":{"decision":"block" if blocked else "allow","blocking_reason":"input:prohibited:EMAIL_ADDRESS" if blocked else None,
                         "mode":"prevent","upstream_called":not blocked,"guard_model_calls":0 if blocked else 2,
                         "policy_bundle_version":"1.1.0","assurance_profile":"high-assurance",
                         "stage_order":[s["stage"] for s in stages],"stages":stages,"duration_ms":3}}
uvicorn.run(app,host="0.0.0.0",port=8014,access_log=False)
''')
        token = secrets.token_hex(20)
        common = {"APPLICATION_INTERNAL_TOKEN": token, "BEDROCK_GATEWAY_TOKEN": token, "AUTH_ADMIN_TOKEN": token,
                  "TELEMETRY_INGEST_TOKEN": token, "TELEMETRY_HMAC_KEY": secrets.token_hex(24),
                  "SECURITY_MONITOR_URL": "http://gateway:8080", "AUTH_EVENT_SINK": "monitor",
                  "OTEL_EXPORTER_OTLP_ENDPOINT": "http://alloy:4318", "NEMO_HUB_URL": "http://hub:8014"}
        prometheus = directory / "prometheus.yml"
        prometheus.write_text('''global:
  scrape_interval: 1s
  evaluation_interval: 1s
rule_files: [/etc/prometheus/alert-rules.yml]
scrape_configs:
  - job_name: llm-security-application
    static_configs: [{targets: [application:8000]}]
  - job_name: llm-security-gateway
    static_configs: [{targets: [gateway:8080]}]
  - job_name: alloy
    static_configs: [{targets: [alloy:12345]}]
''')
        services = {
            "application": {"image": "localhost/mtl-application:review", "environment": common, "ports": ["127.0.0.1::8000"],
                            "volumes": ["application-state:/app/state"], "networks": {"default": {"aliases": ["llm-security-application-gateway"]}}},
            "hub": {"image": "localhost/mtl-application:review", "entrypoint": ["python", "/tmp/hub.py"],
                    "environment": {"OTEL_EXPORTER_OTLP_ENDPOINT": "http://alloy:4318"}, "volumes": [f"{fixture}:/tmp/hub.py:ro"]},
            "gateway": {"image": "localhost/mtl-monitor:review", "environment": {**common,"LLM_MONITOR_TOKEN":token,"LLM_MONITOR_ADMIN_TOKEN":token},
                        "ports": ["127.0.0.1::8080"], "volumes": ["gateway-events:/data"]},
            "alloy": {"image":"docker.io/grafana/alloy:v1.18.0", "command":["run","--server.http.listen-addr=0.0.0.0:12345","--storage.path=/var/lib/alloy/data","--stability.level=public-preview","--disable-reporting","/etc/alloy/config.alloy"],
                      "volumes":[f"{EXAMPLE}/alloy/config.alloy:/etc/alloy/config.alloy:ro","alloy-data:/var/lib/alloy/data"],"ports":["127.0.0.1::12345"]},
            "loki":{"image":"docker.io/grafana/loki:3.5.3","command":["-config.file=/etc/loki/config.yaml"],
                    "volumes":[f"{EXAMPLE}/loki-config.yaml:/etc/loki/config.yaml:ro","loki-data:/loki"],"ports":["127.0.0.1::3100"]},
            "tempo":{"image":"docker.io/grafana/tempo:3.0.2","command":["-target=all","-config.file=/etc/tempo/config.yaml"],
                     "volumes":[f"{EXAMPLE}/tempo.yaml:/etc/tempo/config.yaml:ro","tempo-data:/var/tempo"],"ports":["127.0.0.1::3200"]},
            "prometheus":{"image":"docker.io/prom/prometheus:v3.5.0","command":["--config.file=/etc/prometheus/prometheus.yml","--web.enable-remote-write-receiver"],
                          "volumes":[f"{prometheus}:/etc/prometheus/prometheus.yml:ro",f"{EXAMPLE}/alert-rules.yml:/etc/prometheus/alert-rules.yml:ro"],"ports":["127.0.0.1::9090"]},
        }
        for service in services.values():
            service.setdefault("networks", ["default"])
        config = directory / "compose.json"
        config.write_text(json.dumps({"name": PROJECT, "services": services, "networks":{"default":{"name":PROJECT}},
                                      "volumes":{key:{} for key in ("application-state","gateway-events","alloy-data","loki-data","tempo-data")}}))
        def compose(*args): return run("docker","compose","-f",str(config),*args)
        # Project/network/volumes are newly named and only this fixture owns them.
        assert PROJECT not in run("docker","network","ls","--format","{{.Name}}")
        try:
            compose("up","-d")
            time.sleep(2)
            def url(service, port): return "http://" + compose("port",service,str(port)).strip()
            app_url, monitor_url = url("application",8000), url("gateway",8080)
            loki, tempo, prom, alloy = url("loki",3100), url("tempo",3200), url("prometheus",9090), url("alloy",12345)
            wait(lambda: request(app_url+"/healthz")[0]==200, "Application")
            wait(lambda: request(loki+"/ready")[0]==200, "Loki")
            wait(lambda: request(tempo+"/ready")[0]==200, "Tempo")
            wait(lambda: request(prom+"/-/ready")[0]==200, "Prometheus")
            login = json.loads(request(app_url+"/.well-known/login", {"username":"public-reader","password":"public-reader-demo"})[1])
            auth = {"Authorization":"Bearer "+login["access_token"]}
            # Deliberately stop the collector, then restart the producer with committed events.
            compose("stop","gateway")
            result = json.loads(request(app_url+"/api/chat", {"message":"normal-secret-payload"},auth)[1])
            assert result["application_decision"] == "allow"
            assert result["upstream_called"] is True
            request_id, trace_id = result["request_id"], result["trace_id"]
            before = request(app_url+"/metrics")[1]
            assert "llm_audit_pending_events 0" not in before
            compose("restart","application")
            app_url = url("application",8000)
            wait(lambda: request(app_url+"/healthz")[0]==200, "Application restart")
            compose("start","gateway")
            monitor_url = url("gateway",8080)
            def events():
                return json.loads(request(monitor_url+"/api/events?limit=1000",headers={"Authorization":"Bearer "+token})[1])["events"]
            found = wait(lambda: [e for e in events() if e["request_id"]==request_id], "replayed event")
            assert len(found) == 3  # one summary and two stages
            assert {e["attributes"].get("stage_name") for e in found} == {None,"privacy_input","bedrock_main"}
            assert all(e["attributes"]["trace_id"] == trace_id for e in found)
            def logs_for(rid):
                query = '{service_name="llm-security-gateway"} | json | request_id="'+rid+'"'
                result = json.loads(request(loki+"/loki/api/v1/query_range?"+urllib.parse.urlencode({"query":query,"limit":1000}))[1])
                return [json.loads(row[1]) for stream in result["data"]["result"] for row in stream["values"]]
            wait(lambda: logs_for(request_id), "Loki replay")
            wait(lambda: request(tempo+"/api/traces/"+trace_id)[0]==200, "Trace correlation")
            # Producer -> Monitor outage and Monitor -> Alloy outage have separate persisted backlogs.
            compose("stop","alloy")
            second = json.loads(request(app_url+"/api/chat", {"message":"block-private@example.com"},auth)[1])
            assert second["application_decision"]=="block" and second["upstream_called"] is False
            wait(lambda: [e for e in events() if e["request_id"]==second["request_id"]], "blocked event")
            compose("restart","gateway")
            monitor_url = url("gateway",8080)
            compose("start","alloy")
            alloy = url("alloy",12345)
            wait(lambda: logs_for(second["request_id"]), "durable Monitor log replay")
            # Backend outage must survive Alloy restart, with the same event IDs.
            compose("stop","loki","tempo")
            third = json.loads(request(app_url+"/api/chat", {"message":"normal-canary"},auth)[1])
            wait(lambda: [e for e in events() if e["request_id"]==third["request_id"]], "queued backend event")
            wait(lambda: "otelcol_exporter_queue_size" in request(alloy+"/metrics")[1], "exporter queue metrics")
            time.sleep(3)
            compose("restart","alloy")
            compose("start","loki","tempo")
            loki, tempo = url("loki",3100), url("tempo",3200)
            wait(lambda: logs_for(third["request_id"]), "persistent Alloy log replay")
            wait(lambda: request(tempo+"/api/traces/"+third["trace_id"])[0]==200, "persistent Alloy trace replay")
            bodies=json.dumps(events())
            assert "normal-secret-payload" not in bodies and "private@example.com" not in bodies
            assert login["access_token"] not in bodies
            query='llm_guardrail_decisions_total{engine="nemo",direction="chat",decision="allow"}'
            metrics=wait(lambda: json.loads(request(prom+"/api/v1/query?"+urllib.parse.urlencode({"query":query}))[1])["data"]["result"], "Prometheus decision")
            assert float(metrics[0]["value"][1])>=1
            print(json.dumps({"result":"PASS","project":PROJECT,"request_id":request_id,"trace_id":trace_id,
                              "cases":["Application outbox restart","Monitor log outbox restart","Alloy persistent log and trace queue restart",
                                       "stage and policy correlation","metadata privacy","actual Prometheus decision metric"]},indent=2))
        finally:
            diagnostics=compose("logs","--tail","30")
            Path("/tmp/mtl-acceptance-diagnostics.log").write_text(diagnostics)
            compose("down","--volumes","--remove-orphans")

if __name__ == "__main__": main()
