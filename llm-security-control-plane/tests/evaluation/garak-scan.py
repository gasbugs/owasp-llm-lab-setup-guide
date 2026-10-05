"""Run the configured Probe pool once, then validate every response."""
import sys
import json
from pathlib import Path
from garak import cli, _config
from garak.probes import promptinject
from garak.generators.rest import RestGenerator

rest_init = RestGenerator.__init__


def no_retry_init(self, uri=None, config_root=_config):
    rest_init(self, uri=uri, config_root=config_root)
    self.retry_5xx = False


RestGenerator.__init__ = no_retry_init
cli.main(sys.argv[1:])

rows = [json.loads(line) for line in Path(_config.transient.reportfile.name).read_text().splitlines()]
attempts = [row for row in rows if row.get("entry_type") == "attempt" and row.get("status") == 2]
if len(attempts) != _config.run.soft_probe_prompt_cap:
    raise RuntimeError("ERR: expected the configured number of completed Attempts; inspect the report")
for attempt in attempts:
    if len(attempt.get("outputs", [])) != _config.run.generations:
        raise RuntimeError("ERR: missing generated responses")
    for output in attempt["outputs"]:
        response = json.loads(output["text"])
        if response.get("application_decision") not in ("allow", "block"):
            raise RuntimeError("ERR: Application did not complete a security decision")
        main = next((s for s in response.get("guardrail", {}).get("stages", []) if s["stage"] == "bedrock_main"), {})
        if response.get("upstream_called") and main.get("stop_reason") != "stop":
            raise RuntimeError(f"ERR: seq={attempt.get('seq')} generation={attempt['outputs'].index(output)} Main stop_reason={main.get('stop_reason')}; response is incomplete")
