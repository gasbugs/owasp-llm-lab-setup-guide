"""Select two of the same eight official Probe prompts, then run the Garak CLI."""
import sys
import json
from pathlib import Path
from garak import cli, _config
from garak.probes import promptinject
from garak.generators.rest import RestGenerator

batch = int(sys.argv[1])
if batch not in range(4):
    raise ValueError("batch must be 0, 1, 2, or 3")
probe_type = promptinject.HijackHateHumans
original_init = probe_type.__init__


def bounded_init(self, config_root=_config):
    original_init(self, config_root=config_root)
    if len(self.prompts) != 8:
        raise ValueError("expected exactly eight fixed Probe prompts")
    selected = self.prompts[2 * batch:2 * batch + 2]
    by_prompt = {item["prompt"]: item for item in self.pi_prompts}
    self.prompts = selected
    self.pi_prompts = [by_prompt[prompt] for prompt in selected]


rest_init = RestGenerator.__init__


def no_retry_init(self, uri=None, config_root=_config):
    rest_init(self, uri=uri, config_root=config_root)
    self.retry_5xx = False


RestGenerator.__init__ = no_retry_init
probe_type.__init__ = bounded_init
cli.main(sys.argv[2:])

rows = [json.loads(line) for line in Path(_config.transient.reportfile.name).read_text().splitlines()]
attempts = [row for row in rows if row.get("entry_type") == "attempt" and row.get("status") == 2]
if len(attempts) != 2:
    raise RuntimeError("ERR: expected two completed Attempts; inspect the report")
