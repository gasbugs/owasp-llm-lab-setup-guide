"""Persistent bundle boot and tamper checks, without network peers."""

import json
from pathlib import Path
import tempfile

from policy_store import PolicyStore


with tempfile.TemporaryDirectory() as temporary:
    state = Path(temporary)
    first = PolicyStore(state, Path("/app"))
    digest = first.active.digest
    assert (state / "active.json").is_file()
    assert json.loads((state / "active.json").read_text()) == {"digest": digest}
    assert PolicyStore(state, Path("/app")).active.digest == digest

    prompt = state / "bundles" / digest / "nemo-policy" / "prompts.yml"
    prompt.chmod(0o644)
    prompt.write_text(prompt.read_text().replace("Return one word only", "Return exactly one word"))
    try:
        PolicyStore(state, Path("/app"))
    except ValueError as error:
        assert "digest mismatch" in str(error)
    else:
        raise AssertionError("tampered active policy was accepted")

with tempfile.TemporaryDirectory() as temporary:
    state = Path(temporary)
    PolicyStore(state, Path("/app"))
    (state / "active.json").write_text('{"digest":"../../etc"}')
    try:
        PolicyStore(state, Path("/app"))
    except ValueError as error:
        assert "pointer" in str(error)
    else:
        raise AssertionError("invalid pointer was accepted")

print("policy_store=PASS cases=seed,restart,tamper,pointer")
