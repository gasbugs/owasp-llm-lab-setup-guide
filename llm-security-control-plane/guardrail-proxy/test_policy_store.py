"""Persistent bundle boot and tamper checks, without network peers."""

import hashlib
import json
import shutil
from pathlib import Path
import tempfile

from policy_bundle import POLICY_FILES, load_bundle
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

with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    seed = root / "seed"
    for filename in POLICY_FILES:
        target = seed / filename
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(Path("/app") / filename, target)
    legacy = hashlib.sha256()
    for filename in POLICY_FILES:
        legacy.update(filename.encode() + b"\0" + (seed / filename).read_bytes())
    assert load_bundle(seed).digest == legacy.hexdigest()

    hidden = seed / "nemo-policy" / "untracked.co"
    hidden.write_text('define flow hidden\n  bot say "unexpected"\n')
    try:
        load_bundle(seed)
    except ValueError as error:
        assert "unexpected NeMo policy file" in str(error)
    else:
        raise AssertionError("untracked Colang was accepted outside the digest")
    hidden.unlink()

    flow = seed / "nemo-policy" / "flows.co"
    flow.write_text('''define user ask recovery
  "Where is account recovery help?"

define bot recovery guidance
  "Use the official account support page."

define flow
  user ask recovery
  bot recovery guidance
''')
    candidate = load_bundle(seed)
    assert candidate.digest != legacy.hexdigest()
    store = PolicyStore(root / "state", seed)
    assert store.active.digest == candidate.digest
    copied = root / "state" / "bundles" / candidate.digest / "nemo-policy" / "flows.co"
    assert copied.read_text() == flow.read_text()
    assert PolicyStore(root / "state", seed).active.digest == candidate.digest
    draft = store.create_draft(candidate.digest, "0.2.0",
                               store.active_input_prompt() + "\nExample: normal recovery is No.")
    assert (root / "state" / "bundles" / draft["digest"] /
            "nemo-policy" / "flows.co").read_text() == flow.read_text()
    copied.chmod(0o644)
    copied.write_text(copied.read_text() + "# tampered\n")
    try:
        PolicyStore(root / "state", seed)
    except ValueError as error:
        assert "digest mismatch" in str(error)
    else:
        raise AssertionError("modified Colang was accepted with an old digest")

print("policy_store=PASS cases=seed,restart,tamper,pointer,legacy_digest,flow_inventory,flow_digest,draft_copy")
