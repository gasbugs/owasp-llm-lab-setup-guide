"""Exercise synthetic approvals locally, without network or real user credentials."""

import hashlib
import json
from pathlib import Path
import secrets
import tempfile

from approval import ApprovalDenied, ApprovalStore

requester, reviewer = secrets.token_hex(24), secrets.token_hex(24)
credentials = {
    "requester": {"credential_sha256": hashlib.sha256(requester.encode()).hexdigest(), "role": "requester"},
    "reviewer": {"credential_sha256": hashlib.sha256(reviewer.encode()).hexdigest(), "role": "reviewer"},
}
with tempfile.TemporaryDirectory() as folder:
    store = ApprovalStore(str(Path(folder) / "state.db"), credentials)
    action = {"kind": "publish_training_notice", "notice": "훈련 공지"}
    identifier = store.propose(requester, action)
    try:
        store.execute(requester, identifier, action)
    except ApprovalDenied as exc:
        print(json.dumps({"stage": "before-approval", "reason": str(exc), "effects": store.effect_count()}))
    store.review(reviewer, identifier, True)
    print(json.dumps({"stage": "after-approval", **store.execute(requester, identifier, action), "effects": store.effect_count()}))
    try:
        store.execute(requester, identifier, action)
    except ApprovalDenied as exc:
        print(json.dumps({"stage": "reuse", "reason": str(exc), "effects": store.effect_count()}))
