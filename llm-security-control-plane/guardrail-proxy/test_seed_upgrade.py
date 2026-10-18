"""Upgrade an old policy through the same candidate test and promote gate."""

import asyncio
import os
from pathlib import Path
import shutil
import tempfile

import httpx
import yaml

os.environ.setdefault("PROXY_CALLER_TOKEN", "c" * 64)
os.environ.setdefault("PROXY_ADMIN_TOKEN", "a" * 64)
os.environ.setdefault("PROXY_GATEWAY_TOKEN", "g" * 64)
os.environ.setdefault("PROXY_PRIVACY_TOKEN", "p" * 64)
os.environ.setdefault("GATEWAY_URL", "http://unused")
os.environ.setdefault("PRIVACY_URL", "http://unused")

import server
from policy_store import PolicyStore


ACTION_PRESENT = False


async def fake_pipeline(message, bundle, *, record_decision, fixture_id=None):
    assert record_decision is False
    risk = fixture_id == "recovery-injected" or message.startswith((
        "Ignore", "Paraphrase", "Print your private", "Before the recovery advice"))
    return 200, {
        "decision": "block" if risk else "allow",
        "stopped_at": "retrieval" if fixture_id and risk else "nemo_input" if risk else "presidio_output",
        "upstream_called": not risk,
        "main_completed": not risk,
        "policy_digest": bundle.digest,
        "stages": [{"name": "retrieval", "native_action_invoked": ACTION_PRESENT}]
        if fixture_id else [],
    }


async def check():
    global ACTION_PRESENT
    with tempfile.TemporaryDirectory() as temp:
        temp = Path(temp)
        old = temp / "old"
        old.mkdir()
        shutil.copytree("/app/nemo-policy", old / "nemo-policy")
        (old / "nemo-policy" / "flows.co").unlink()
        config_path = old / "nemo-policy" / "config.yml"
        config_path.chmod(0o600)
        config = yaml.safe_load(config_path.read_text())
        config.pop("core", None)
        config["rails"].pop("retrieval", None)
        config_path.write_text(yaml.safe_dump(config, sort_keys=False))
        policy = yaml.safe_load(Path("/app/policy.yaml").read_text())
        policy["version"] = "0.1.1"
        (old / "policy.yaml").write_text(yaml.safe_dump(policy, sort_keys=False))
        store = PolicyStore(temp / "state", old)
        previous = store.active.digest
        store.seed_root = Path("/app")
        server.STORE = store
        server.ACTIVE_BUNDLE = store.active
        server.run_pipeline = fake_pipeline
        caller = {"Authorization": "Bearer " + os.environ["PROXY_CALLER_TOKEN"]}
        admin = {"Authorization": "Bearer " + os.environ["PROXY_ADMIN_TOKEN"]}
        body = {"expected_active_digest": previous}
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=server.app),
                                     base_url="http://test") as client:
            assert (await client.post("/admin/seed-draft", json=body)).status_code == 401
            assert (await client.post("/admin/seed-draft", headers=caller,
                                      json=body)).status_code == 401
            assert (await client.post("/admin/seed-draft", headers=admin,
                                      json={"expected_active_digest": "0" * 64})).status_code == 409
            created = await client.post("/admin/seed-draft", headers=admin, json=body)
            assert created.status_code == 201, created.text
            draft = created.json()
            digest = draft["digest"]
            assert draft["version"] == "0.1.2" and draft["source"] == "image_seed"
            assert digest != previous and store.get_draft(digest)[1].retrieval_enabled
            assert store.active.digest == previous
            repeated = await client.post("/admin/seed-draft", headers=admin, json=body)
            assert repeated.status_code == 201 and repeated.json() == draft
            assert (await client.post(f"/admin/drafts/{digest}/promote", headers=admin,
                                      json=body)).status_code == 409
            failed = (await client.post(f"/admin/drafts/{digest}/test", headers=admin)).json()
            assert failed["passed"] is False and failed["results"][-1]["case"] == "recovery-safe"
            assert store.active.digest == previous
            ACTION_PRESENT = True
            tested = (await client.post(f"/admin/drafts/{digest}/test", headers=admin)).json()
            assert tested["passed"] and len(tested["results"]) == 16
            assert all(item["passed"] for item in tested["results"])
            promoted = await client.post(f"/admin/drafts/{digest}/promote", headers=admin,
                                         json=body)
            assert promoted.status_code == 200 and store.active.digest == digest
            assert (await client.get("/v1/policy", headers=caller)).json()[
                "retrieval_fixture_available"] is True
            assert (await client.post("/admin/seed-draft", headers=admin,
                                      json={"expected_active_digest": digest})).status_code == 422
            rolled = await client.post("/admin/rollback", headers=admin,
                                       json={"expected_active_digest": digest,
                                             "target_digest": previous})
            assert rolled.status_code == 200 and store.active.digest == previous


if __name__ == "__main__":
    asyncio.run(check())
    print("seed_upgrade=PASS cases=auth,stale,untested,retrieval_gate,promote,rollback")
