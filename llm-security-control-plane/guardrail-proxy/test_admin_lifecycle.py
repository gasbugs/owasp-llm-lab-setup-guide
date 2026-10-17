"""Draft tests must pass before atomic promotion; failed tests never activate."""

import asyncio
import os

import httpx

os.environ.setdefault("PROXY_CALLER_TOKEN", "c" * 64)
os.environ.setdefault("PROXY_ADMIN_TOKEN", "a" * 64)
os.environ.setdefault("PROXY_GATEWAY_TOKEN", "g" * 64)
os.environ.setdefault("PROXY_PRIVACY_TOKEN", "p" * 64)
os.environ.setdefault("GATEWAY_URL", "http://unused")
os.environ.setdefault("PRIVACY_URL", "http://unused")

import server


FAIL_RISK = False


async def fake_pipeline(message, bundle, *, record_decision):
    assert record_decision is False
    risk = message.startswith(("Ignore", "Paraphrase", "Print your private"))
    if risk and FAIL_RISK:
        return 502, {"decision": "ERR", "stopped_at": "nemo_input",
                     "upstream_called": False, "policy_digest": bundle.digest}
    return 200, {"decision": "block" if risk else "allow",
                 "stopped_at": "nemo_input" if risk else "presidio_output",
                 "upstream_called": not risk, "policy_digest": bundle.digest}


async def check():
    global FAIL_RISK
    server.run_pipeline = fake_pipeline
    caller = {"Authorization": "Bearer " + os.environ["PROXY_CALLER_TOKEN"]}
    admin = {"Authorization": "Bearer " + os.environ["PROXY_ADMIN_TOKEN"]}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=server.app),
                                 base_url="http://test") as client:
        source = (await client.get("/admin/source", headers=admin)).json()
        old = source["base_digest"]
        created = (await client.post("/admin/drafts", headers=admin, json={
            "base_digest": old, "version": "0.2.0",
            "input_prompt": source["input_prompt"] + "\nExample: ordinary recovery help is No.",
        })).json()
        digest = created["digest"]
        target = f"/admin/drafts/{digest}"
        assert (await client.post(target + "/promote", headers=admin,
                                  json={"expected_active_digest": old})).status_code == 409
        assert (await client.post(target + "/test", headers=caller)).status_code == 401
        tested = (await client.post(target + "/test", headers=admin)).json()
        assert tested["passed"] and len(tested["results"]) == 11
        assert all(item["passed"] for item in tested["results"])
        assert (await client.get("/v1/policy", headers=caller)).json()["digest"] == old
        assert (await client.post(target + "/promote", headers=admin,
                                  json={"expected_active_digest": "0" * 64})).status_code == 409
        promoted = await client.post(target + "/promote", headers=admin,
                                      json={"expected_active_digest": old})
        assert promoted.status_code == 200, promoted.text
        assert promoted.json() == {"state": "active", "digest": digest,
                                   "previous_digest": old}
        assert (await client.get("/v1/policy", headers=caller)).json()["digest"] == digest
        assert (await client.post("/admin/rollback", headers=caller, json={
            "expected_active_digest": digest, "target_digest": old})).status_code == 401
        assert (await client.post("/admin/rollback", headers=admin, json={
            "expected_active_digest": "0" * 64, "target_digest": old})).status_code == 409
        rolled = await client.post("/admin/rollback", headers=admin, json={
            "expected_active_digest": digest, "target_digest": old})
        assert rolled.status_code == 200 and rolled.json()["digest"] == old
        assert server.STORE.load_active().digest == old
        assert (await client.get("/v1/policy", headers=caller)).json()["digest"] == old
        forward = await client.post("/admin/rollback", headers=admin, json={
            "expected_active_digest": old, "target_digest": digest})
        assert forward.status_code == 200 and forward.json()["digest"] == digest
        assert (await client.get("/v1/policy", headers=caller)).json()["digest"] == digest
        assert server.STORE.load_active().digest == digest
        assert (await client.get("/admin/drafts", headers=admin)).json()["drafts"][0]["state"] == "active"

        current = (await client.get("/admin/source", headers=admin)).json()
        second = (await client.post("/admin/drafts", headers=admin, json={
            "base_digest": digest, "version": "0.3.0",
            "input_prompt": current["input_prompt"] + "\nExample: another ordinary request is No.",
        })).json()["digest"]
        FAIL_RISK = True
        failed = (await client.post(f"/admin/drafts/{second}/test", headers=admin)).json()
        assert failed["passed"] is False and failed["results"][-1]["decision"] == "ERR"
        assert (await client.post(f"/admin/drafts/{second}/promote", headers=admin,
                                  json={"expected_active_digest": digest})).status_code == 409
        assert (await client.get("/v1/policy", headers=caller)).json()["digest"] == digest


if __name__ == "__main__":
    asyncio.run(check())
    print("admin_lifecycle=PASS cases=untested_rejected,tested,promoted,persistent,rollback,failed_test")
