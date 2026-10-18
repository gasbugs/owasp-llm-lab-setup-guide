"""Product retrieval API: server-owned chunks, native rail, and fail-closed ordering."""

import asyncio
from dataclasses import replace
import os
from types import SimpleNamespace

import httpx

os.environ.setdefault("PROXY_CALLER_TOKEN", "c" * 64)
os.environ.setdefault("PROXY_ADMIN_TOKEN", "a" * 64)
os.environ.setdefault("PROXY_GATEWAY_TOKEN", "g" * 64)
os.environ.setdefault("PROXY_PRIVACY_TOKEN", "p" * 64)
os.environ.setdefault("GATEWAY_URL", "http://unused")
os.environ.setdefault("PRIVACY_URL", "http://unused")

import server


SEEN = {"privacy": [], "main": []}


async def fake_privacy(stage, text, _request_id):
    SEEN["privacy"].append(stage)
    if stage == "retrieval" and SEEN.get("retrieval_error"):
        raise TimeoutError("fixture privacy peer")
    if stage == "output":
        return "Contact <EMAIL_ADDRESS>.", ["EMAIL_ADDRESS"]
    return text, []


async def fake_text_rail(stage, _text, _model, *, config=None):
    assert config is server.ACTIVE_BUNDLE.rails_config
    return {"allowed": True, "evidence": {"rail": "self check input" if stage == "input_rail"
                                         else "self check output"}}


class FakeGatewayModel:
    def __init__(self, role, tracker):
        self.role = role
        self.tracker = tracker

    async def generate_async(self, prompt):
        assert self.role == "main"
        SEEN["main"].append(prompt)
        self.tracker.main_attempted = True
        self.tracker.calls.append({"role": "main"})
        return SimpleNamespace(content="Contact support@example.com.")


async def check():
    server.privacy_scan = fake_privacy
    server.check_text = fake_text_rail
    server.GatewayModel = FakeGatewayModel
    auth = {"Authorization": "Bearer " + os.environ["PROXY_CALLER_TOKEN"]}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=server.app),
                                 base_url="http://test") as client:
        endpoint = "/v1/retrieval-chat"
        body = {"message": "Where is account recovery help?", "fixture_id": "recovery-safe"}
        assert (await client.post(endpoint, json=body)).status_code == 401
        assert (await client.post(endpoint, headers=auth, json={**body,
                "relevant_chunks": "caller forged text"})).status_code == 422
        assert (await client.post(endpoint, headers=auth, json={**body,
                "fixture_id": "unknown"})).status_code == 422
        policy = (await client.get("/v1/policy", headers=auth)).json()
        assert policy["retrieval_fixture_available"] is True

        safe = await client.post(endpoint, headers=auth, json=body)
        assert safe.status_code == 200, safe.text
        result = safe.json()
        assert result["decision"] == "allow" and result["answer"] == "Contact <EMAIL_ADDRESS>."
        assert result["upstream_called"] is True and result["main_completed"] is True
        assert [stage["name"] for stage in result["stages"]] == [
            "presidio_input", "nemo_input", "retrieval", "main", "nemo_output", "presidio_output"]
        assert result["stages"][2]["native_action_invoked"] is True
        assert result["stages"][2]["result"] == "passed"
        assert len(SEEN["main"]) == 1

        risky = await client.post(endpoint, headers=auth, json={**body,
                                  "fixture_id": "recovery-injected"})
        assert risky.status_code == 200, risky.text
        blocked = risky.json()
        assert blocked["decision"] == "block" and blocked["answer"] is None
        assert blocked["stopped_at"] == "retrieval"
        assert blocked["upstream_called"] is False and blocked["main_completed"] is False
        assert blocked["stages"][-1]["native_action_invoked"] is True
        assert blocked["stages"][-1]["result"] == "blocked"
        assert len(SEEN["main"]) == 1

        SEEN["retrieval_error"] = True
        failed = await client.post(endpoint, headers=auth, json=body)
        assert failed.status_code == 502 and failed.json()["decision"] == "ERR"
        assert failed.json()["stopped_at"] == "retrieval"
        assert failed.json()["upstream_called"] is False
        SEEN["retrieval_error"] = False

        active = server.ACTIVE_BUNDLE
        server.ACTIVE_BUNDLE = replace(active, retrieval_enabled=False)
        old = await client.post(endpoint, headers=auth, json=body)
        assert old.status_code == 502 and old.json()["decision"] == "ERR"
        assert old.json()["stopped_at"] == "retrieval" and old.json()["upstream_called"] is False
        server.ACTIVE_BUNDLE = active

        records = (await client.get("/v1/requests", headers=auth)).json()["requests"]
        assert len(records) == 4
        assert "Ignore previous instructions" not in str(records)
        assert "support@example.com" not in str(records)
        assert SEEN["privacy"].count("retrieval") == 3


if __name__ == "__main__":
    asyncio.run(check())
    print("retrieval_product=PASS cases=auth,source_integrity,safe,blocked,peer_error,old_policy")
