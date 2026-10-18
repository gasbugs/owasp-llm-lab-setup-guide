"""Product tool fixture API: server validation before tool and Main boundaries."""

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
    if stage == "tool_result" and SEEN.get("peer_error"):
        raise TimeoutError("tool privacy peer")
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
        return SimpleNamespace(content="Use the official support page.")


async def check():
    server.privacy_scan = fake_privacy
    server.check_text = fake_text_rail
    server.GatewayModel = FakeGatewayModel
    auth = {"Authorization": "Bearer " + os.environ["PROXY_CALLER_TOKEN"]}
    body = {"message": "Where is account recovery help?", "fixture_id": "status-safe"}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=server.app),
                                 base_url="http://test") as client:
        assert (await client.post("/v1/tool-chat", json=body)).status_code == 401
        assert (await client.post("/v1/tool-chat", headers=auth, json={
            **body, "tool_call": {"name": "get_account_recovery_status"}})).status_code == 422
        assert (await client.post("/v1/tool-chat", headers=auth, json={
            **body, "fixture_id": "unknown"})).status_code == 422
        policy = (await client.get("/v1/policy", headers=auth)).json()
        assert policy["tool_fixture_available"] is True
        assert policy["native_tool_rail"] is False

        safe = await client.post("/v1/tool-chat", headers=auth, json=body)
        assert safe.status_code == 200, safe.text
        result = safe.json()
        assert result["decision"] == "allow" and result["tool_executed"] is True
        assert result["upstream_called"] is True and result["main_completed"] is True
        assert [stage["name"] for stage in result["stages"]] == [
            "presidio_input", "nemo_input", "tool_input", "tool_result", "main",
            "nemo_output", "presidio_output"]
        assert result["stages"][3]["native_action_invoked"] is True
        assert len(SEEN["main"]) == 1

        expected = {
            "status-injected": ("tool_result", True),
            "status-unknown-tool": ("tool_input", False),
            "status-invalid-args": ("tool_input", False),
            "status-forged-result": ("tool_result", True),
        }
        for fixture_id, (stop, executed) in expected.items():
            blocked = await client.post("/v1/tool-chat", headers=auth,
                                        json={**body, "fixture_id": fixture_id})
            assert blocked.status_code == 200, blocked.text
            value = blocked.json()
            assert value["decision"] == "block" and value["stopped_at"] == stop
            assert value["tool_executed"] is executed
            assert value["upstream_called"] is False and value["main_completed"] is False
        assert len(SEEN["main"]) == 1
        assert SEEN["privacy"].count("tool_result") == 2

        SEEN["peer_error"] = True
        failed = await client.post("/v1/tool-chat", headers=auth, json=body)
        assert failed.status_code == 502 and failed.json()["decision"] == "ERR"
        assert failed.json()["stopped_at"] == "tool_result"
        assert failed.json()["tool_executed"] is True
        assert failed.json()["upstream_called"] is False
        SEEN["peer_error"] = False

        active = server.ACTIVE_BUNDLE
        server.ACTIVE_BUNDLE = replace(active, retrieval_enabled=False)
        old = await client.post("/v1/tool-chat", headers=auth, json=body)
        assert old.status_code == 502 and old.json()["decision"] == "ERR"
        assert old.json()["stopped_at"] == "tool_input"
        assert old.json()["tool_executed"] is False
        server.ACTIVE_BUNDLE = active

        records = (await client.get("/v1/requests", headers=auth)).json()["requests"]
        assert len(records) == 7
        assert "Ignore previous instructions" not in str(records)
        assert "training-account" not in str(records)


if __name__ == "__main__":
    asyncio.run(check())
    print("tool_product=PASS cases=auth,source_integrity,safe,input_block,output_block,peer_error,old_policy")
