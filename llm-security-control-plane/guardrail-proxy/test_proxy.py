"""Deterministic API-boundary regression without Bedrock or Docker peers."""

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


MODE = {"input_block": False, "output_block": False, "privacy_error_stage": None,
        "main_calls": 0, "privacy_output_calls": 0}


async def fake_privacy(stage, text, request_id):
    if stage == "input" and MODE.get("hold_input"):
        MODE["input_entered"].set()
        await MODE["release_input"].wait()
    if MODE["privacy_error_stage"] == stage:
        raise TimeoutError("fixture")
    if stage == "output":
        MODE["privacy_output_calls"] += 1
        return "<EMAIL_ADDRESS>", ["EMAIL_ADDRESS"]
    return text.replace("sample@example.com", "<EMAIL_ADDRESS>"), ["EMAIL_ADDRESS"] if "@" in text else []


async def fake_rail(stage, text, model, *, config=None):
    MODE.setdefault("seen_configs", []).append(config)
    blocked = MODE["input_block"] if stage == "input_rail" else MODE["output_block"]
    return {"allowed": not blocked, "evidence": {"rail": "self check input" if stage == "input_rail" else "self check output"}}


class FakeModel:
    def __init__(self, role, tracker):
        self.role, self.tracker = role, tracker

    async def generate_async(self, prompt):
        assert self.role == "main"
        MODE["main_calls"] += 1
        self.tracker.main_attempted = True
        self.tracker.calls.append({"role": "main"})
        return SimpleNamespace(content="Contact sample@example.com")


async def check():
    server.privacy_scan = fake_privacy
    server.check_text = fake_rail
    server.GatewayModel = FakeModel
    auth = {"Authorization": "Bearer " + os.environ["PROXY_CALLER_TOKEN"]}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=server.app), base_url="http://test") as client:
        assert (await client.post("/v1/chat", json={"message": "hello"})).status_code == 401
        assert (await client.post("/v1/chat", json={"message": {"secret": "do-not-echo"}})).status_code == 401
        invalid = await client.post("/v1/chat", headers=auth, json={"message": "hello", "secret": "do-not-echo"})
        assert invalid.status_code == 422 and "do-not-echo" not in invalid.text
        policy = (await client.get("/v1/policy", headers=auth)).json()
        assert policy["read_only"] is True and policy["digest"] == server.POLICY_DIGEST

        MODE["input_block"] = True
        blocked = (await client.post("/v1/chat", headers=auth, json={"message": "risk"})).json()
        assert blocked["decision"] == "block" and blocked["answer"] is None
        assert blocked["upstream_called"] is False and MODE["main_calls"] == 0
        assert [stage["name"] for stage in blocked["stages"]] == ["presidio_input", "nemo_input"]

        MODE["input_block"] = False
        allowed = (await client.post("/v1/chat", headers=auth, json={"message": "sample@example.com"})).json()
        assert allowed["decision"] == "allow" and allowed["answer"] == "<EMAIL_ADDRESS>"
        assert allowed["upstream_called"] is True and MODE["main_calls"] == 1
        assert [stage["name"] for stage in allowed["stages"]] == [
            "presidio_input", "nemo_input", "main", "nemo_output", "presidio_output"]

        MODE["output_block"] = True
        before = MODE["privacy_output_calls"]
        output_block = (await client.post("/v1/chat", headers=auth, json={"message": "hello"})).json()
        assert output_block["decision"] == "block" and output_block["upstream_called"] is True
        assert MODE["privacy_output_calls"] == before

        MODE["output_block"] = False
        MODE["privacy_error_stage"] = "input"
        error = await client.post("/v1/chat", headers=auth, json={"message": "hello"})
        assert error.status_code == 502 and error.json()["decision"] == "ERR"
        assert error.json()["upstream_called"] is False
        MODE["privacy_error_stage"] = "output"
        before = MODE["main_calls"]
        late_error = await client.post("/v1/chat", headers=auth, json={"message": "hello"})
        assert late_error.status_code == 502 and late_error.json()["decision"] == "ERR"
        assert late_error.json()["stopped_at"] == "presidio_output"
        assert late_error.json()["upstream_called"] is True and MODE["main_calls"] == before + 1
        assert "sample@example.com" not in late_error.text
        MODE["privacy_error_stage"] = None

        records = (await client.get("/v1/requests", headers=auth)).json()["requests"]
        assert len(records) == 5 and "sample@example.com" not in str(records)
        assert all(item["policy_digest"] == server.POLICY_DIGEST for item in records)

        base = server.ACTIVE_BUNDLE
        alternate = replace(base, digest="f" * 64, rails_config=object(),
                            limit=asyncio.Semaphore(2))
        MODE["seen_configs"] = []
        MODE["hold_input"] = True
        MODE["input_entered"] = asyncio.Event()
        MODE["release_input"] = asyncio.Event()
        in_flight = asyncio.create_task(client.post("/v1/chat", headers=auth,
                                                     json={"message": "hello"}))
        await asyncio.wait_for(MODE["input_entered"].wait(), timeout=5)
        server.ACTIVE_BUNDLE = alternate
        MODE["release_input"].set()
        pinned = (await in_flight).json()
        assert pinned["policy_digest"] == base.digest
        assert MODE["seen_configs"] == [base.rails_config, base.rails_config]
        MODE["hold_input"] = False
        MODE["seen_configs"] = []
        latest = (await client.post("/v1/chat", headers=auth,
                                     json={"message": "hello"})).json()
        assert latest["policy_digest"] == alternate.digest
        assert MODE["seen_configs"] == [alternate.rails_config, alternate.rails_config]
        assert (await client.get("/v1/policy", headers=auth)).json()["digest"] == alternate.digest
        server.ACTIVE_BUNDLE = base


if __name__ == "__main__":
    asyncio.run(check())
    print("proxy_api_contract=PASS cases=auth,validation,block,allow,output_block,input_error,output_timeout,records,inflight_policy_pin")
