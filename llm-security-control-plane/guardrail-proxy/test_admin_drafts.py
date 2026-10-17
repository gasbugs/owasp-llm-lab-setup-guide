"""Admin-only, content-addressed draft creation leaves the live policy unchanged."""

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


async def check():
    caller = {"Authorization": "Bearer " + os.environ["PROXY_CALLER_TOKEN"]}
    admin = {"Authorization": "Bearer " + os.environ["PROXY_ADMIN_TOKEN"]}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=server.app),
                                 base_url="http://test") as client:
        assert (await client.get("/admin/source")).status_code == 401
        assert (await client.get("/admin/source", headers=caller)).status_code == 401
        source = (await client.get("/admin/source", headers=admin)).json()
        original = (await client.get("/v1/policy", headers=caller)).json()
        assert source["base_digest"] == original["digest"]
        prompt = source["input_prompt"] + "\nAdditional example: ordinary recovery guidance is No."
        payload = {"base_digest": source["base_digest"], "version": "0.2.0",
                   "input_prompt": prompt}
        assert (await client.post("/admin/drafts", headers=caller,
                                  json=payload)).status_code == 401
        created = await client.post("/admin/drafts", headers=admin, json=payload)
        assert created.status_code == 201, created.text
        draft = created.json()
        assert draft["state"] == "draft" and draft["digest"] != original["digest"]
        assert (await client.get("/v1/policy", headers=caller)).json() == original
        assert draft in (await client.get("/admin/drafts", headers=admin)).json()["drafts"]
        assert (await client.post("/admin/drafts", headers=admin,
                                  json={**payload, "base_digest": "0" * 64})).status_code == 409
        assert (await client.post("/admin/drafts", headers=admin,
                                  json={**payload, "input_prompt": prompt + " {{ evil }}"})
                ).status_code == 422
        assert (await client.post("/admin/drafts", headers=admin,
                                  json={**payload, "unexpected": "secret"})
                ).status_code == 422
        assert (await client.get("/v1/policy", headers=caller)).json() == original


if __name__ == "__main__":
    asyncio.run(check())
    print("admin_drafts=PASS cases=auth,draft,active_unchanged,stale_base,template,shape")
