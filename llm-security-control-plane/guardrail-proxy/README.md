# Guardrail Proxy API

This is the first file-backed, text-only product slice. It runs in its own Compose project and exposes only the proxy on WSL loopback port `28906`. The Gateway alone mounts AWS credentials. NeMo reads `nemo-policy/config.yml` and `prompts.yml`; Presidio processes input and output. The active policy is immutable while the container runs.

From the setup checkout root, create `.state/guardrail-proxy.env` with distinct random `PROXY_CALLER_TOKEN`, `PROXY_GATEWAY_TOKEN`, and `PROXY_PRIVACY_TOKEN` values of at least 40 characters, plus `LOCAL_UID` and `LOCAL_GID`. Keep this file outside Git. Build and start with:

```sh
cd llm-security-control-plane/guardrail-proxy
docker compose --env-file ../../.state/guardrail-proxy.env build gateway privacy proxy
docker compose --env-file ../../.state/guardrail-proxy.env up -d gateway privacy proxy
```

`GET /healthz` is public. `GET /v1/policy`, `GET /v1/requests`, and `POST /v1/chat` require `Authorization: Bearer <caller token>`. The chat body is `{"message":"What is one safe account recovery tip?"}`. A policy block returns HTTP 200 with `decision: block`; an engine/peer failure returns HTTP 502 with `decision: ERR`. Both include the stopped stage and whether the Main model was attempted. The request list is an in-memory, bounded, content-free operational summary and clears on restart. No policy mutation endpoint is present.

Open `http://127.0.0.1:28906/console/` for the same-origin operational console. Enter the caller token from the ignored environment file; the browser keeps it only in page memory. The console shows the active policy and actual request records and sends test calls through `/v1/chat`, which can incur Bedrock usage. Policy editing, promotion, and rollback remain unavailable and are labeled accordingly. The earlier course UI prototype is separate demo material.

Run the deterministic contract inside the pinned API image with product files mounted at `/app`; run a small live call against the built stack before claiming real integration. Tests must confirm caller authentication, input stop before Main, normal input/output progression, failure behavior, stage ledger, and absence of raw text in records. This slice does not yet implement policy version changes, UI editing, retrieval/tool adapters, or a broad false-positive/false-negative evaluation.
