# Guardrail Proxy API

This file-backed product slice supports text chat and a fixed, server-owned retrieval fixture. It runs in its own Compose project and exposes only the proxy on WSL loopback port `28906`. The Gateway alone mounts AWS credentials. NeMo reads `nemo-policy/config.yml`, `prompts.yml`, and the versioned `flows.co`; Presidio processes input, retrieved chunks, and output. The active policy is pinned for each request and the selected version persists in a named Docker volume.

From the setup checkout root, create `.state/guardrail-proxy.env` with distinct random `PROXY_CALLER_TOKEN`, `PROXY_ADMIN_TOKEN`, `PROXY_GATEWAY_TOKEN`, and `PROXY_PRIVACY_TOKEN` values of at least 40 characters, plus `LOCAL_UID` and `LOCAL_GID`. Keep this file outside Git. Build and start with:

```sh
cd llm-security-control-plane/guardrail-proxy
docker compose --env-file ../../.state/guardrail-proxy.env build gateway privacy proxy
docker compose --env-file ../../.state/guardrail-proxy.env up -d gateway privacy proxy
```

`GET /healthz` is public. `GET /v1/policy`, `GET /v1/requests`, and `POST /v1/chat` require `Authorization: Bearer <caller token>`. The chat body is `{"message":"What is one safe account recovery tip?"}`. A policy block returns HTTP 200 with `decision: block`; an engine/peer failure returns HTTP 502 with `decision: ERR`. Both include the stopped stage, whether the Main Gateway request was attempted (`upstream_called`), and whether a valid Main Gateway response was received (`main_completed`). A failed Main request may have been attempted without a confirmed provider result.

`POST /v1/retrieval-chat` requires the same caller token and accepts
`{"message":"Where is account recovery help?","fixture_id":"recovery-safe"}` or
`fixture_id: "recovery-injected"`. The caller selects one server-owned learning fixture;
it cannot supply a chunk body. The proxy scans the selected chunk with Presidio,
runs NeMo's native `dialog` plus `retrieval` flow, and checks that its registered
Action actually ran before calling Main. The fixed Colang dialog uses a local,
network-free model only to drive this rail; the allowed answer still uses the
Bedrock Gateway Main role. Missing rail evidence or an older active policy without
the retrieval flow returns HTTP 502 `ERR` before Main. A rejected injected chunk
returns `block` at the retrieval stage with `upstream_called=false`. The stage
record contains a fixture ID and digest, never the chunk text.
The request list is an in-memory, bounded, content-free operational summary and clears on restart. Administrator endpoints manage draft tests, activation, and rollback.

Open `http://127.0.0.1:28906/console/` for the same-origin operational console. Enter the caller token from the ignored environment file; the browser keeps it only in page memory. The console shows the active policy and actual request records and sends test calls through `/v1/chat`, which can incur Bedrock usage. Policy Versions provides administrator-controlled editing, candidate testing, activation, and rollback. The earlier course UI prototype is separate demo material.

Run `test_proxy.py`, `test_retrieval_product.py`, `test_privacy_response.py`, `test_policy_store.py`, `test_admin_drafts.py`, and `test_admin_lifecycle.py` inside the pinned API image, and `spokes/presidio-privacy/test_proxy_privacy.py` inside the pinned Privacy image; run a small live call against the built stack before claiming real integration. The proxy rejects mismatched request or stage evidence and a candidate that retains a detected value before calling the next stage. The synthetic `DEMO_API_KEY` recognizer accepts spaces around `=`. Tests check caller authentication, input stop before Main, normal input/output progression, timeout and peer-error behavior, overlapping entities, stage records, and absence of raw text in records. A `502` with `decision: ERR` is fail-closed evidence, not proof that the policy deliberately blocked the attack. General retrieval connectors, tool adapters, and population-level false-positive/false-negative estimates remain future work. The bounded 25-case matrix is an operational regression, not a population estimate. The checked-in 0.1.2 seed adds a repeated indirect hidden-prompt disclosure case to the promotion gate. An existing policy volume keeps its active digest until an administrator tests and promotes a draft; rebuilding the image alone does not change the active policy.

The console test selector can send either text chat or the two fixed retrieval fixtures. A Main call may incur Bedrock usage. Retrieval options are disabled when the active policy lacks the retrieval flow.

## Versioned policy administration

The proxy pins the active policy bundle for each request. A named Docker volume holds content-addressed bundles and an atomic active pointer across proxy recreation. A missing or tampered active bundle causes startup failure.

The console Policy Versions view uses a separate administrator token from the caller token. It permits edits to the input self-check prompt and semantic version only. Saving creates an inactive draft. Testing runs two normal and twelve attack calls through Presidio, NeMo and Bedrock. Retrieval-enabled candidates add one safe and one injected fixture; all sixteen results, including native Action evidence, must pass before promotion. Promotion checks the expected prior digest and updates the active pointer atomically. Previously activated versions can be selected for rollback. Both candidate tests and normal chat calls incur Bedrock usage. Tokens remain in page memory; keep the ignored environment file private.

A checked-in seed policy upgrade can be staged with `POST /admin/seed-draft` using `expected_active_digest`. It creates an inactive, content-addressed draft only when the image seed version is newer. Run the existing draft test and promote endpoints; candidates with retrieval also require safe and injected fixture results with native Action evidence. A failed candidate leaves the active policy unchanged.

The administrator API includes GET /admin/source, GET /admin/drafts, GET /admin/versions, POST /admin/drafts, POST /admin/seed-draft, POST /admin/drafts/{digest}/test, POST /admin/drafts/{digest}/promote, and POST /admin/rollback. Run the policy store, admin draft, and admin lifecycle tests alongside the existing proxy and privacy tests. Arbitrary retrieval connectors, tool adapters, and population-level misclassification estimates remain future work.

## Bounded live quality check

The publisher evaluator covers 12 normal and 13 attack expressions, including Korean, quoted reports, paraphrased hidden instructions, encoded disclosure, and PII mixed with an instruction. It checks HTTP status, decision, stage, upstream call, and policy digest without recording prompt or answer text. Set PROXY_CALLER_TOKEN in the process environment from the ignored environment file and run:

~~~sh
python3 evaluate_policy_quality.py --base-url http://127.0.0.1:28906 --repeats 3 --output /tmp/guardrail-proxy-quality.json
~~~

The command exits nonzero on any mismatch. Its Bedrock calls incur cost; keep the output outside Git until reviewed and summarize verified results in course evidence. A passing fixed matrix does not prove all possible wording or intent is detected.
