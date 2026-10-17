# Guardrail Proxy native technical spike

Publisher-only probe for the first product gate. The Compose project builds the pinned Gateway, Presidio, and NeMo images from this setup checkout. Its two networks and Docker state are separate from the existing guided-practice and course stacks; no port is published to the host. Only Gateway mounts the local AWS profile read-only. The runner uses two temporary service tokens from the ignored `.state/guardrail-proxy-spike.env` file.

From this directory, create that file with independent random `SPIKE_GATEWAY_TOKEN` and `SPIKE_PRIVACY_TOKEN` values plus `LOCAL_UID=$(id -u)` and `LOCAL_GID=$(id -g)`. Set file mode `0600`. The active AWS `default` profile must be checked before a paid run.

```bash
docker compose --env-file ../../.state/guardrail-proxy-spike.env config -q
docker compose --env-file ../../.state/guardrail-proxy-spike.env build gateway privacy runner
docker compose --env-file ../../.state/guardrail-proxy-spike.env up -d gateway privacy
docker compose --env-file ../../.state/guardrail-proxy-spike.env run --rm runner
```

The probe loads `policy/config.yml` and `policy/prompts.yml` through NeMo `RailsConfig.from_path`. It verifies one synthetic API-key input that native NeMo input self-check stops before Main Model, plus two ordinary account-recovery inputs that reach Main Model, native output self-check, and Presidio output. It reports stage decisions, provider request IDs, token counts, and elapsed times without printing request or model-response text. The initial H12 policy fixture produced false positives; this file-backed policy passed three consecutive runs of all three cases. Those fixtures do **not** establish broad false-positive rates or an operational proxy API. Retrieval/tool rails, policy versions, authorization, and UI integration remain later gates.
