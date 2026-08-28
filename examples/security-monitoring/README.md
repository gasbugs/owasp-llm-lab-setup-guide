# LLM Security Observability Stack

`compose.yaml` is the canonical Module 09 observability deployment. Learners first inspect the
application code that emits one structured security log, a distributed trace,
and bounded Prometheus metrics. They verify each raw signal before following it
through Alloy and the storage backends. The module ends by building a minimal
three-panel Grafana dashboard and comparing it with the provisioned
`grafana/dashboards/llm-security.json` operations dashboard.

## Learner path

```text
application instrumentation
  -> raw /metrics and response trace_id
  -> Alloy collection and processing
  -> Loki logs + Tempo traces + Prometheus metrics
  -> learner-built Metric/Log/Trace dashboard
  -> provisioned dashboard JSON with alerts, Bedrock usage, RED, and queue health
```

## Request path

```text
browser -> Module 08 Application :18095 -> NeMo/Presidio
        -> local Bedrock Gateway -> Amazon Bedrock

Security Events :8014 <- metadata-only events from Application and local services

internal bridge: gateway/retrieval -> Alloy, Prometheus -> all metrics,
                 Alloy/Prometheus -> LGTM, Alertmanager -> webhook
host boundary:   published ports -> learner public IPv4 /32 security group
```

The Application derives identity and authorization from its signed access token.
The Security Events service on `:8014` is a lookup and telemetry component, not
a second chat API. Requests blocked by Application or a Guardrail return
`upstream_called=false` and never reach Amazon Bedrock.

## Telemetry and alert paths

```text
gateway + retrieval --OTLP logs/traces--> Alloy ----logs----> Loki
                                  \----traces--> Tempo --span RED/service graph--> Prometheus

application + local Bedrock Gateway + Alloy + LGTM + alert services
       --/metrics--> Prometheus --rules--> Alertmanager --> alert webhook

Grafana --> Prometheus + Loki + Tempo + Alertmanager
```

Prometheus is the local metric store, scraper, remote-write receiver, and rule evaluator. Tempo 3.x runs in monolithic `target=all` mode without Kafka, generates RED and service-graph metrics from traces, and remote-writes them to Prometheus. Alertmanager's webhook receiver proves that an evaluated alert reached a final destination instead of stopping at `firing` state.

Alloy receives only the structured OTLP logs and traces that the instrumented application explicitly exports. It does not receive the Podman API socket, so the collector cannot enumerate or control the learner's other rootless containers. Raw text is reduced to a keyed HMAC identity and a sanitized excerpt in the application before the OTLP boundary.

## Data and trust boundaries

- Host-published ports bind only to WSL loopback. Container-to-container traffic uses the private Compose network and no observability backend is published on a LAN interface.
- Raw prompts are not stored. The structured event contains a keyed HMAC identity, a sanitized excerpt, decision, rule, stage, request ID, and trace ID.
- Request IDs and trace IDs remain log fields or exemplars, not metric or Loki stream labels, to avoid unbounded cardinality.
- Prometheus retains lab metrics for 24 hours. Loki and Tempo keep their lab data in named volumes that survive the learner stop command.
- Every host port binds to WSL loopback, Grafana anonymous access is disabled, and service credentials come from the permission-restricted Module 08 environment file. Production deployments still require managed identity, authorization, secret rotation, TLS, network policy, and backend multi-tenancy.
- Alloy queues are memory-backed and each backend is a single lab process. A production design needs persistent buffering, object storage, replication, access control, capacity planning, backup, and tested recovery objectives.
- Grafana's bundled plugin preinstallation and update checks are disabled so the lab does not silently download code at startup. Only the built-in data sources used by the provisioned dashboard are required.
- The rootless Podman 4.9 lab uses one private bridge because its CNI DNS does not reliably fall through between multiple network DNS zones. External exposure is restricted by the learner-owned `/32` security-group rule. A production Kubernetes deployment should separate application, telemetry, and backend planes with directional NetworkPolicy instead of treating this lab bridge as network isolation.

## Start on GPU-less WSL

```bash
export BEDROCK_MODEL_ID=us.amazon.nova-lite-v1:0
export PODMAN_COMPOSE_PROVIDER=podman-compose
export COMPOSE_ENV_FILE="$HOME/owasp-llm-lab-setup-guide/llm-security-control-plane/.state/module08-compose.env"
podman-compose --project-name llm-security-observability \
  --env-file "$COMPOSE_ENV_FILE" --file compose.yaml up --detach --build
```

## Publisher regression

The default E2E uses a deterministic Bedrock contract double. The real validation path uses the local credential-isolating Gateway and Amazon Nova Lite.

```bash
bash tests/e2e/security-monitoring/test_security_monitoring.sh
USE_REAL_BEDROCK=true RUN_FAILURE_DRILL=true \
  bash tests/e2e/security-monitoring/test_security_monitoring.sh
```

## Stop

```bash
podman-compose --project-name llm-security-observability \
  --env-file "$COMPOSE_ENV_FILE" --file compose.yaml down
```

The learner command intentionally preserves named volumes. Publisher E2E adds `--volumes` because each validation run must start from isolated data.
