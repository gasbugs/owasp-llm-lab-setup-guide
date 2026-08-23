# LLM Security Observability Stack

`compose.yaml` is the canonical Module 08 deployment. Learners first inspect the
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
client -> gateway -> input policy -> internal retrieval service
       -> tenant policy -> tool authorization -> local Bedrock Gateway -> output policy

internal bridge: gateway/retrieval -> Alloy, Prometheus -> all metrics,
                 Alloy/Prometheus -> LGTM, Alertmanager -> webhook
host boundary:   published ports -> learner public IPv4 /32 security group
```

The gateway derives tenant and dangerous-tool permissions from the bearer-token map. A request body cannot select authorization attributes. A request blocked at input, retrieval, or tool authorization returns `upstream_called=false` and never reaches Amazon Bedrock.

## Telemetry and alert paths

```text
gateway + retrieval --OTLP logs/traces--> Alloy ----logs----> Loki
                                  \----traces--> Tempo --span RED/service graph--> Prometheus
Podman rootless socket --stdout/stderr--> Alloy --> Loki

application + local Bedrock Gateway + Alloy + LGTM + alert services
       --/metrics--> Prometheus --rules--> Alertmanager --> alert webhook

Grafana --> Prometheus + Loki + Tempo + Alertmanager
```

Prometheus is the local metric store, scraper, remote-write receiver, and rule evaluator. Tempo 3.x runs in monolithic `target=all` mode without Kafka, generates RED and service-graph metrics from traces, and remote-writes them to Prometheus. Alertmanager's webhook receiver proves that an evaluated alert reached a final destination instead of stopping at `firing` state.

Alloy performs two separate jobs from one configuration: it receives structured OTLP logs and traces from the application, and it discovers this stack's `llm-sec-*` containers through the rootless Podman API to collect stdout and stderr. Container log lines are size-limited and common demo secrets are redacted before Loki ingestion.

## Data and trust boundaries

- Host-published ports listen on the EC2 interface and are reachable only from the learner public IPv4 `/32` allowed by the security group. Never allow `0.0.0.0/0`.
- Raw prompts are not stored. The structured event contains a keyed HMAC identity, a sanitized excerpt, decision, rule, stage, request ID, and trace ID.
- Request IDs and trace IDs remain log fields or exemplars, not metric or Loki stream labels, to avoid unbounded cardinality.
- Prometheus retains lab metrics for 24 hours. Loki and Tempo keep their lab data in named volumes that survive the learner stop command.
- A read-only bind option does not make the Podman API read-only. The lab limits impact with a rootless socket and a container-name allowlist. Production deployments should prefer journal/file collection or an authenticated allowlist socket proxy.
- Anonymous Grafana access and default lab tokens are acceptable only in this temporary lab behind a learner-owned `/32` security-group rule. Production deployments require real identity, authorization, secret rotation, TLS, and backend multi-tenancy.
- Alloy queues are memory-backed and each backend is a single lab process. A production design needs persistent buffering, object storage, replication, access control, capacity planning, backup, and tested recovery objectives.
- Grafana's bundled plugin preinstallation and update checks are disabled so the lab does not silently download code at startup. Only the built-in data sources used by the provisioned dashboard are required.
- The rootless Podman 4.9 lab uses one private bridge because its CNI DNS does not reliably fall through between multiple network DNS zones. External exposure is restricted by the learner-owned `/32` security-group rule. A production Kubernetes deployment should separate application, telemetry, and backend planes with directional NetworkPolicy instead of treating this lab bridge as network isolation.

## Start on GPU-less WSL

```bash
export BEDROCK_MODEL_ID=us.amazon.nova-lite-v1:0
export PODMAN_COMPOSE_PROVIDER=podman-compose
export PODMAN_SOCKET_PATH=/run/user/$(id -u)/podman/podman.sock
podman compose --file compose.yaml up --detach --build
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
podman compose --file compose.yaml down
```

The learner command intentionally preserves named volumes. Publisher E2E adds `--volumes` because each validation run must start from isolated data.
