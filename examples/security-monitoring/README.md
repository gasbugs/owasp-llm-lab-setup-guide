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
  -> Loki logs + Tempo traces + Mimir metrics
  -> learner-built Metric/Log/Trace dashboard
  -> provisioned dashboard JSON with alerts, GPU, RED, and queue health
```

## Request path

```text
client -> gateway -> input policy -> internal retrieval service
       -> tenant policy -> tool authorization -> Ollama -> output policy

internal bridge: gateway/retrieval -> Alloy, Prometheus -> all metrics,
                 Alloy/Prometheus -> LGTM, Alertmanager -> webhook
host boundary:   every published port -> 127.0.0.1 only
```

The gateway derives tenant and dangerous-tool permissions from the bearer-token map. A request body cannot select authorization attributes. A request blocked at input, retrieval, or tool authorization returns `upstream_called=false` and never reaches Ollama.

## Telemetry and alert paths

```text
gateway + retrieval --OTLP logs/traces--> Alloy ----logs----> Loki
                                  \----traces--> Tempo --span RED/service graph--> Mimir
Podman rootless socket --stdout/stderr--> Alloy --> Loki

gateway + Alloy + LGTM + alert services + GPU exporter
       --/metrics--> Prometheus --remote_write/exemplars--> Mimir
                       \--rules--> Alertmanager --> alert webhook

Grafana --> Mimir + Loki + Tempo + Alertmanager
```

Prometheus is the local scraper and rule evaluator. Mimir is the dashboard's durable Prometheus-compatible metric store. Tempo generates RED and service-graph metrics from traces and writes them to Mimir. Alertmanager's webhook receiver proves that an evaluated alert reached a final destination instead of stopping at `firing` state.

Alloy performs two separate jobs from one configuration: it receives structured OTLP logs and traces from the application, and it discovers this stack's `llm-sec-*` containers through the rootless Podman API to collect stdout and stderr. Container log lines are size-limited and common demo secrets are redacted before Loki ingestion.

## Data and trust boundaries

- All host-published ports bind to `127.0.0.1`; the stack is reached through the existing SSM forwarding path.
- Raw prompts are not stored. The structured event contains a keyed HMAC identity, a sanitized excerpt, decision, rule, stage, request ID, and trace ID.
- Request IDs and trace IDs remain log fields or exemplars, not metric or Loki stream labels, to avoid unbounded cardinality.
- Prometheus, Mimir, Loki, and Tempo retain lab data for 24 hours. Named volumes survive the learner stop command.
- A read-only bind option does not make the Podman API read-only. The lab limits impact with a rootless socket and a container-name allowlist. Production deployments should prefer journal/file collection or an authenticated allowlist socket proxy.
- Anonymous Grafana access and default lab tokens are safe only behind the loopback boundary. Production deployments require real identity, authorization, secret rotation, TLS, and backend multi-tenancy.
- Alloy queues are memory-backed and each backend is a single lab process. A production design needs persistent buffering, object storage, replication, access control, capacity planning, backup, and tested recovery objectives.
- Grafana's bundled plugin preinstallation and update checks are disabled so the lab does not silently download code at startup. Only the built-in data sources used by the provisioned dashboard are required.
- The rootless Podman 4.9 lab uses one private bridge because its CNI DNS does not reliably fall through between multiple network DNS zones. External exposure is still restricted by loopback-only publishing. A production Kubernetes deployment should separate application, telemetry, and backend planes with directional NetworkPolicy instead of treating this lab bridge as network isolation.

## Start on the GPU host

```bash
export OLLAMA_MODEL=llama3.1:8b-instruct-q4_K_M
export PODMAN_COMPOSE_PROVIDER=podman-compose
podman compose --file compose.yaml --file compose.gpu.yaml up --detach --build
```

The GPU exporter receives only the NVIDIA CDI device and converts a fixed read-only `nvidia-smi` query to Prometheus metrics. The project runs rootless without `sudo`, `privileged`, or additional Linux capabilities.

## Publisher regression

The default E2E uses a deterministic Ollama contract double. The real validation path uses the actual Ollama model and NVIDIA GPU.

```bash
bash tests/e2e/security-monitoring/test_security_monitoring.sh
USE_REAL_OLLAMA=true WITH_GPU=true RUN_FAILURE_DRILL=true \
  bash tests/e2e/security-monitoring/test_security_monitoring.sh
```

## Stop

```bash
podman compose --file compose.yaml --file compose.gpu.yaml down
```

The learner command intentionally preserves named volumes. Publisher E2E adds `--volumes` because each validation run must start from isolated data.
