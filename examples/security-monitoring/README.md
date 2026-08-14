# LLM Security Observability Stack

`compose.yaml` is the canonical deployment for Module 08. It connects the existing deterministic policy engine to an actual `/api/chat` request path and exports security telemetry to separate metrics, logs, traces, alerting, dashboard, and GPU backends.

## Runtime path

```text
client -> gateway -> input policy -> tenant retrieval -> tool authorization
       -> Ollama -> output policy
```

The gateway derives the authenticated tenant and dangerous-tool permission from the bearer token map in `app.py`. Request bodies cannot select these authorization attributes. Blocked input, retrieval, or tool requests return `upstream_called=false` and do not call Ollama.

## Telemetry path

```text
gateway --OTLP logs/traces--> OpenTelemetry Collector --> Loki / Tempo
gateway --/metrics---------> Prometheus -------------> Alertmanager
NVIDIA L4 --DCGM metrics---> Prometheus
Prometheus + Loki + Tempo + Alertmanager ------------> Grafana
```

Raw prompts are not stored. Structured events contain a SHA-256 identity, a redacted excerpt, policy decision, rule, stage, request ID, and trace ID.

## Start on the validated GPU host

```bash
export OLLAMA_MODEL=llama3.1:8b-instruct-q4_K_M
podman compose --file compose.yaml --profile gpu up --detach --build
```

All published ports bind to `127.0.0.1`. The stack assumes Ollama is available on host port `11434` and reaches it through `host.containers.internal`.

## Publisher regression

The regression suite uses a deterministic Ollama contract double by default. Set `USE_REAL_OLLAMA=true WITH_GPU=true` on the validated g6 host to exercise the actual Ollama model and DCGM metrics.

```bash
bash tests/e2e/security-monitoring/test_security_monitoring.sh
USE_REAL_OLLAMA=true WITH_GPU=true \
  bash tests/e2e/security-monitoring/test_security_monitoring.sh
```

## Stop

```bash
podman compose --file compose.yaml --profile gpu down
```

Named volumes are intentionally retained by the learner command. Publisher E2E uses `down --volumes` because each validation run is isolated.
