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
NVIDIA L4 --read-only nvidia-smi metrics--> Prometheus
Prometheus + Loki + Tempo + Alertmanager ------------> Grafana
```

Raw prompts are not stored. Structured events contain a SHA-256 identity, a redacted excerpt, policy decision, rule, stage, request ID, and trace ID.

## Start on the validated GPU host

```bash
export OLLAMA_MODEL=llama3.1:8b-instruct-q4_K_M
export PODMAN_COMPOSE_PROVIDER=podman-compose
podman compose --file compose.yaml --file compose.gpu.yaml up --detach --build
```

Ubuntu 24.04에서 Docker Compose plugin도 함께 설치되어 있으면 `podman compose`가 이를 먼저 선택할 수 있다. `PODMAN_COMPOSE_PROVIDER`는 Podman과 직접 통신하는 `podman-compose`를 선택해 Docker daemon 의존성을 없앤다.

GPU exporter는 NVIDIA CDI 장치만 전달받아 고정된 읽기 전용 `nvidia-smi` query를 Prometheus 형식으로 변환한다. 전체 Compose 프로젝트는 rootless로 실행하며 `sudo`, `privileged`, 추가 Linux capability를 사용하지 않는다.

All published ports bind to `127.0.0.1`. The stack assumes Ollama is available on host port `11434` and reaches it through `host.containers.internal`.

## Publisher regression

The regression suite uses a deterministic Ollama contract double by default. Set `USE_REAL_OLLAMA=true WITH_GPU=true` on the validated g6 host to exercise the actual Ollama model and NVIDIA GPU metrics.

```bash
bash tests/e2e/security-monitoring/test_security_monitoring.sh
USE_REAL_OLLAMA=true WITH_GPU=true \
  bash tests/e2e/security-monitoring/test_security_monitoring.sh
```

## Stop

```bash
podman compose --file compose.yaml --file compose.gpu.yaml down
```

Named volumes are intentionally retained by the learner command. Publisher E2E uses `down --volumes` because each validation run is isolated.
