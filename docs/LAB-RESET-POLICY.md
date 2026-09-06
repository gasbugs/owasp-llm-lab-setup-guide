# Lab state and container recreation policy

This document records where the installed Day 1–5 runtime keeps mutable state
and the smallest supported learner action. The classification comes from the
application source and the canonical Docker Compose definition installed by
`install-lab.sh`.

## Learner Compose commands

Read-only labs need no reset. After a lab changes Python memory or source in a
container writable layer, learners first run `cd ~/.config/owasp-llm-lab` and
then operate the exact Compose service shown below. `--no-deps` leaves unrelated
services alone. `--force-recreate` discards only the selected container layer
and creates it again from the configured image.

| Lab | Exact Compose command | Raw verification |
|---|---|---|
| LLM01 secure-coding source or LLM01-B | `docker compose up -d --no-deps --force-recreate prompt-rag` | `curl -sS http://localhost:8000/healthz` |
| LLM02 secure-coding source or LLM08 RAG corpus | `docker compose up -d --no-deps --force-recreate data-rag` | `curl -sS http://localhost:8010/healthz` |
| LLM05 | `docker compose up -d --no-deps --force-recreate output-rag` | `curl -sS http://localhost:8011/healthz` |
| LLM06 delete | `docker compose up -d --no-deps --force-recreate vuln-agent` | `curl -sS http://localhost:8001/healthz` |
| LLM08 or LLM09 secure-coding source | `docker compose up -d --no-deps --force-recreate knowledge-rag` | `curl -sS http://localhost:8012/healthz` |
| Mutable LLMGoat challenge | `docker compose restart llmgoat` | `curl -sS http://localhost:5000/api/model_status` |
| LLM10 source or overload | Use the ordered sequence below. | `curl -sS http://localhost:8013/healthz` |

These commands never write to or delete `/home/ubuntu/work`,
`/home/ubuntu/ollama-models`, `/home/ubuntu/.LLMGoat/models`, or
`/home/ubuntu/.LLMGoat/cache`.

## Runtime inventory

| Compose service | Port | Mutable runtime state | Persistent mount | Minimum action |
|---|---:|---|---|---|
| `ollama` | 11434 | loaded model and request queue | `/home/ubuntu/ollama-models:/root/.ollama` | Do not restart for ordinary lessons. Restart it only in the LLM10 overload sequence. |
| `prompt-rag` | 8000 | Python `day1._corpus` and editable layer | none | Force-recreate after an LLM01 source switch or corpus injection. |
| `data-rag` | 8010 | Python `day2._corpus` and editable layer | none | Force-recreate after an LLM02 source switch or LLM08 corpus mutation. |
| `output-rag` | 8011 | Python `day3._corpus` and editable layer | none | Force-recreate after a renderer source switch or stored payload. |
| `knowledge-rag` | 8012 | Python `day4._tenants` and editable layer | none | Force-recreate after an LLM08 or LLM09 source switch. |
| `resource-rag` | 8013 | in-flight uvicorn tasks, Python `day5._corpus`, and editable layer | none | Use the LLM10 sequence below. |
| `vuln-agent` | 8001 | Python `ANIMALS`, `DELETED_LOG`, and editable layer | none | Force-recreate to restore vulnerable source, `g-003`, and an empty deletion log. |
| `llmgoat` | 5000 | A04 reviews, A08 vector store, A09 upload and model lock in process memory | models and cache only | Restart the Compose service. Browser completion badges are a signed client cookie and are not challenge fixtures. |
| `dvla` | 8501 | Streamlit session and container-layer `transactions.db` | `/home/ubuntu/work/dvla/llm-config.yaml:/app/llm-config.yaml` | Restart only to clear a session; it does not restore the host YAML. |
| `fake-registry` | 8002 | startup rewrites `/app/data/A.gguf` and `B.gguf` | `/home/ubuntu/work/fake-registry:/app` | Standard LLM03 is read-only. Restart does not restore modified host files. |
| `portal` | 8080 | none | `/home/ubuntu/work/portal:/app` | No reset. Restart does not restore modified host content. |

All five vulnerable RAG services use the same image but run as separate
processes. Their Python globals are isolated and return to image defaults when
the corresponding container is force-recreated.

The Agent image also exposes read-only `GET /api/admin/state` for publisher E2E
verification. Learners do not need that endpoint: they force-recreate
`vuln-agent` and then read the raw `/healthz` output.

## Why LLM10 has an ordered sequence

A client timeout does not prove server-side work stopped. A timed-out Day 5
request can leave an uvicorn task waiting on the shared Ollama queue. Learners
therefore perform the recovery explicitly instead of hiding it in a project
wrapper:

```bash
cd ~/.config/owasp-llm-lab
docker compose up -d --no-deps --force-recreate resource-rag
docker compose restart ollama
curl -fsS http://localhost:11434/api/tags
docker compose up -d --no-deps --force-recreate resource-rag
docker compose ps resource-rag ollama
curl -sS http://localhost:8013/healthz
```

The first recreation cancels app-side waiters, restarting Ollama clears queued
generation, and the second recreation starts Day 5 against the ready model
server. If the readiness request runs before Ollama is ready, repeat only the
read-only `curl` check.

## Container state is not lifecycle cleanup

Keep these operations separate from application state recreation:

- stop the learner-built process by its verified PID;
- stop or remove learner-owned containers only when that lesson is finished;
- preserve all source and evidence below `~/work`;
- stop the EC2 instance separately to end compute charges.

Open WebUI data, Ollama models, LLMGoat models/cache, the DVLA YAML,
fake-registry source, portal source, and Capstone code are host or volume state.
Recreating the listed service does not delete or overwrite them.
