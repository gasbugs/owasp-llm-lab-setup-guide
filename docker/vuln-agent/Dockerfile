# OWASP LLM Lab — vuln-agent (Podman/OCI 호환)

ARG BASE_IMAGE=docker.io/gasbugs/owasp-llm-base-gpu:latest
FROM ${BASE_IMAGE}

LABEL org.opencontainers.image.title="owasp-llm-vuln-agent"
LABEL owasp.llm.lab.warning="INTENTIONALLY VULNERABLE — DO NOT DEPLOY OUTSIDE TRAINING"

WORKDIR /app

COPY pyproject.toml uv.lock* ./
RUN uv sync --frozen --no-dev || uv sync --no-dev

COPY app ./app

ENV PORT=8001 \
    OLLAMA_URL=http://ollama:11434 \
    OLLAMA_MODEL=llama3.1:8b-instruct-q4_K_M

EXPOSE 8001

HEALTHCHECK --interval=15s --timeout=5s CMD curl -fs "http://localhost:${PORT}/healthz" || exit 1

CMD ["sh", "-c", "exec uv run uvicorn app.main:app --host 0.0.0.0 --port \"$PORT\""]
