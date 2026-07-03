# OWASP LLM Lab — vuln-rag (Podman/OCI 호환)

ARG BASE_IMAGE=docker.io/owasplllab/owasp-llm-base-gpu:latest
FROM ${BASE_IMAGE}

LABEL org.opencontainers.image.title="owasp-llm-vuln-rag"
LABEL owasp.llm.lab.warning="INTENTIONALLY VULNERABLE — DO NOT DEPLOY OUTSIDE TRAINING"

WORKDIR /app

COPY pyproject.toml uv.lock* ./
RUN uv sync --frozen --no-dev || uv sync --no-dev

COPY app ./app

ENV PORT=8000 \
    OLLAMA_URL=http://ollama:11434 \
    OLLAMA_MODEL=llama3.1:8b-instruct-q4_K_M \
    CHROMA_URL=http://chroma:8001 \
    DEFAULT_SCENARIO=day1

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s CMD curl -fs http://localhost:8000/healthz || exit 1

CMD ["uv", "run", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
