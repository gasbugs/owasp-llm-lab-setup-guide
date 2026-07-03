# docker/dvla/Dockerfile
# WithSecureLabs/damn-vulnerable-llm-agent (Apache 2.0)
# Day 3 LLM06 cross-platform 학습용. ReAct Agent 취약 — 본 강의 lab-ollama 공유.
#
# 빌드:
#   docker build -t docker.io/gasbugs/owasp-llm-dvla:latest .
#
# 실행 (본 강의 인프라):
#   docker run -d --name lab-dvla --network host \
#     -e OLLAMA_HOST=http://localhost:11434 \
#     -e model_name=ollama-local-llama3 \
#     docker.io/gasbugs/owasp-llm-dvla:latest
#
# 로컬 검증 (Mac native Ollama):
#   docker run -d --name lab-dvla -p 8501:8501 \
#     -e OLLAMA_HOST=http://host.docker.internal:11434 \
#     -e model_name=ollama-local-llama3 \
#     docker.io/gasbugs/owasp-llm-dvla:latest

# ---------- stage 1: clone ----------
FROM alpine/git:latest AS clone

ARG REPO_REF=main
WORKDIR /src

RUN git clone --depth=1 --branch=${REPO_REF} \
    https://github.com/WithSecureLabs/damn-vulnerable-llm-agent.git .

# ---------- stage 2: runtime (DVLA 원본 Dockerfile 그대로 + ollama env) ----------
FROM python:3.11-slim
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        curl \
        git \
    && rm -rf /var/lib/apt/lists/*

COPY --from=clone /src/ /app/
RUN pip install --no-cache-dir python-dotenv \
    && pip install --no-cache-dir -r requirements.txt

# Streamlit config + env defaults (Ollama backend)
COPY --from=clone /src/config.toml /root/.streamlit/config.toml
RUN cp /app/.env.ollama.template /app/.env
RUN sed -i 's#ollama/llama3#ollama/llama3.1:8b-instruct-q4_K_M#' /app/llm-config.yaml

# 학생 강의 인프라용 기본값 — 실행 시 -e로 override 가능
ENV OLLAMA_HOST=http://localhost:11434 \
    model_name=ollama-local-llama3

EXPOSE 8501

HEALTHCHECK --interval=20s --timeout=5s --retries=3 \
    CMD curl --fail http://localhost:8501/_stcore/health || exit 1

ENTRYPOINT ["streamlit", "run", "main.py", \
            "--server.port=8501", "--server.address=0.0.0.0", \
            "--server.headless=true"]
