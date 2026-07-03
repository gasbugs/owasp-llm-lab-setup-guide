# OWASP LLM Lab — base-gpu
# CUDA 베이스 + Python 3.12 + uv. 모든 강의 앱이 이 이미지 위에 빌드됨.

FROM docker.io/nvidia/cuda:12.8.2-runtime-ubuntu24.04

LABEL org.opencontainers.image.title="owasp-llm-lab/base-gpu"
LABEL org.opencontainers.image.description="CUDA 12.8 + Python 3.12 + uv (training base)"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_INSTALL_DIR=/opt/uv-python \
    PATH=/root/.local/bin:/opt/uv-python/bin:$PATH

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        tini \
        python3.12 \
        python3.12-venv \
        python3-pip \
    && ln -sf /usr/bin/python3.12 /usr/local/bin/python3 \
    && ln -sf /usr/bin/python3.12 /usr/local/bin/python \
    && rm -rf /var/lib/apt/lists/*

# uv — 빠르고 재현 가능한 Python 패키지 매니저
RUN curl -LsSf https://astral.sh/uv/install.sh | sh

WORKDIR /app

ENTRYPOINT ["/usr/bin/tini", "--"]
