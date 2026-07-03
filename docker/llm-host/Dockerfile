# OWASP LLM Lab — llm-host
# Ollama를 그대로 쓰지만 헬스체크와 모델 사전 로드 스크립트만 추가

FROM ollama/ollama:latest

LABEL org.opencontainers.image.title="owasp-llm-lab/llm-host"

# 호스트에서 마운트한 weights를 사용하므로 이미지에 모델 포함 안 함
ENV OLLAMA_HOST=0.0.0.0:11434 \
    OLLAMA_KEEP_ALIVE=24h \
    OLLAMA_MAX_LOADED_MODELS=2

HEALTHCHECK --interval=15s --timeout=5s --start-period=120s --retries=10 \
    CMD curl -fs http://localhost:11434/api/tags || exit 1

# Ollama 기본 entrypoint (`serve`) 그대로 사용
