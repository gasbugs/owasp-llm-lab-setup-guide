# docker/llmgoat/Dockerfile
# SECFORCE/LLMGoat wrapper — Day 1·3·5 cross-platform 학습용 (gemma-2-9b GGUF, llama-cpp)
#
# 원본: https://github.com/SECFORCE/LLMGoat (Apache 2.0)
# 빌드:
#   docker build -t docker.io/gasbugs/owasp-llm-llmgoat:sha-<commit> .
# 실행 (본 강의 인프라):
#   docker run -d --name lab-llmgoat --device nvidia.com/gpu=all -p 5000:5000 \
#     -e LLMGOAT_SERVER_HOST=0.0.0.0 -e LLMGOAT_DEFAULT_MODEL=gemma-2.gguf \
#     -e LLMGOAT_N_GPU_LAYERS=20 \
#     -v ~/.LLMGoat/models:/root/.LLMGoat/models:Z \
#     -v ~/.LLMGoat/cache:/root/.LLMGoat/cache:Z \
#     docker.io/gasbugs/owasp-llm-llmgoat:sha-<commit>
#
# 첫 부팅 시 gemma-2-9b-it-Q4_K_M GGUF (~5GB)를 Hugging Face에서 자동 다운로드.

FROM ghcr.io/secforce/llmgoat-gpu:latest

# LLMGoat 원본은 비-Docker 환경에서 부팅 시 interactive disclaimer prompt를 띄움.
# /.dockerenv 파일이 있으면 컨테이너로 인식하고 disclaimer를 건너뜀.
# Podman은 /.dockerenv를 자동 생성하지 않으므로 이미지 레벨에서 마커 박음.
RUN touch /.dockerenv

EXPOSE 5000
