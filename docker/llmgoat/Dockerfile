# SECFORCE/LLMGoat v0.1.0 local training image
# Upstream source: https://github.com/SECFORCE/LLMGoat/tree/v0.1.0
# Upstream license: GPL-3.0

# 실행 코드가 들어 있는 upstream GPU image를 tag와 manifest digest로 함께 고정한다.
FROM ghcr.io/secforce/llmgoat-gpu:v0.1.0@sha256:b17ac2038813de509a5cabe4f284b1119c7d0c025b9f63166854688f52698611

ARG VCS_REF=unknown
ARG APP_VERSION=dev
LABEL org.opencontainers.image.title="OWASP LLMGoat local training image" \
      org.opencontainers.image.description="SECFORCE LLMGoat v0.1.0 with the course URI-prefix wrapper" \
      org.opencontainers.image.source="https://github.com/gasbugs/owasp-llm-lab-setup-guide" \
      org.opencontainers.image.revision="$VCS_REF" \
      org.opencontainers.image.version="$APP_VERSION" \
      org.opencontainers.image.licenses="GPL-3.0" \
      org.opencontainers.image.url="https://github.com/SECFORCE/LLMGoat/tree/v0.1.0"
ENV APP_VERSION=$APP_VERSION

# 실행 image와 같은 v0.1.0 전체 소스를 checksum으로 확인해 image 안에 보관한다.
# checksum이 달라지면 Build가 중단되므로 바뀐 소스를 조용히 실행하지 않는다.
ADD --checksum=sha256:4e3251ebd6ae59a4003791e18606a23ae94708bb48236caf51aa51cffbe34e29 \
    https://codeload.github.com/SECFORCE/LLMGoat/tar.gz/refs/tags/v0.1.0 \
    /tmp/llmgoat-v0.1.0.tar.gz

RUN mkdir -p /usr/src/llmgoat-v0.1.0 /usr/share/licenses/llmgoat \
    && tar -xzf /tmp/llmgoat-v0.1.0.tar.gz \
        --strip-components=1 -C /usr/src/llmgoat-v0.1.0 \
    && cp /usr/src/llmgoat-v0.1.0/LICENSE /app/LICENSE \
    && cp /usr/src/llmgoat-v0.1.0/LICENSE \
        /usr/share/licenses/llmgoat/GPL-3.0.txt \
    && rm /tmp/llmgoat-v0.1.0.tar.gz

COPY NOTICE.md /usr/share/doc/llmgoat/NOTICE.md

# 원본 challenge 코드는 바꾸지 않고, 통합 포털의 /llmgoat 경로만 연결한다.
COPY proxy_entrypoint.py /opt/owasp-llm/proxy_entrypoint.py

EXPOSE 5000

ENTRYPOINT ["python3", "/opt/owasp-llm/proxy_entrypoint.py"]
