FROM docker.io/library/python:3.12-slim

ARG VCS_REF=unknown

LABEL org.opencontainers.image.source="https://github.com/gasbugs/owasp-llm-lab-setup-guide" \
      org.opencontainers.image.revision="$VCS_REF" \
      org.opencontainers.image.title="OWASP LLM Lab Portal" \
      org.opencontainers.image.licenses="PolyForm-Noncommercial-1.0.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --system --gid 10001 portal \
    && useradd --system --uid 10001 --gid portal --home-dir /app portal

WORKDIR /app
COPY --chown=portal:portal index.html server.py ./

USER 10001:10001
EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=6 \
  CMD ["python", "-c", "from urllib.request import urlopen; urlopen('http://127.0.0.1:8080/', timeout=2).read(1)"]

CMD ["python", "/app/server.py"]
