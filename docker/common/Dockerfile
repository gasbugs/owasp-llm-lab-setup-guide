FROM docker.io/nginxinc/nginx-unprivileged:1.27-alpine

ARG VCS_REF=unknown

LABEL org.opencontainers.image.source="https://github.com/gasbugs/owasp-llm-lab-setup-guide" \
      org.opencontainers.image.revision="$VCS_REF" \
      org.opencontainers.image.title="OWASP LLM Lab Common UI" \
      org.opencontainers.image.licenses="PolyForm-Noncommercial-1.0.0"

COPY common/default.conf /etc/nginx/conf.d/default.conf
COPY shared-ui/theme.css /usr/share/nginx/html/theme.css

USER 101:101
EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=3s --retries=6 \
  CMD ["wget", "-q", "-O", "/dev/null", "http://127.0.0.1:8080/healthz"]
