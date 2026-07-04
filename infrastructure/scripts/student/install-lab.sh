#!/bin/bash
# Manual lab installer for OWASP Top 10 for LLM.
#
# 실행 위치: Terraform이 만든 EC2 인스턴스 안.
# 권장 실행:
#   curl -fsSL https://raw.githubusercontent.com/gasbugs/owasp-llm-lab-setup-guide/main/infrastructure/scripts/student/install-lab.sh | sudo bash
#
# 같은 스크립트는 선택적 user-data 자동 설치에서도 재사용된다.

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "이 스크립트는 root 권한이 필요합니다. 다음처럼 실행하세요:"
  echo "  curl -fsSL https://raw.githubusercontent.com/gasbugs/owasp-llm-lab-setup-guide/main/infrastructure/scripts/student/install-lab.sh | sudo bash"
  exit 1
fi

LOG_FILE="${LAB_INSTALL_LOG:-/var/log/owasp-llm-lab-install.log}"
exec > >(tee -a "$LOG_FILE") 2>&1

RAW_URL="${LAB_SETUP_REPO_RAW_URL:-https://raw.githubusercontent.com/gasbugs/owasp-llm-lab-setup-guide/main}"
SCRIPT_VERSION="0.1.4"
IMAGE_NAMESPACE="${IMAGE_NAMESPACE:-gasbugs}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
REFRESH_IMAGES="${REFRESH_IMAGES:-true}"
OLLAMA_MODEL="${OLLAMA_MODEL:-llama3.1:8b-instruct-q4_K_M}"
OLLAMA_COMPAT_MODEL="${OLLAMA_COMPAT_MODEL:-llama3}"
LLAMA_GUARD_MODEL="${LLAMA_GUARD_MODEL:-llama-guard3:8b}"
LLMGOAT_N_GPU_LAYERS="${LLMGOAT_N_GPU_LAYERS:-20}"
SKIP_EMBEDDING_VENV="${SKIP_EMBEDDING_VENV:-true}"
INSTALL_START_EPOCH=$(date +%s)

step() {
  printf '\n[install-lab] STEP %s - %s\n' "$1" "$2"
}

echo "=== owasp-llm-lab manual install start: $(date -Iseconds) ==="
echo "SCRIPT_VERSION=$SCRIPT_VERSION"
echo "RAW_URL=$RAW_URL"
echo "IMAGE_NAMESPACE=$IMAGE_NAMESPACE IMAGE_TAG=$IMAGE_TAG"
echo "REFRESH_IMAGES=$REFRESH_IMAGES"

# 1) IMDSv2로 instance metadata와 tag 조회
step "1/10" "EC2 메타데이터와 태그를 조회해 설치 대상 정보를 확인합니다"
TOKEN=$(curl -fsS -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
HDR="X-aws-ec2-metadata-token: $TOKEN"
INSTANCE_ID=$(curl -fsSH "$HDR" http://169.254.169.254/latest/meta-data/instance-id)
IDENTITY_DOCUMENT=$(curl -fsSH "$HDR" http://169.254.169.254/latest/dynamic/instance-identity/document)
REGION=$(printf '%s' "$IDENTITY_DOCUMENT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["region"])')
PUBLIC_IPV4=$(curl -fsSH "$HDR" http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "")
STUDENT=$(curl -fsSH "$HDR" http://169.254.169.254/latest/meta-data/tags/instance/Student 2>/dev/null || echo "student")
COURSE_ID=$(curl -fsSH "$HDR" http://169.254.169.254/latest/meta-data/tags/instance/Course 2>/dev/null || echo "owasp-llm")

echo "INSTANCE_ID=$INSTANCE_ID REGION=$REGION PUBLIC_IPV4=${PUBLIC_IPV4:-none} STUDENT=$STUDENT COURSE_ID=$COURSE_ID"

# 2) /etc/lab/env
step "2/10" "/etc/lab/env에 실습 환경 변수를 기록합니다"
install -d -m 0755 /etc/lab
cat > /etc/lab/env <<EOF
SCRIPT_VERSION=$SCRIPT_VERSION
STUDENT=$STUDENT
COURSE_ID=$COURSE_ID
AWS_DEFAULT_REGION=$REGION
EC2_DOMAIN=$PUBLIC_IPV4
IMAGE_NAMESPACE=$IMAGE_NAMESPACE
IMAGE_TAG=$IMAGE_TAG
OLLAMA_MODEL=$OLLAMA_MODEL
OLLAMA_COMPAT_MODEL=$OLLAMA_COMPAT_MODEL
LLMGOAT_N_GPU_LAYERS=$LLMGOAT_N_GPU_LAYERS
SKIP_EMBEDDING_VENV=$SKIP_EMBEDDING_VENV
EOF
chmod 0644 /etc/lab/env

# 3) 작업 디렉터리 생성
step "3/10" "ubuntu 사용자 작업 디렉터리를 준비합니다"
install -d -m 0755 -o ubuntu -g ubuntu /home/ubuntu/work

# 4) Podman 설치
step "4/10" "Podman rootless 실행에 필요한 패키지를 확인하고 부족하면 설치합니다"
export DEBIAN_FRONTEND=noninteractive
if command -v podman >/dev/null 2>&1 && \
  command -v podman-compose >/dev/null 2>&1 && \
  command -v crun >/dev/null 2>&1 && \
  command -v fuse-overlayfs >/dev/null 2>&1 && \
  command -v slirp4netns >/dev/null 2>&1 && \
  command -v newuidmap >/dev/null 2>&1 && \
  command -v jq >/dev/null 2>&1 && \
  dpkg -s python3-venv >/dev/null 2>&1; then
  echo "[install-lab] Podman/rootless prerequisites already installed"
else
  apt-get update -y
  apt-get install -y --no-install-recommends \
    curl ca-certificates git jq \
    python3-venv \
    podman podman-compose podman-docker crun fuse-overlayfs slirp4netns uidmap
fi

# rootless 설정
step "5/10" "ubuntu 사용자 rootless Podman과 systemd user session을 설정합니다"
touch /etc/containers/nodocker
grep -q '^ubuntu:' /etc/subuid || echo "ubuntu:100000:65536" >> /etc/subuid
grep -q '^ubuntu:' /etc/subgid || echo "ubuntu:100000:65536" >> /etc/subgid
loginctl enable-linger ubuntu
UBUNTU_UID=$(id -u ubuntu)
systemctl start "user@$UBUNTU_UID.service"
for _ in $(seq 1 20); do
  [ -S "/run/user/$UBUNTU_UID/bus" ] && break
  sleep 1
done
[ -S "/run/user/$UBUNTU_UID/bus" ] || {
  echo "ERROR: ubuntu systemd user bus is not ready at /run/user/$UBUNTU_UID/bus" >&2
  exit 1
}
UBUNTU_USER_ENV=(
  XDG_RUNTIME_DIR="/run/user/$UBUNTU_UID"
  DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$UBUNTU_UID/bus"
)
RUN_AS_UBUNTU=(runuser -u ubuntu -- env "${UBUNTU_USER_ENV[@]}")

# CDI 모드 nvidia
step "6/10" "NVIDIA GPU를 Podman 컨테이너에서 사용할 CDI 설정을 확인합니다"
if [ -s /etc/cdi/nvidia.yaml ]; then
  echo "[install-lab] NVIDIA CDI config already exists: /etc/cdi/nvidia.yaml"
else
  nvidia-ctk cdi generate --output=/etc/cdi/nvidia.yaml || \
    echo "(nvidia-ctk 미설치 — apt install nvidia-container-toolkit 필요)"
fi

# 5) Ollama 모델 디렉터리
step "7/10" "Ollama 모델 디렉터리를 준비합니다"
install -d -m 0755 -o ubuntu -g ubuntu /home/ubuntu/ollama-models

# 6) 컨테이너 이미지 pull
step "8/10" "실습 컨테이너 이미지를 확인하고 최신 이미지를 pull합니다"
"${RUN_AS_UBUNTU[@]}" bash <<PULLSH
set -euo pipefail
for img in owasp-llm-base-gpu owasp-llm-vuln-rag owasp-llm-vuln-agent owasp-llm-llmgoat owasp-llm-dvla; do
  if [ "${REFRESH_IMAGES}" != "true" ] && podman image exists "docker.io/${IMAGE_NAMESPACE}/\${img}:${IMAGE_TAG}"; then
    echo "[install-lab] image already exists: docker.io/${IMAGE_NAMESPACE}/\${img}:${IMAGE_TAG}"
    continue
  fi
  pulled=false
  for i in \$(seq 1 3); do
    if podman pull "docker.io/${IMAGE_NAMESPACE}/\${img}:${IMAGE_TAG}"; then
      pulled=true
      break
    fi
    echo "  retry \$i/3..."; sleep 5
  done
  if [ "\$pulled" != true ]; then
    echo "ERROR: failed to pull docker.io/${IMAGE_NAMESPACE}/\${img}:${IMAGE_TAG}" >&2
    exit 1
  fi
done
PULLSH

# 7) 시나리오 결정
echo "[install-lab] enabled scenarios: day1 day2 day3 day4 day5"

# 8) Quadlet으로 컨테이너 systemd user unit 작성 및 실행
# podman generate systemd는 deprecated라 새 설치에서는 Quadlet을 직접 사용한다.
step "9/10" "Quadlet unit, 모든 실습 컨테이너, 모델, 선택 도구를 준비합니다"
mkdir -p /home/ubuntu/.LLMGoat/models /home/ubuntu/.LLMGoat/cache
chown -R ubuntu:ubuntu /home/ubuntu/.LLMGoat
if [ -f /home/ubuntu/.LLMGoat/models/gemma-2.gguf ]; then
  MODEL_BYTES=$(stat -c '%s' /home/ubuntu/.LLMGoat/models/gemma-2.gguf)
  if [ "$MODEL_BYTES" -lt 1000000000 ]; then
    echo "[install-lab] removing incomplete LLMGoat model: /home/ubuntu/.LLMGoat/models/gemma-2.gguf (${MODEL_BYTES} bytes)"
    rm -f /home/ubuntu/.LLMGoat/models/gemma-2.gguf
  fi
fi

# Day 2 LLM03 Supply Chain — fake model-registry (port 8002)
echo "[install-lab] preparing fake model registry files"
mkdir -p /home/ubuntu/work/fake-registry
if [ -s /home/ubuntu/work/fake-registry/server.py ]; then
  echo "[install-lab] fake-registry server.py already exists"
else
  curl -fsSL "$RAW_URL/infrastructure/fake-registry/server.py" -o /home/ubuntu/work/fake-registry/server.py
fi
chown -R ubuntu:ubuntu /home/ubuntu/work/fake-registry

echo "[install-lab] preparing lab portal files"
mkdir -p /home/ubuntu/work/portal
curl -fsSL "$RAW_URL/infrastructure/portal/index.html" -o /home/ubuntu/work/portal/index.html
chown -R ubuntu:ubuntu /home/ubuntu/work/portal

# Day 3 LLM06 — DVLA must use the same Ollama model pulled by this lab.
echo "[install-lab] preparing DVLA LiteLLM model config"
mkdir -p /home/ubuntu/work/dvla
cat > /home/ubuntu/work/dvla/llm-config.yaml <<EOF
default_model: ollama-local-llama3
models:
  - model_name: ollama-local-llama3
    model: "ollama/$OLLAMA_MODEL"
EOF
chown -R ubuntu:ubuntu /home/ubuntu/work/dvla

QUADLET_DIR="/home/ubuntu/.config/containers/systemd"
install -d -m 0755 -o ubuntu -g ubuntu "$QUADLET_DIR"

echo "[install-lab] writing Quadlet unit files under $QUADLET_DIR"

echo "[install-lab] removing legacy single-day unit files and containers if they exist"
rm -f "$QUADLET_DIR/lab-vuln-rag.container"
rm -f "$QUADLET_DIR/lab-vuln-agent.container"
rm -f "$QUADLET_DIR/lab-dvla.container"
rm -f "$QUADLET_DIR/lab-fake-registry.container"
rm -f "$QUADLET_DIR/lab-portal.container"
"${RUN_AS_UBUNTU[@]}" bash <<'LEGACYSH'
set -euo pipefail
for unit in lab-vuln-rag lab-vuln-agent lab-dvla lab-fake-registry lab-portal; do
  systemctl --user stop "$unit.service" >/dev/null 2>&1 || true
  systemctl --user reset-failed "$unit.service" >/dev/null 2>&1 || true
  podman rm -f "$unit" >/dev/null 2>&1 || true
done
LEGACYSH

cat > "$QUADLET_DIR/lab-ollama.container" <<'EOF'
[Unit]
Description=OWASP LLM Lab - Ollama

[Container]
ContainerName=lab-ollama
Image=docker.io/ollama/ollama:latest
AddDevice=nvidia.com/gpu=all
PublishPort=11434:11434
Volume=/home/ubuntu/ollama-models:/root/.ollama:Z
Environment=OLLAMA_HOST=0.0.0.0:11434
Environment=OLLAMA_KEEP_ALIVE=24h

[Service]
Restart=always

[Install]
WantedBy=default.target
EOF

declare -A RAG_PORTS=(
  [day1]=8000
  [day2]=8010
  [day3]=8011
  [day4]=8012
  [day5]=8013
)

for scenario in day1 day2 day3 day4 day5; do
  rag_port="${RAG_PORTS[$scenario]}"
  cat > "$QUADLET_DIR/lab-${scenario}-vuln-rag.container" <<EOF
[Unit]
Description=OWASP LLM Lab - ${scenario} Vulnerable RAG
After=lab-ollama.container
Requires=lab-ollama.container

[Container]
ContainerName=lab-${scenario}-vuln-rag
Image=docker.io/${IMAGE_NAMESPACE}/owasp-llm-vuln-rag:${IMAGE_TAG}
Network=host
Environment=DEFAULT_SCENARIO=${scenario}
Environment=SCENARIO=${scenario}
Environment=OLLAMA_URL=http://localhost:11434
Environment=OLLAMA_MODEL=$OLLAMA_MODEL
Exec=uv run uvicorn app.main:app --host 0.0.0.0 --port ${rag_port}

[Service]
Restart=always

[Install]
WantedBy=default.target
EOF
done

cat > "$QUADLET_DIR/lab-day3-vuln-agent.container" <<EOF
[Unit]
Description=OWASP LLM Lab - day3 Vulnerable Agent
After=lab-ollama.container
Requires=lab-ollama.container

[Container]
ContainerName=lab-day3-vuln-agent
Image=docker.io/${IMAGE_NAMESPACE}/owasp-llm-vuln-agent:${IMAGE_TAG}
Network=host
Environment=OLLAMA_URL=http://localhost:11434
Environment=OLLAMA_MODEL=$OLLAMA_MODEL

[Service]
Restart=always

[Install]
WantedBy=default.target
EOF

cat > "$QUADLET_DIR/lab-llmgoat.container" <<EOF
[Unit]
Description=OWASP LLM Lab - LLMGoat

[Container]
ContainerName=lab-llmgoat
Image=docker.io/${IMAGE_NAMESPACE}/owasp-llm-llmgoat:${IMAGE_TAG}
AddDevice=nvidia.com/gpu=all
PublishPort=5000:5000
Environment=LLMGOAT_SERVER_HOST=0.0.0.0
Environment=LLMGOAT_SERVER_PORT=5000
Environment=LLMGOAT_DEFAULT_MODEL=gemma-2.gguf
Environment=LLMGOAT_N_GPU_LAYERS=$LLMGOAT_N_GPU_LAYERS
Environment=LLMGOAT_N_THREADS=4
Environment=LLMGOAT_VERBOSE=1
Volume=/home/ubuntu/.LLMGoat/models:/root/.LLMGoat/models:Z
Volume=/home/ubuntu/.LLMGoat/cache:/root/.LLMGoat/cache:Z

[Service]
Restart=always

[Install]
WantedBy=default.target
EOF

cat > "$QUADLET_DIR/lab-day3-dvla.container" <<EOF
[Unit]
Description=OWASP LLM Lab - day3 Damn Vulnerable LLM Agent
After=lab-ollama.container
Requires=lab-ollama.container

[Container]
ContainerName=lab-day3-dvla
Image=docker.io/${IMAGE_NAMESPACE}/owasp-llm-dvla:${IMAGE_TAG}
Network=host
Environment=OLLAMA_HOST=http://localhost:11434
Environment=OLLAMA_API_BASE=http://localhost:11434
Environment=model_name=ollama-local-llama3
Volume=/home/ubuntu/work/dvla/llm-config.yaml:/app/llm-config.yaml:Z

[Service]
Restart=always

[Install]
WantedBy=default.target
EOF

cat > "$QUADLET_DIR/lab-day2-fake-registry.container" <<'EOF'
[Unit]
Description=OWASP LLM Lab - day2 Fake Model Registry

[Container]
ContainerName=lab-day2-fake-registry
Image=docker.io/library/python:3.12-slim
Network=host
Volume=/home/ubuntu/work/fake-registry:/app:Z
Exec=python /app/server.py

[Service]
Restart=always

[Install]
WantedBy=default.target
EOF

cat > "$QUADLET_DIR/lab-portal.container" <<'EOF'
[Unit]
Description=OWASP LLM Lab - Portal

[Container]
ContainerName=lab-portal
Image=docker.io/library/python:3.12-slim
Network=host
Volume=/home/ubuntu/work/portal:/app:Z
Exec=python -m http.server 8080 --directory /app

[Service]
Restart=always

[Install]
WantedBy=default.target
EOF

chown -R ubuntu:ubuntu "$QUADLET_DIR"

"${RUN_AS_UBUNTU[@]}" bash <<'QUADLETSH'
set -euo pipefail
echo "[install-lab] reloading systemd user units and starting missing lab services"
units=(
  lab-ollama
  lab-day1-vuln-rag
  lab-day2-vuln-rag
  lab-day3-vuln-rag
  lab-day4-vuln-rag
  lab-day5-vuln-rag
  lab-day3-vuln-agent
  lab-llmgoat
  lab-day3-dvla
  lab-day2-fake-registry
  lab-portal
)
systemctl --user daemon-reload
for unit in "${units[@]}"; do
  systemctl --user reset-failed "$unit.service" >/dev/null 2>&1 || true
  if [ "$unit" = "lab-day3-dvla" ] && systemctl --user is-active --quiet "$unit.service"; then
    echo "[install-lab] restarting $unit.service to apply DVLA model config"
    systemctl --user restart "$unit.service"
  elif systemctl --user is-active --quiet "$unit.service"; then
    echo "[install-lab] $unit.service already running"
  else
    podman rm -f "$unit" >/dev/null 2>&1 || true
    systemctl --user start "$unit.service"
  fi
done
QUADLETSH

# 10) Ollama 모델 pull 및 warm-up
step "10/10" "Ollama 모델 pull, warm-up, 선택 도구를 준비합니다"
echo "[install-lab] checking Ollama readiness, model availability, and warm-up"
"${RUN_AS_UBUNTU[@]}" bash <<OLLAMASH
set -euo pipefail
echo "[install-lab] waiting for lab-ollama API on localhost:11434"
for i in \$(seq 1 60); do
  if curl -fs http://localhost:11434/api/tags >/dev/null 2>&1; then
    break
  fi
  sleep 5
done
if podman exec lab-ollama ollama list | awk 'NR > 1 { print \$1 }' | grep -qx "$OLLAMA_MODEL"; then
  echo "[install-lab] $OLLAMA_MODEL already pulled"
else
  podman exec lab-ollama ollama pull "$OLLAMA_MODEL"
fi
if [ -n "$OLLAMA_COMPAT_MODEL" ] && [ "$OLLAMA_COMPAT_MODEL" != "$OLLAMA_MODEL" ]; then
  if podman exec lab-ollama ollama list | awk 'NR > 1 { print \$1 }' | grep -qx "$OLLAMA_COMPAT_MODEL"; then
    echo "[install-lab] $OLLAMA_COMPAT_MODEL compatibility alias already available"
  else
    printf 'FROM %s\n' "$OLLAMA_MODEL" | podman exec -i lab-ollama sh -c 'cat > /tmp/Modelfile.compat'
    podman exec lab-ollama ollama create "$OLLAMA_COMPAT_MODEL" -f /tmp/Modelfile.compat
    podman exec lab-ollama rm -f /tmp/Modelfile.compat
    echo "[install-lab] created $OLLAMA_COMPAT_MODEL compatibility alias for DVLA"
  fi
fi
if podman exec lab-ollama ollama list | awk 'NR > 1 { print \$1 }' | grep -qx "$LLAMA_GUARD_MODEL"; then
  echo "[install-lab] $LLAMA_GUARD_MODEL already pulled"
else
  podman exec lab-ollama ollama pull "$LLAMA_GUARD_MODEL" 2>&1 | tail -3 || true
  echo "[install-lab] $LLAMA_GUARD_MODEL pulled (Day 5 Defense demo)"
fi

curl -s --max-time 120 http://localhost:11434/api/generate \
  -d "{\"model\":\"$OLLAMA_MODEL\",\"prompt\":\"ready\",\"stream\":false,\"options\":{\"num_predict\":5}}" >/dev/null 2>&1 || true
echo "[install-lab] ollama warm-up done"

echo "[install-lab] checking optional Day 4 embedding Python environment"
if [ "$SKIP_EMBEDDING_VENV" = "true" ]; then
  echo "[install-lab] embedding-venv skipped by SKIP_EMBEDDING_VENV=true"
else
  AVAILABLE_KB=\$(df --output=avail -k /home/ubuntu/work | tail -n 1 | tr -d ' ')
  MIN_EMBEDDING_KB=\$((6 * 1024 * 1024))
  if [ "\$AVAILABLE_KB" -lt "\$MIN_EMBEDDING_KB" ]; then
    echo "[install-lab] embedding-venv skipped: only \$((AVAILABLE_KB / 1024)) MB free under /home/ubuntu/work"
    echo "[install-lab] set SKIP_EMBEDDING_VENV=false and free at least 6 GB to install Day 4 embedding tools"
  else
    if [ -x /home/ubuntu/work/embedding-venv/bin/pip ] && \
      /home/ubuntu/work/embedding-venv/bin/pip show sentence-transformers scikit-learn numpy >/dev/null 2>&1; then
      echo "[install-lab] embedding-venv already ready for Day 4 LLM08-A"
    else
      rm -rf /home/ubuntu/work/embedding-venv /home/ubuntu/.cache/pip
      python3 -m venv /home/ubuntu/work/embedding-venv
      if timeout 600 /home/ubuntu/work/embedding-venv/bin/pip install --no-cache-dir -q sentence-transformers scikit-learn numpy; then
        chown -R ubuntu:ubuntu /home/ubuntu/work/embedding-venv 2>/dev/null || true
        echo "[install-lab] embedding-venv ready for Day 4 LLM08-A"
      else
        rm -rf /home/ubuntu/work/embedding-venv /home/ubuntu/.cache/pip
        echo "[install-lab] embedding-venv install failed or timed out; continuing without optional Day 4 embedding tools"
      fi
    fi
  fi
fi
OLLAMASH

INSTALL_END_EPOCH=$(date +%s)
INSTALL_DURATION=$((INSTALL_END_EPOCH - INSTALL_START_EPOCH))
INSTALL_DURATION_MIN=$((INSTALL_DURATION / 60))
INSTALL_DURATION_SEC=$((INSTALL_DURATION % 60))

cat <<EOF

============================================================
OWASP LLM Lab 설치가 완료되었습니다.
============================================================

완료 시각: $(date -Iseconds)
스크립트 버전: $SCRIPT_VERSION
총 설치 시간: ${INSTALL_DURATION_MIN}분 ${INSTALL_DURATION_SEC}초
설치 로그: $LOG_FILE

다음 명령으로 실행 중인 실습 컨테이너를 확인하세요.
  sudo -u ubuntu podman ps

주요 서비스:
  - Lab Portal            8080
    모든 실습 앱으로 이동하는 단일 진입점입니다.

  - Ollama API            11434
    로컬 LLM 모델 목록 확인과 generate API 호출에 사용합니다.

  - Day 1 Vulnerable RAG  8000
    LLM01/LLM02 계열 프롬프트 인젝션과 민감정보 노출 실습 앱입니다.

  - Day 2 Vulnerable RAG  8010
    LLM03 공급망/모델 무결성 시나리오와 연결되는 RAG 실습 앱입니다.

  - Day 3 Vulnerable RAG  8011
    Agent/도구 호출 취약점과 비교하기 위한 RAG 실습 앱입니다.

  - Day 4 Vulnerable RAG  8012
    LLM08 벡터/임베딩과 RAG 데이터 오염 실습 앱입니다.

  - Day 5 Vulnerable RAG  8013
    방어/가드레일 우회와 로깅/모니터링 실습 앱입니다.

  - Day 3 Vulnerable Agent 8001
    도구 호출형 LLM Agent의 excessive agency, tool misuse 실습 앱입니다.

  - Day 2 Fake Model Registry 8002
    모델 공급망/무결성 검증 실습용 가짜 모델 레지스트리 API입니다.

  - LLMGoat               5000
    OWASP Top 10 for LLM 항목별 웹 챌린지 실습 UI입니다.

  - Day 3 DVLA            8501
    Damn Vulnerable LLM Agent. ReAct Agent prompt injection 실습 UI입니다.

브라우저 접속 URL:
  export EC2_DOMAIN=${PUBLIC_IPV4:-"<EC2_PUBLIC_IP>"}

  Lab Portal:
    http://${PUBLIC_IPV4:-"<EC2_PUBLIC_IP>"}:8080

  Ollama 모델 목록:
    http://${PUBLIC_IPV4:-"<EC2_PUBLIC_IP>"}:11434/api/tags

  Day 1 Vulnerable RAG health check:
    http://${PUBLIC_IPV4:-"<EC2_PUBLIC_IP>"}:8000/healthz

  Day 2 Vulnerable RAG health check:
    http://${PUBLIC_IPV4:-"<EC2_PUBLIC_IP>"}:8010/healthz

  Day 3 Vulnerable RAG health check:
    http://${PUBLIC_IPV4:-"<EC2_PUBLIC_IP>"}:8011/healthz

  Day 4 Vulnerable RAG health check:
    http://${PUBLIC_IPV4:-"<EC2_PUBLIC_IP>"}:8012/healthz

  Day 5 Vulnerable RAG health check:
    http://${PUBLIC_IPV4:-"<EC2_PUBLIC_IP>"}:8013/healthz

  Day 3 Vulnerable Agent health check:
    http://${PUBLIC_IPV4:-"<EC2_PUBLIC_IP>"}:8001/healthz

  Day 2 Fake Model Registry model list:
    http://${PUBLIC_IPV4:-"<EC2_PUBLIC_IP>"}:8002/api/v1/models

  LLMGoat web UI:
    http://${PUBLIC_IPV4:-"<EC2_PUBLIC_IP>"}:5000

  Day 3 DVLA web UI:
    http://${PUBLIC_IPV4:-"<EC2_PUBLIC_IP>"}:8501

터미널 검증 명령:
  # Ollama generate API smoke test
  curl http://\$EC2_DOMAIN:11434/api/generate \\
    -d '{
      "model": "$OLLAMA_MODEL",
      "prompt": "ready",
      "stream": false,
      "options": {
        "num_predict": 5
      }
    }' | jq

  # API 응답 확인
  curl -fsS http://\$EC2_DOMAIN:8080/ >/dev/null
  curl -fsS http://\$EC2_DOMAIN:11434/api/tags | jq
  curl -fsS http://\$EC2_DOMAIN:8000/healthz
  curl -fsS http://\$EC2_DOMAIN:8010/healthz
  curl -fsS http://\$EC2_DOMAIN:8011/healthz
  curl -fsS http://\$EC2_DOMAIN:8012/healthz
  curl -fsS http://\$EC2_DOMAIN:8013/healthz
  curl -fsS http://\$EC2_DOMAIN:8001/healthz
  curl -fsS http://\$EC2_DOMAIN:8002/api/v1/models | jq

주의: public IP 직접 접속은 Terraform allowed_ingress_cidr가 본인 IP/32로 열려 있을 때만 동작합니다.

비용 안전장치:
  Terraform 기본 설정은 매일 17:30 KST에 Lambda를 호출해 실행 중인 실습 EC2를 자동 중지합니다.
  필요하면 auto_stop_schedule_mode로 야간 반복 모드 또는 custom cron을 선택할 수 있습니다.

EOF
