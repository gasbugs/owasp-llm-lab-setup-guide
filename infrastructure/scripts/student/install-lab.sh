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
IMAGE_NAMESPACE="${IMAGE_NAMESPACE:-gasbugs}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
OLLAMA_MODEL="${OLLAMA_MODEL:-llama3.1:8b-instruct-q4_K_M}"
LLAMA_GUARD_MODEL="${LLAMA_GUARD_MODEL:-llama-guard3:8b}"
INSTALL_START_EPOCH=$(date +%s)

echo "=== owasp-llm-lab manual install start: $(date -Iseconds) ==="
echo "RAW_URL=$RAW_URL"
echo "IMAGE_NAMESPACE=$IMAGE_NAMESPACE IMAGE_TAG=$IMAGE_TAG"

# 1) IMDSv2로 instance metadata와 tag 조회
TOKEN=$(curl -fsS -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
HDR="X-aws-ec2-metadata-token: $TOKEN"
INSTANCE_ID=$(curl -fsSH "$HDR" http://169.254.169.254/latest/meta-data/instance-id)
IDENTITY_DOCUMENT=$(curl -fsSH "$HDR" http://169.254.169.254/latest/dynamic/instance-identity/document)
REGION=$(printf '%s' "$IDENTITY_DOCUMENT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["region"])')
STUDENT=$(curl -fsSH "$HDR" http://169.254.169.254/latest/meta-data/tags/instance/Student 2>/dev/null || echo "student")
COURSE_ID=$(curl -fsSH "$HDR" http://169.254.169.254/latest/meta-data/tags/instance/Course 2>/dev/null || echo "owasp-llm")

echo "INSTANCE_ID=$INSTANCE_ID REGION=$REGION STUDENT=$STUDENT COURSE_ID=$COURSE_ID"

# 2) /etc/lab/env
install -d -m 0755 /etc/lab
cat > /etc/lab/env <<EOF
STUDENT=$STUDENT
COURSE_ID=$COURSE_ID
AWS_DEFAULT_REGION=$REGION
IMAGE_NAMESPACE=$IMAGE_NAMESPACE
IMAGE_TAG=$IMAGE_TAG
OLLAMA_MODEL=$OLLAMA_MODEL
EOF
chmod 0644 /etc/lab/env

# 3) 작업 디렉터리 생성
install -d -m 0755 -o ubuntu -g ubuntu /home/ubuntu/work

# 4) Podman 설치
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends \
  curl ca-certificates git \
  python3-venv \
  podman podman-compose podman-docker crun fuse-overlayfs slirp4netns uidmap

# rootless 설정
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
nvidia-ctk cdi generate --output=/etc/cdi/nvidia.yaml || \
  echo "(nvidia-ctk 미설치 — apt install nvidia-container-toolkit 필요)"

# 5) Ollama 모델 디렉터리
install -d -m 0755 -o ubuntu -g ubuntu /home/ubuntu/ollama-models

# 6) 컨테이너 이미지 pull
"${RUN_AS_UBUNTU[@]}" bash <<PULLSH
set -euo pipefail
for img in owasp-llm-base-gpu owasp-llm-vuln-rag owasp-llm-vuln-agent owasp-llm-llmgoat owasp-llm-dvla; do
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
DAY=$(date +%u)
PROFILE="day$DAY"
[ "$DAY" -gt 5 ] && PROFILE="day1"

# 8) Quadlet으로 컨테이너 systemd user unit 작성 및 실행
# podman generate systemd는 deprecated라 새 설치에서는 Quadlet을 직접 사용한다.
mkdir -p /home/ubuntu/.LLMGoat/models /home/ubuntu/.LLMGoat/cache
chown -R ubuntu:ubuntu /home/ubuntu/.LLMGoat

# Day 2 LLM03 Supply Chain — fake model-registry (port 8002)
mkdir -p /home/ubuntu/work/fake-registry
curl -fsSL "$RAW_URL/infrastructure/fake-registry/server.py" -o /home/ubuntu/work/fake-registry/server.py
chown -R ubuntu:ubuntu /home/ubuntu/work/fake-registry

QUADLET_DIR="/home/ubuntu/.config/containers/systemd"
install -d -m 0755 -o ubuntu -g ubuntu "$QUADLET_DIR"

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

cat > "$QUADLET_DIR/lab-vuln-rag.container" <<EOF
[Unit]
Description=OWASP LLM Lab - Vulnerable RAG
After=lab-ollama.container
Requires=lab-ollama.container

[Container]
ContainerName=lab-vuln-rag
Image=docker.io/${IMAGE_NAMESPACE}/owasp-llm-vuln-rag:${IMAGE_TAG}
Network=host
Environment=SCENARIO=$PROFILE
Environment=OLLAMA_URL=http://localhost:11434
Environment=OLLAMA_MODEL=$OLLAMA_MODEL

[Service]
Restart=always

[Install]
WantedBy=default.target
EOF

cat > "$QUADLET_DIR/lab-vuln-agent.container" <<EOF
[Unit]
Description=OWASP LLM Lab - Vulnerable Agent
After=lab-ollama.container
Requires=lab-ollama.container

[Container]
ContainerName=lab-vuln-agent
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
Environment=LLMGOAT_N_GPU_LAYERS=20
Environment=LLMGOAT_N_THREADS=4
Volume=/home/ubuntu/.LLMGoat/models:/root/.LLMGoat/models:Z
Volume=/home/ubuntu/.LLMGoat/cache:/root/.LLMGoat/cache:Z

[Service]
Restart=always

[Install]
WantedBy=default.target
EOF

cat > "$QUADLET_DIR/lab-dvla.container" <<EOF
[Unit]
Description=OWASP LLM Lab - Damn Vulnerable LLM Agent
After=lab-ollama.container
Requires=lab-ollama.container

[Container]
ContainerName=lab-dvla
Image=docker.io/${IMAGE_NAMESPACE}/owasp-llm-dvla:${IMAGE_TAG}
Network=host
Environment=OLLAMA_HOST=http://localhost:11434
Environment=model_name=ollama-local-llama3

[Service]
Restart=always

[Install]
WantedBy=default.target
EOF

cat > "$QUADLET_DIR/lab-fake-registry.container" <<'EOF'
[Unit]
Description=OWASP LLM Lab - Fake Model Registry

[Container]
ContainerName=lab-fake-registry
Image=docker.io/library/python:3.12-slim
Network=host
Volume=/home/ubuntu/work/fake-registry:/app:Z
Exec=python /app/server.py

[Service]
Restart=always

[Install]
WantedBy=default.target
EOF

chown -R ubuntu:ubuntu "$QUADLET_DIR"

"${RUN_AS_UBUNTU[@]}" bash <<'QUADLETSH'
set -euo pipefail
units=(lab-ollama lab-vuln-rag lab-vuln-agent lab-llmgoat lab-dvla lab-fake-registry)
for unit in "${units[@]}"; do
  systemctl --user stop "$unit.service" >/dev/null 2>&1 || true
done
for container in "${units[@]}"; do
  podman rm -f "$container" >/dev/null 2>&1 || true
done
systemctl --user daemon-reload
for unit in "${units[@]}"; do
  systemctl --user reset-failed "$unit.service" >/dev/null 2>&1 || true
  systemctl --user start "$unit.service"
done
QUADLETSH

# 9) Ollama 모델 pull 및 warm-up
"${RUN_AS_UBUNTU[@]}" bash <<OLLAMASH
set -euo pipefail
for i in \$(seq 1 60); do
  if curl -fs http://localhost:11434/api/tags >/dev/null 2>&1; then
    break
  fi
  sleep 5
done
podman exec lab-ollama ollama pull "$OLLAMA_MODEL"
podman exec lab-ollama ollama pull "$LLAMA_GUARD_MODEL" 2>&1 | tail -3 || true
echo "[install-lab] $LLAMA_GUARD_MODEL pulled (Day 5 Defense demo)"

curl -s --max-time 120 http://localhost:11434/api/generate \
  -d "{\"model\":\"$OLLAMA_MODEL\",\"prompt\":\"ready\",\"stream\":false,\"options\":{\"num_predict\":5}}" >/dev/null 2>&1 || true
echo "[install-lab] ollama warm-up done"

rm -rf /home/ubuntu/work/embedding-venv
python3 -m venv /home/ubuntu/work/embedding-venv
/home/ubuntu/work/embedding-venv/bin/pip install -q sentence-transformers scikit-learn numpy
chown -R ubuntu:ubuntu /home/ubuntu/work/embedding-venv 2>/dev/null || true
echo "[install-lab] embedding-venv ready for Day 4 LLM08-A"
OLLAMASH

# 11) 비용 안전망: 설치 시점부터 240분 후 OS-level 자동 stop
shutdown -h +240 "[auto-stop] 4h cost safety net — sudo shutdown -c to cancel" || true

INSTALL_END_EPOCH=$(date +%s)
INSTALL_DURATION=$((INSTALL_END_EPOCH - INSTALL_START_EPOCH))
INSTALL_DURATION_MIN=$((INSTALL_DURATION / 60))
INSTALL_DURATION_SEC=$((INSTALL_DURATION % 60))

cat <<EOF

============================================================
OWASP LLM Lab 설치가 완료되었습니다.
============================================================

완료 시각: $(date -Iseconds)
총 설치 시간: ${INSTALL_DURATION_MIN}분 ${INSTALL_DURATION_SEC}초
설치 로그: $LOG_FILE

다음 명령으로 실행 중인 실습 컨테이너를 확인하세요.
  sudo -u ubuntu podman ps

주요 서비스 포트:
  - Vulnerable RAG:        8000
  - Vulnerable Agent:      8001
  - Fake Model Registry:   8002
  - LLMGoat:               5000
  - DVLA:                  8501
  - Ollama API:            11434

비용 안전장치로 이 인스턴스는 약 4시간 후 자동 종료 예약되었습니다.
자동 종료를 취소하려면 다음 명령을 실행하세요.
  sudo shutdown -c

EOF
