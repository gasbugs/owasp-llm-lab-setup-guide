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
exec > >(tee -a "$LOG_FILE" | logger -t owasp-llm-install) 2>&1

RAW_URL="${LAB_SETUP_REPO_RAW_URL:-https://raw.githubusercontent.com/gasbugs/owasp-llm-lab-setup-guide/main}"
IMAGE_NAMESPACE="${IMAGE_NAMESPACE:-gasbugs}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
OLLAMA_MODEL="${OLLAMA_MODEL:-llama3.1:8b-instruct-q4_K_M}"
LLAMA_GUARD_MODEL="${LLAMA_GUARD_MODEL:-llama-guard3:8b}"

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
  podman podman-compose podman-docker crun fuse-overlayfs slirp4netns uidmap

# rootless 설정
touch /etc/containers/nodocker
grep -q '^ubuntu:' /etc/subuid || echo "ubuntu:100000:65536" >> /etc/subuid
grep -q '^ubuntu:' /etc/subgid || echo "ubuntu:100000:65536" >> /etc/subgid
loginctl enable-linger ubuntu
UBUNTU_UID=$(id -u ubuntu)
systemctl start "user@$UBUNTU_UID.service" || true

# CDI 모드 nvidia
nvidia-ctk cdi generate --output=/etc/cdi/nvidia.yaml || \
  echo "(nvidia-ctk 미설치 — apt install nvidia-container-toolkit 필요)"

# 5) Ollama 모델 디렉터리
install -d -m 0755 -o ubuntu -g ubuntu /home/ubuntu/ollama-models

# 6) 컨테이너 이미지 pull
runuser -u ubuntu -- bash <<PULLSH
set -euo pipefail
for img in owasp-llm-base-gpu owasp-llm-vuln-rag owasp-llm-vuln-agent owasp-llm-llmgoat owasp-llm-dvla; do
  for i in \$(seq 1 3); do
    if podman pull "docker.io/${IMAGE_NAMESPACE}/\${img}:${IMAGE_TAG}"; then
      break
    fi
    echo "  retry \$i/3..."; sleep 5
  done
done
PULLSH

# 7) 시나리오 결정
DAY=$(date +%u)
PROFILE="day$DAY"
[ "$DAY" -gt 5 ] && PROFILE="day1"

# 8) 컨테이너 실행
runuser -u ubuntu -- podman run -d --replace --name lab-ollama \
  --device nvidia.com/gpu=all \
  -p 11434:11434 \
  -v /home/ubuntu/ollama-models:/root/.ollama:Z \
  -e OLLAMA_HOST=0.0.0.0:11434 \
  -e OLLAMA_KEEP_ALIVE=24h \
  docker.io/ollama/ollama:latest

runuser -u ubuntu -- podman run -d --replace --name lab-vuln-rag \
  --network host \
  -e SCENARIO="$PROFILE" \
  -e OLLAMA_URL=http://localhost:11434 \
  -e OLLAMA_MODEL="$OLLAMA_MODEL" \
  "docker.io/${IMAGE_NAMESPACE}/owasp-llm-vuln-rag:${IMAGE_TAG}"

runuser -u ubuntu -- podman run -d --replace --name lab-vuln-agent \
  --network host \
  -e OLLAMA_URL=http://localhost:11434 \
  -e OLLAMA_MODEL="$OLLAMA_MODEL" \
  "docker.io/${IMAGE_NAMESPACE}/owasp-llm-vuln-agent:${IMAGE_TAG}"

mkdir -p /home/ubuntu/.LLMGoat/models /home/ubuntu/.LLMGoat/cache
chown -R ubuntu:ubuntu /home/ubuntu/.LLMGoat
runuser -u ubuntu -- podman run -d --replace --name lab-llmgoat \
  --device nvidia.com/gpu=all \
  -p 5000:5000 \
  -e LLMGOAT_SERVER_HOST=0.0.0.0 \
  -e LLMGOAT_SERVER_PORT=5000 \
  -e LLMGOAT_DEFAULT_MODEL=gemma-2.gguf \
  -e LLMGOAT_N_GPU_LAYERS=20 \
  -e LLMGOAT_N_THREADS=4 \
  -v /home/ubuntu/.LLMGoat/models:/root/.LLMGoat/models:Z \
  -v /home/ubuntu/.LLMGoat/cache:/root/.LLMGoat/cache:Z \
  "docker.io/${IMAGE_NAMESPACE}/owasp-llm-llmgoat:${IMAGE_TAG}"

runuser -u ubuntu -- podman run -d --replace --name lab-dvla \
  --network host \
  -e OLLAMA_HOST=http://localhost:11434 \
  -e model_name=ollama-local-llama3 \
  "docker.io/${IMAGE_NAMESPACE}/owasp-llm-dvla:${IMAGE_TAG}"

# Day 2 LLM03 Supply Chain — fake model-registry (port 8002)
mkdir -p /home/ubuntu/work/fake-registry
curl -fsSL "$RAW_URL/infrastructure/fake-registry/server.py" -o /home/ubuntu/work/fake-registry/server.py
chown -R ubuntu:ubuntu /home/ubuntu/work/fake-registry
runuser -u ubuntu -- podman run -d --replace --name lab-fake-registry \
  --network host \
  -v /home/ubuntu/work/fake-registry:/app:Z \
  docker.io/library/python:3.12-slim \
  python /app/server.py

# 9) Ollama 모델 pull 및 warm-up
runuser -u ubuntu -- bash <<OLLAMASH
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

python3 -m venv /home/ubuntu/work/embedding-venv 2>/dev/null || true
/home/ubuntu/work/embedding-venv/bin/pip install -q sentence-transformers scikit-learn numpy 2>&1 | tail -2 || true
chown -R ubuntu:ubuntu /home/ubuntu/work/embedding-venv 2>/dev/null || true
echo "[install-lab] embedding-venv ready for Day 4 LLM08-A"
OLLAMASH

# 10) systemd unit으로 컨테이너 자동 재시작 등록
runuser -u ubuntu -- env XDG_RUNTIME_DIR="/run/user/$UBUNTU_UID" bash <<'SYSDSH'
set -euo pipefail
mkdir -p /home/ubuntu/.config/systemd/user
cd /home/ubuntu/.config/systemd/user
for c in lab-ollama lab-vuln-rag lab-vuln-agent lab-llmgoat lab-dvla lab-fake-registry; do
  rm -f "container-$c.service"
  podman generate systemd --name "$c" --files --restart-policy=always --new=false
done
systemctl --user daemon-reload
for c in lab-ollama lab-vuln-rag lab-vuln-agent lab-llmgoat lab-dvla lab-fake-registry; do
  systemctl --user enable "container-$c.service"
done
SYSDSH

# 11) 비용 안전망: 설치 시점부터 240분 후 OS-level 자동 stop
shutdown -h +240 "[auto-stop] 4h cost safety net — sudo shutdown -c to cancel" || true

echo "=== owasp-llm-lab manual install done: $(date -Iseconds) ==="
echo "설치 로그: $LOG_FILE"
echo "컨테이너 확인: sudo -u ubuntu podman ps"
