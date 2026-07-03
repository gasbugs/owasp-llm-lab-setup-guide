#!/bin/bash
# user-data — DLAMI(Ubuntu 24.04 + NVIDIA driver + Docker)에서 부팅 시 1회 실행
#
# 흐름:
#   1) 학생 ID·환경변수 셋업
#   2) 작업 디렉터리 생성 (학생이 개인 GitHub 작업 repo에 push로 보존)
#   3) Podman 설치 (DLAMI엔 docker만 있음)
#   4) 컨테이너 이미지 Docker Hub pull
#   5) Day별 시나리오 컨테이너 기동
#
# 작업물 보존:
#   강사 계정 S3 사용 X. 학생이 개인 GitHub 작업 repo에 git push.
#   매일 종료 → 다음날 start → systemd user unit으로 컨테이너 자동 재시작.

set -euo pipefail
exec > >(tee /var/log/user-data.log | logger -t user-data) 2>&1

echo "=== owasp-llm-lab user-data start: $(date -Iseconds) ==="

# 1) IMDSv2로 instance ID + 태그 직접 조회
TOKEN=$(curl -sX PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
HDR="X-aws-ec2-metadata-token: $TOKEN"
INSTANCE_ID=$(curl -sH "$HDR" http://169.254.169.254/latest/meta-data/instance-id)
STUDENT=$(curl -sH "$HDR" http://169.254.169.254/latest/meta-data/tags/instance/Student)

echo "INSTANCE_ID=$INSTANCE_ID STUDENT=$STUDENT"

# 2) /etc/lab/env
install -d -m 0755 /etc/lab
cat > /etc/lab/env <<EOF
STUDENT=$STUDENT
COURSE_ID=${course_id}
AWS_DEFAULT_REGION=${region}
EOF
chmod 0644 /etc/lab/env

# 3) 작업 디렉터리 생성 (학생이 개인 GitHub 작업 repo에 push로 보존)
install -d -m 0755 -o ubuntu -g ubuntu /home/ubuntu/work

# 4) Podman 설치 (DLAMI엔 docker만, rootless podman 강의용)
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends \
    podman podman-compose podman-docker crun fuse-overlayfs slirp4netns uidmap

# rootless 설정
touch /etc/containers/nodocker
grep -q '^ubuntu:' /etc/subuid || echo "ubuntu:100000:65536" >> /etc/subuid
grep -q '^ubuntu:' /etc/subgid || echo "ubuntu:100000:65536" >> /etc/subgid
loginctl enable-linger ubuntu

# CDI 모드 nvidia (DLAMI에 nvidia-container-toolkit 이미 있음)
nvidia-ctk cdi generate --output=/etc/cdi/nvidia.yaml || \
  echo "(nvidia-ctk 미설치 — apt install nvidia-container-toolkit 필요)"

# 5) Ollama 모델 디렉터리 + 모델 pull
install -d -m 0755 -o ubuntu -g ubuntu /home/ubuntu/ollama-models

# 6) 컨테이너 이미지 pull (Docker Hub에서 30초~1분)
#    이전: podman build 3회 (5~10분). 강의 직전 학생 인스턴스를 빠르게 띄우기 위해 pull로 전환.
#    수동 빌드는 강의 자료에 Stretch로 포함 (Day 1 환경 셋업 + Day 2 LLM03 무결성 검증).
runuser -u ubuntu -- bash <<'PULLSH'
set -e
for img in owasp-llm-base-gpu owasp-llm-vuln-rag owasp-llm-vuln-agent owasp-llm-llmgoat owasp-llm-dvla; do
  for i in $(seq 1 3); do
    if podman pull "docker.io/gasbugs/$${img}:latest"; then break; fi
    echo "  retry $i/3..."; sleep 5
  done
done
PULLSH

# 7) 시나리오 결정
DAY=$(date +%u)
PROFILE="day$DAY"
[ "$DAY" -gt 5 ] && PROFILE="day1"

# 8) 직접 podman run (compose 의존 제거 — 어제 podman compose --profile 호환성 이슈 우회)
# Ollama (host network 안 씀 — 별도 컨테이너로 GPU)
runuser -u ubuntu -- podman run -d --replace --name lab-ollama \
  --device nvidia.com/gpu=all \
  -p 11434:11434 \
  -v /home/ubuntu/ollama-models:/root/.ollama:Z \
  -e OLLAMA_HOST=0.0.0.0:11434 \
  -e OLLAMA_KEEP_ALIVE=24h \
  docker.io/ollama/ollama:latest

# vuln-rag (host network로 ollama 접근, 8000 포트)
runuser -u ubuntu -- podman run -d --replace --name lab-vuln-rag \
  --network host \
  -e SCENARIO=$PROFILE \
  -e OLLAMA_URL=http://localhost:11434 \
  -e OLLAMA_MODEL=llama3.1:8b-instruct-q4_K_M \
  docker.io/gasbugs/owasp-llm-vuln-rag:latest

# vuln-agent (host network, 8001 포트)
runuser -u ubuntu -- podman run -d --replace --name lab-vuln-agent \
  --network host \
  -e OLLAMA_URL=http://localhost:11434 \
  -e OLLAMA_MODEL=llama3.1:8b-instruct-q4_K_M \
  docker.io/gasbugs/owasp-llm-vuln-agent:latest

# lab-llmgoat (SECFORCE/LLMGoat wrapper, Apache 2.0) — Day 1·3·5 cross-platform
# gemma-2-9b GGUF + llama-cpp. 본 강의 llama3.1:8b와 *모델 차이* 비교 목적
# 포트 5000. GPU 필요 (--device nvidia.com/gpu=all)
# 첫 부팅 시 gemma-2 모델 ~5GB Hugging Face 자동 다운로드 (인스턴스 EBS에 영구 캐시)
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
  docker.io/gasbugs/owasp-llm-llmgoat:latest

# lab-dvla (WithSecureLabs/damn-vulnerable-llm-agent, Apache 2.0) — Day 3 LLM06 cross-platform
# 본 lab-ollama 공유. ReAct Agent 취약 (vuln-agent function calling과 비교)
# 포트 8501 Streamlit
runuser -u ubuntu -- podman run -d --replace --name lab-dvla \
  --network host \
  -e OLLAMA_HOST=http://localhost:11434 \
  -e model_name=ollama-local-llama3 \
  docker.io/gasbugs/owasp-llm-dvla:latest

# Day 2 LLM03 Supply Chain — fake model-registry (port 8002)
# 스크립트는 Terraform 패키지의 `infrastructure/fake-registry/server.py`를 user-data에 삽입한다.
mkdir -p /home/ubuntu/work/fake-registry
cat >/home/ubuntu/work/fake-registry/server.py.b64 <<'FAKEREGISTRY'
${fake_registry_server_b64}
FAKEREGISTRY
base64 -d /home/ubuntu/work/fake-registry/server.py.b64 >/home/ubuntu/work/fake-registry/server.py
rm -f /home/ubuntu/work/fake-registry/server.py.b64
chown -R ubuntu:ubuntu /home/ubuntu/work/fake-registry
runuser -u ubuntu -- podman run -d --replace --name lab-fake-registry \
  --network host \
  -v /home/ubuntu/work/fake-registry:/app:Z \
  docker.io/library/python:3.12-slim \
  python /app/server.py

# 9) Ollama 모델 사전 pull (Ollama healthz 대기 후)
runuser -u ubuntu -- bash <<'OLLAMASH'
for i in $(seq 1 60); do
  if curl -fs http://localhost:11434/api/tags >/dev/null 2>&1; then break; fi
  sleep 5
done
podman exec lab-ollama ollama pull llama3.1:8b-instruct-q4_K_M

# Day 5 방어 종합 lab용 — Llama Guard 3 8B (~5GB) 추가 pull (디스크만, warm-up 안 함)
# 학생 데모: podman exec lab-ollama ollama run llama-guard3 "input text"
podman exec lab-ollama ollama pull llama-guard3:8b 2>&1 | tail -3 || true
echo "[user-data] llama-guard3:8b pulled (Day 5 Defense demo)"

# 모델 *메모리에 로딩* (warm-up) — 첫 호출 timeout 방지 (D-9 발견)
# ollama pull은 *디스크에만* 받음. 메모리 로딩은 *첫 API 호출 시*에 발생 → 첫 호출 ~30~60초 timeout.
# warm-up 1회로 메모리에 미리 로딩. KEEP_ALIVE=24h로 24h 동안 unload 안 함.
curl -s --max-time 120 http://localhost:11434/api/generate \
  -d '{"model":"llama3.1:8b-instruct-q4_K_M","prompt":"ready","stream":false,"options":{"num_predict":5}}' >/dev/null 2>&1 || true
echo "[user-data] ollama warm-up done"

# Day 4 LLM08-A 실습용 — 호스트 venv에 sentence-transformers 사전 설치
# vuln-rag 컨테이너는 슬림 deps라 임베딩 모듈 없음 (의도된 설계). 호스트에서 별도 사용.
python3 -m venv /home/ubuntu/work/embedding-venv 2>/dev/null || true
/home/ubuntu/work/embedding-venv/bin/pip install -q sentence-transformers scikit-learn numpy 2>&1 | tail -2 || true
chown -R ubuntu:ubuntu /home/ubuntu/work/embedding-venv 2>/dev/null || true
echo "[user-data] embedding-venv ready for Day 4 LLM08-A"
OLLAMASH

# 10) systemd unit으로 컨테이너 자동 재시작 등록 (instance start 시 자동)
#     인스턴스가 stop → start 됐을 때 podman 컨테이너가 자동으로 다시 켜지도록.
#     podman generate systemd 사용.
runuser -u ubuntu -- bash <<'SYSDSH'
mkdir -p /home/ubuntu/.config/systemd/user
cd /home/ubuntu/.config/systemd/user
for c in lab-ollama lab-vuln-rag lab-vuln-agent lab-llmgoat lab-dvla lab-fake-registry; do
  podman generate systemd --name "$c" --files --restart-policy=always --new=false
done
systemctl --user daemon-reload
for c in lab-ollama lab-vuln-rag lab-vuln-agent lab-llmgoat lab-dvla lab-fake-registry; do
  systemctl --user enable "container-$c.service"
done
SYSDSH

# 11) 학생 작업 보존 안내 (강의 자료에 상세):
#   매일 종료 전 개인 GitHub 작업 repo에 push:
#     cd ~/work && git add . && git commit -m "Day-N $(date +%F)" && git push origin main

# =========================================================
# 안전망: 부팅 240분 후 OS-level 자동 stop (비용 보호)
# - 강사·학생이 잊어도 4h 후 인스턴스 자동 종료
# - EBS는 유지 → 다음 start 시 어제 상태 그대로 복원
# - 작업 더 필요하면: sudo shutdown -c (cancel) 또는 sudo shutdown -h +N (extend)
# =========================================================
shutdown -h +240 "[auto-stop] 4h cost safety net — sudo shutdown -c to cancel" || true

echo "=== owasp-llm-lab user-data done: $(date -Iseconds) ==="
echo "=== auto-stop scheduled at $(date -d '+240 min' -Iseconds 2>/dev/null || date -v +240M -Iseconds) ==="
