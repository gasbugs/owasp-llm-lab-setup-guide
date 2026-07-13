# Troubleshooting

## Terraform apply에서 GPU quota 오류

증상:

```text
VcpuLimitExceeded
You have requested more vCPU capacity than your current vCPU limit
```

확인:

```bash
aws service-quotas get-service-quota \
  --profile owasp-llm --region us-east-1 \
  --service-code ec2 --quota-code L-DB2E81BA \
  --query "Quota.{Name:QuotaName,Value:Value}"
```

해결:

- AWS Console -> Service Quotas -> EC2
- `Running On-Demand G and VT instances`를 4 vCPU 이상으로 증설 신청

## SSM 접속 실패

확인:

```bash
aws ssm describe-instance-information \
  --profile owasp-llm --region us-east-1 \
  --query "InstanceInformationList[].{Id:InstanceId,Ping:PingStatus}"
```

해결:

- 인스턴스가 `running`인지 확인
- 최초 부팅 직후라면 2~5분 기다림
- IAM instance profile이 붙었는지 확인
- 로컬에 Session Manager Plugin이 설치됐는지 확인

## 앱이 안 뜸

SSM 접속 후:

```bash
sudo tail -n 200 /var/log/owasp-llm-lab-install.log
sudo -u ubuntu podman ps -a
sudo -u ubuntu podman logs lab-ollama --tail 100
sudo -u ubuntu podman logs lab-day1-vuln-rag --tail 100
sudo -u ubuntu podman logs lab-day2-vuln-rag --tail 100
```

흔한 원인:

- 공개 GHCR package pull 실패(`unauthorized`이면 package visibility가 `Public`인지 확인)
- Ollama 모델 pull이 오래 걸림
- GPU CDI 파일 누락
- 디스크 공간 부족
- 아직 `install-lab.sh`를 실행하지 않음

Quadlet unit 상태 확인:

```bash
UBUNTU_UID=$(id -u ubuntu)
sudo -u ubuntu \
  XDG_RUNTIME_DIR=/run/user/$UBUNTU_UID \
  DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$UBUNTU_UID/bus \
  systemctl --user status lab-ollama.service
sudo -u ubuntu \
  XDG_RUNTIME_DIR=/run/user/$UBUNTU_UID \
  DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$UBUNTU_UID/bus \
  systemctl --user status lab-day1-vuln-rag.service
```

`Failed to enable unit: ... is transient or generated`가 보이면 오래된 설치 스크립트가 Quadlet generated unit에 `enable`을 시도한 것입니다. 최신 `install-lab.sh`를 다시 실행하세요. Quadlet은 `.container` 파일의 `[Install]` 설정을 generator가 처리하므로, generated `.service`에 직접 `enable`을 실행하지 않습니다.

## 설치를 깨끗하게 다시 하고 싶을 때

SSM 세션 안에서 실행합니다. 기본 클린업은 컨테이너와 Quadlet unit만 제거하고 작업물과 모델 캐시는 보존합니다.

```bash
curl -fsSL https://raw.githubusercontent.com/gasbugs/owasp-llm-lab-setup-guide/main/infrastructure/scripts/student/cleanup-lab.sh | sudo bash
curl -fsSL https://raw.githubusercontent.com/gasbugs/owasp-llm-lab-setup-guide/main/infrastructure/scripts/student/install-lab.sh | sudo bash
```

모델 캐시까지 모두 지우는 완전 정리는 아래처럼 실행합니다.

```bash
curl -fsSL https://raw.githubusercontent.com/gasbugs/owasp-llm-lab-setup-guide/main/infrastructure/scripts/student/cleanup-lab.sh | sudo bash -s -- --purge
```

## GPU 인식 실패

```bash
nvidia-smi
ls -l /etc/cdi/nvidia.yaml
sudo nvidia-ctk cdi generate --output=/etc/cdi/nvidia.yaml
```

그 후 컨테이너 재시작:

```bash
sudo -u ubuntu podman restart lab-ollama
```

## LLM08 embedding/API/미니 앱 문제

정상 설치와 재설치 순서는 [LLM08 embedding lab setup](LLM08-SETUP.md)이 정본입니다. 먼저 **강사·콘텐츠 배포자가 공개 main source와 같은 commit의 GHCR 이미지가 모두 있는지** 확인합니다. 아래 publish gate는 강사용이며, 수강생은 공지된 40자리 setup commit을 사용하고 로컬 PC에 Podman을 추가 설치하지 않습니다. 로컬 워킹트리에만 있는 파일은 EC2 installer나 image에 자동 반영되지 않습니다.

```bash
# [로컬 노트북] setup repo 루트
set -euo pipefail
git fetch origin main
SETUP_COMMIT=$(git rev-parse origin/main)
IMAGE_TAG="sha-$SETUP_COMMIT"
git cat-file -e "$SETUP_COMMIT:examples/llm08/mini_vector_search_app.py"
git cat-file -e "$SETUP_COMMIT:docker/vuln-rag/app/embedding.py"
podman manifest inspect \
  "ghcr.io/gasbugs/owasp-llm-vuln-rag:$IMAGE_TAG" >/dev/null
```

runtime 상태를 한 번에 수집합니다.

```bash
# [EC2 / SSM 세션, ubuntu 사용자]
set -euo pipefail
grep -E '^(SCRIPT_VERSION|IMAGE_TAG|OLLAMA_EMBED_MODEL)=' /etc/lab/env
podman ps --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}'
podman exec lab-ollama ollama list
curl -fsS --max-time 10 http://127.0.0.1:8012/healthz | jq
test -x "$HOME/work/llm08-analysis-venv/bin/python"
"$HOME/work/llm08-analysis-venv/bin/python" -c 'import numpy; print(numpy.__version__)'
```

증상별 해석은 다음과 같습니다.

- `/api/embed` HTTP 404: 8012가 Day 4인지 확인합니다. Day 4인데도 404라면 새 endpoint가 없는 구 `vuln-rag` 이미지입니다.
- HTTP 401: `Authorization: Bearer llm08-acme-demo-token`이 없거나 틀렸습니다. request body의 `tenant`로 인증을 대신하지 않습니다.
- HTTP 422: input이 비었거나 batch/길이 계약을 벗어났거나, safe endpoint에 `tenant` 같은 알 수 없는 필드를 넣었습니다.
- HTTP 502: Day 4 API가 Ollama embedding backend의 실패나 잘못된 vector 응답을 fail-closed로 거부한 것입니다.
- `bge-m3:latest`가 Ollama 목록에 없음: installer model pull이 끝나지 않았습니다. 설치 로그의 마지막 성공 단계를 확인합니다.
- `~/work/llm08-analysis-venv` 또는 scaffold가 없음: 구 installer/checkout을 사용했거나 설치가 중간 실패했습니다. 같은 published commit으로 재실행합니다.
- `dimensions`가 1024가 아님: 1024는 2026-07-13 측정 예입니다. model이 맞는지 확인하고 실제 합격 조건인 `dimensions > 0`과 vector 길이 일치를 검사합니다.

상세 로그와 직접 API 진단은 EC2에서 실행합니다.

```bash
# [EC2 / SSM 세션, ubuntu 사용자]
set -euo pipefail
tail -n 200 /var/log/owasp-llm-lab-install.log
podman logs --tail 200 lab-day4-vuln-rag
podman logs --tail 200 lab-ollama

curl -fsS --retry 2 --retry-all-errors --max-time 180 \
  http://127.0.0.1:8012/api/embed \
  -H 'Authorization: Bearer llm08-acme-demo-token' \
  -H 'Content-Type: application/json' \
  --data-binary '{"input":["embedding diagnostic"]}' \
  | jq -e '
      (.model | type == "string" and length > 0)
      and (.dimensions | type == "number" and . > 0)
      and (.dimensions as $d | .embeddings[0] | length == $d)
    '
```

미니 앱이 18080을 열지 못하면 다른 process를 바로 죽이지 말고 listener와 pid file의 소유를 비교합니다.

```bash
# [EC2 / SSM 세션, ubuntu 사용자]
ss -ltnp | grep ':18080' || true
if [ -r "$HOME/work/llm08-mini-app/server.pid" ]; then
  APP_PID=$(cat "$HOME/work/llm08-mini-app/server.pid")
  ps -p "$APP_PID" -o pid=,args=
fi
```

브라우저가 안 열리면 Security Group을 공개하지 말고 로컬 Session Manager Plugin, instance ID, forwarding terminal을 확인합니다.

```bash
# [로컬 노트북]
session-manager-plugin --version
aws ssm describe-instance-information \
  --profile owasp-llm --region us-east-1 \
  --query 'InstanceInformationList[].{Id:InstanceId,Ping:PingStatus}'
lsof -nP -iTCP:18080 -sTCP:LISTEN || true
```

작업이 끝나면 evidence를 먼저 보존하고 미니 앱/forwarding을 정리한 뒤, **마지막에 EC2를 중지해 `stopped`를 확인**합니다.

## 비용이 걱정될 때

현재 상태 확인:

```bash
aws ec2 describe-instances \
  --profile owasp-llm --region us-east-1 \
  --filters "Name=tag:Course,Values=owasp-llm-2026" \
  --query "Reservations[].Instances[].{Id:InstanceId,State:State.Name,Type:InstanceType}"
```

즉시 중지:

```bash
AWS_PROFILE=owasp-llm AWS_REGION=us-east-1 STUDENT=yourname \
  bash infrastructure/scripts/student/stop-lab.sh
```

강의 종료 후 삭제:

```bash
cd infrastructure/terraform
terraform destroy
```
