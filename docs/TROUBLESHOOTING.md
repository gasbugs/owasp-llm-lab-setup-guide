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
