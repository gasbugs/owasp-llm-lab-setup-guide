# Packer — 골든 AMI 빌드

수강생 또는 강사가 `terraform apply`로 만드는 실습 인스턴스가 이 AMI에서 출발합니다. 현재 운영 모델은 매일 재배포가 아니라 같은 EC2/EBS를 stop/start로 이어서 사용하는 방식입니다. **AMI 안에 가능한 모든 것을 넣어** 첫 부팅과 강의 중 다운로드 시간을 줄이는 것이 목표입니다.

## AMI에 포함되는 것

- Ubuntu 24.04 LTS + 최신 보안 패치
- NVIDIA Driver + CUDA Toolkit 12.8
- nvidia-container-toolkit (CDI 모드, `/etc/cdi/nvidia.yaml` 사전 생성)
- **Docker Engine + Docker Compose v2** (일반 daemon, `ubuntu`는 `docker` 그룹)
- AWS CLI v2 + SSM 에이전트
- 강의용 컨테이너 이미지 (공개 GHCR에서 사전 anonymous docker pull)
- LLM 모델 weights (`llama3.1:8b-instruct-q4_K_M`, 약 5GB)

포함하지 않는 것:

- 수강생 작업물, 정답, 이전 실행의 검증 증거
- `tests/e2e/` checkout. 강사용 검증 도구는 AMI에 굽지 않고 검증할 저장소 커밋에서 실행한다.

## 사전 준비 — 강사 측

골든 AMI를 빌드하기 **전**에 강의 컨테이너 이미지가 공개 GHCR에 push되어 있어야 합니다.

```bash
cd ../../docker
SETUP_COMMIT=$(git rev-parse HEAD)
IMAGE_NAMESPACE=gasbugs \
TAG="sha-$SETUP_COMMIT" \
  ./build-and-push.sh
```

이후 Packer가 그 이미지를 docker pull로 캐시.

## 빌드 절차

```bash
cd infrastructure/packer
SETUP_COMMIT=$(git rev-parse HEAD)
packer init ami.pkr.hcl
packer build \
  -var "aws_profile=owasp-llm" \
  -var "region=us-east-1" \
  -var "image_namespace=gasbugs" \
  -var "image_tag=sha-$SETUP_COMMIT" \
  ami.pkr.hcl
```

결과는 `manifest.json`에 AMI ID가 기록된다. Terraform에서 이 Packer AMI 계열을 자동 선택하려면 `terraform.tfvars`에 아래처럼 설정한다.

```hcl
ami_owner_id     = "self"
ami_name_pattern = "owasp-llm-lab-*"
```

## 빌드 시간 / 비용

| 단계 | 소요 |
|---|---|
| 베이스 OS 부팅 | 1분 |
| 시스템 패키지 | 3분 |
| NVIDIA 드라이버 + CUDA | 10분 (재부팅 포함) |
| Docker + CDI 설정 | 2분 |
| 이미지 docker pull + 모델 weights | 15~20분 |
| AMI 생성 | 5분 |
| **총** | **35~40분** |

빌드 비용은 리전, 빌드 시간, 환율, VAT에 따라 달라진다. 강의 직전에는 실제 사용할 리전의 `g6.xlarge` 단가로 다시 계산한다.

## 자주 발생하는 이슈

**NVIDIA 드라이버 설치 후 재부팅이 끊기는 경우**
- `expect_disconnect = true` 설정으로 처리. Packer가 자동 재접속.
- 그래도 멈추면 보통 SG에 SSH 22번이 안 열려있는 경우. Packer 임시 SG에는 22가 열려야 함(Packer 기본 동작).

**Docker 컨테이너에서 GPU가 안 보임**
- `/etc/docker/daemon.json`에 NVIDIA runtime 설정이 있어야 한다. `30-docker.sh`가 `nvidia-ctk runtime configure --runtime=docker`로 만든다.
- 설정을 바꾼 뒤에는 `sudo systemctl restart docker`를 실행한다.
- 확인: `sudo -u ubuntu docker run --rm --gpus all docker.io/nvidia/cuda:12.8.2-base-ubuntu24.04 nvidia-smi`

**모델 weights 다운로드 실패**
- Ollama 컨테이너가 들어오는 동안 listen하지 않은 경우. `sleep` 늘리기.
- 또는 빌드 인스턴스에서 외부 인터넷 접근 차단 시 → 빌드 VPC는 인터넷 허용해야 함.

**GHCR pull이 `unauthorized`로 실패**
- `ghcr.io/gasbugs/owasp-llm-*` 다섯 package의 visibility가 모두 `Public`인지 확인한다.
- 로컬 credential 영향이 없는 환경에서 `docker manifest inspect ghcr.io/gasbugs/owasp-llm-base-gpu:<tag>`가 인증 없이 성공해야 AMI 빌드를 시작한다.

**AMI 용량 초과**
- `root_volume_size = 100`까지 확인. 더 큰 모델 추가 시 150GB 이상으로 키우기.
- 강의 인스턴스 EBS 크기도 같이 늘려야 함 (`terraform.tfvars`의 `root_volume_size`).

## Docker daemon 관련 주의

Docker는 system service로 활성화되므로 SSM 세션이 끝나도 Compose 컨테이너는 계속 실행된다. `ubuntu` 사용자가 새로 `docker` 그룹에 들어간 직후의 기존 셸에서는 권한이 갱신되지 않을 수 있으므로 새 SSM 세션에서 확인한다.

## 변형 — 가벼운 모델로 바꾸기

`-var "default_model=llama3.2:3b-instruct-q4_K_M"`로 빌드하면 weights 2GB, 빌드 5분 단축, 강의 중 응답 빠르지만 일부 jailbreak 페이로드가 너무 쉽게 동작(교육 효과 ↓). 권장 안 함.
