# Instructor live validation

최근 진단 실행 기록: [2026-07-10 EC2 live validation](LIVE-VALIDATION-2026-07-10.md)

이 문서는 이 저장소의 특정 main 커밋에서 만든 런타임 이미지 세트를 EC2에 설치하고, 고정 포트·health 계약·e2e 결과를 같은 커밋 증거로 남기는 표준 절차입니다. 이 저장소가 AWS/Podman 런타임과 실측 검증 코드의 단일 기준입니다.

`tests/e2e/`는 공개된 강사용 검증 도구이며 수강생 과제나 채점 기준이 아닙니다. 의도적으로 취약한 동작을 실행하므로 본인이 허가한 개인 실습 계정에서만 사용합니다.

## 비용 상한이 있는 단일 커밋 전수 실행

아래 강사용 controller는 이 문서의 commit pin, Terraform user-data 설치, strict e2e, 현재 PyPI `NOT_FOUND` 후보의 격리 설치, Day 5 live-validation harness, 증거 회수와 destroy를 한 번에 묶습니다. 공개 이미지 원본은 `ghcr.io/gasbugs`로 고정하며 자격증명을 저장하지 않습니다. `COURSE_REPO`는 `capstone/solutions/validate-live.sh`를 포함한 로컬 강의 저장소 절대 경로입니다.

```bash
SETUP_COMMIT=$(git rev-parse origin/main)
COURSE_COMMIT=$(git -C /absolute/path/to/owasp-top-10-for-llm rev-parse origin/main)

SETUP_COMMIT="$SETUP_COMMIT" \
COURSE_COMMIT="$COURSE_COMMIT" \
COURSE_REPO=/absolute/path/to/owasp-top-10-for-llm \
ALERT_EMAIL=instructor@example.com \
AWS_PROFILE=owasp-llm \
AWS_REGION=us-east-1 \
STUDENT=validator \
EMERGENCY_STOP_MINUTES=120 \
  bash infrastructure/scripts/instructor/run-commit-live-validation.sh
```

controller는 setup과 course의 명시한 40자리 commit이 각각 공개 `origin/main`에 있고 course worktree가 완전히 clean인지 먼저 확인합니다. 이후 두 저장소를 임시 `git archive`로 분리하며, Terraform state와 Capstone upload, 로컬 browser harness도 이 고정 복사본만 사용합니다. 공개 GHCR의 다섯 이미지에서 tag digest와 `linux/amd64` digest를 고정하고, EC2의 실제 Podman digest와 `org.opencontainers.image.revision`이 다르면 테스트를 시작하지 않습니다.

EC2 생성 전에는 선택한 Playwright package/browser를 실제 headless launch/close하고 로컬 `18011`, `18501`, `15000` 포트가 비어 있는지도 확인합니다. 원격 strict core가 끝나면 controller가 SSM forward `8011→18011`, `8501→18501`, `5000→15000`을 bounded child process로 열고 Day 3 UI/DVLA와 LLMGoat A01 harness를 실행합니다. LLMGoat UI는 API `response`의 정확한 DOM 반영과 boolean `solved`에 따른 overlay/sidebar 일치를 검사하며, solved 자체는 관찰값으로만 남깁니다. 결과와 세 forward cleanup 증거를 원격 raw bundle에 원자적으로 전달한 뒤에만 archive를 닫습니다. `STRICT_ACCEPTANCE=true TRIALS=5` full-cycle의 종료 코드를 그대로 사용하며 LLM10 timeout 같은 결과를 controller가 임의로 성공으로 바꾸지 않습니다. raw evidence archive와 SHA-256은 기본적으로 `$HOME/owasp-llm-live-evidence/<run-id>/remote/`에 회수됩니다.

테스트가 실패해도 원격 runner의 EXIT trap이 현재 증거를 먼저 archive합니다. 원격 timeout/crash면 controller가 기존 run root를 `partial=true`로 별도 archive해 회수합니다. 그 직후 captured instance ID와 고유 `Course` 태그로 EC2 terminate를 직접 요청하고 terminated 상태를 확인한 다음, `terraform destroy`로 나머지 자원을 정리합니다. 마지막에는 Terraform state뿐 아니라 EC2, EBS, 네트워크, Lambda, EventBridge, SNS, IAM, Budget을 직접 조회합니다. 증거 회수·직접 terminate·destroy·잔여 자원 확인 중 하나라도 실패하면 전체 명령도 실패합니다. 이 controller에는 인스턴스를 남기는 옵션이 없습니다.

## 1. 검증 커밋과 이미지 세트 고정

main에 반영된 40자리 커밋을 선택합니다. PR 커밋은 테스트만 실행하며 publish하지 않습니다.

```bash
git fetch origin main
SETUP_COMMIT=$(git rev-parse origin/main)
test "${#SETUP_COMMIT}" -eq 40
IMAGE_TAG="sha-$SETUP_COMMIT"
printf 'SETUP_COMMIT=%s\nIMAGE_TAG=%s\n' "$SETUP_COMMIT" "$IMAGE_TAG"
```

GitHub Actions의 `Test, Build & Push Runtime Images`가 성공했는지 확인하고 다섯 manifest가 존재하는지 확인합니다.
이 검사는 저장된 registry credential이 없는 환경에서도 성공해야 하며, 실패하면 package visibility를 `Public`으로 바로잡은 뒤에만 EC2를 생성합니다.

```bash
for image in base-gpu vuln-rag vuln-agent llmgoat dvla; do
  podman manifest inspect \
    "ghcr.io/gasbugs/owasp-llm-${image}:${IMAGE_TAG}" >/dev/null
done
```

CI는 기존 SHA 태그 덮어쓰기를 거부하고 각 commit 태그를 publish하며, 모든 이미지가 성공한 경우에만 그 세트를 `latest`로 승격합니다. 실측 증거에는 이동하는 `latest`를 사용하지 않고, 실제 pull된 resolved digest를 함께 기록합니다. upstream base의 이동 태그 때문에 Git commit만으로 bit-for-bit 재빌드를 보장하지 않으므로 digest가 최종 실행 식별자입니다.

## 2. 로컬 정적 게이트 재현

```bash
python3 -m unittest discover -s tests/unit -p 'test_*.py' -v
python3 -m compileall -q docker tests
find infrastructure tests docker -type f -name '*.sh' -print0 | xargs -0 -n1 bash -n
terraform fmt -check -recursive infrastructure/terraform
terraform -chdir=infrastructure/terraform init -backend=false -input=false
terraform -chdir=infrastructure/terraform validate
packer fmt -check infrastructure/packer/ami.pkr.hcl
packer init infrastructure/packer/ami.pkr.hcl
packer validate -syntax-only infrastructure/packer/ami.pkr.hcl
for context in base-gpu vuln-rag vuln-agent llmgoat dvla; do
  docker build --check "docker/$context"
done
```

unit suite에는 tool-call parser, 동일 응답의 DOM sink replay, 공개 파일의 PII/secret placeholder 검사가 포함됩니다.

## 3. EC2 준비와 정확한 커밋 checkout

Terraform과 설치 절차는 [`STUDENT-QUICKSTART.md`](STUDENT-QUICKSTART.md)를 공유합니다. 기본 `allowed_ingress_cidr = "127.0.0.1/32"`를 유지하고 SSM으로 접속합니다.

최초 부팅 user-data로 설치할 때는 1단계의 동일한 commit을 Terraform 입력에도 전달합니다. 기존 `terraform.tfvars`의 필수값을 채운 뒤, **인스턴스를 처음 만드는 apply**에서 실행합니다.

```bash
terraform -chdir=infrastructure/terraform apply -auto-approve \
  -var='enable_user_data_bootstrap=true' \
  -var="lab_setup_repo_raw_url=https://raw.githubusercontent.com/gasbugs/owasp-llm-lab-setup-guide/$SETUP_COMMIT" \
  -var='lab_image_namespace=gasbugs' \
  -var="lab_image_tag=$IMAGE_TAG"
```

`user_data_replace_on_change = false`이므로 이미 생성된 인스턴스에서 이 변수만 바꿔도 user-data가 다시 실행되거나 인스턴스가 자동 교체되지 않습니다. 기존 인스턴스를 보존해야 하면 아래 수동 설치 절차를 사용하고, 교체가 필요하면 증거와 작업물을 먼저 회수한 뒤 명시적인 재생성 절차를 수행합니다.

EC2의 SSM 세션 안에서 검증할 커밋을 checkout합니다.

```bash
# 1단계에서 고정한 실제 값으로 바꿉니다.
SETUP_COMMIT=0123456789abcdef0123456789abcdef01234567
IMAGE_TAG="sha-$SETUP_COMMIT"

command -v git >/dev/null || {
  sudo apt-get update -y
  sudo apt-get install -y --no-install-recommends git
}

cd /home/ubuntu
if [ ! -d owasp-llm-lab-setup-guide/.git ]; then
  git clone https://github.com/gasbugs/owasp-llm-lab-setup-guide.git
fi
cd owasp-llm-lab-setup-guide
git fetch origin main
git checkout --detach "$SETUP_COMMIT"
test "$(git rev-parse HEAD)" = "$SETUP_COMMIT"
```

같은 커밋의 설치 스크립트와 이미지 태그를 묶어서 실행합니다.

```bash
sudo env \
  IMAGE_NAMESPACE=gasbugs \
  IMAGE_TAG="$IMAGE_TAG" \
  REFRESH_IMAGES=true \
  LAB_SETUP_REPO_RAW_URL="https://raw.githubusercontent.com/gasbugs/owasp-llm-lab-setup-guide/$SETUP_COMMIT" \
  bash infrastructure/scripts/student/install-lab.sh
```

설치 후 기록이 일치해야 합니다.

```bash
grep -E '^(IMAGE_NAMESPACE|IMAGE_TAG)=' /etc/lab/env
sudo -u ubuntu podman ps --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}'
```

## 4. 고정 포트와 health 계약

| 포트 | 서비스 | 계약 |
|---:|---|---|
| 8000 | `lab-day1-vuln-rag` | `default_scenario=day1` |
| 8010 | `lab-day2-vuln-rag` | `default_scenario=day2` |
| 8011 | `lab-day3-vuln-rag` | `default_scenario=day3` |
| 8012 | `lab-day4-vuln-rag` | `default_scenario=day4` |
| 8013 | `lab-day5-vuln-rag` | `default_scenario=day5` |
| 8001 | `lab-day3-vuln-agent` | `ok=true`, tool catalog 존재 |
| 8002 | `lab-day2-fake-registry` | `/api/v1/models` JSON |
| 8080 | `lab-portal` | HTTP 200 |
| 5000 | `lab-llmgoat` | web/API |
| 8501 | `lab-day3-dvla` | Streamlit health |
| 11434 | `lab-ollama` | `/api/tags` JSON |

RAG health의 canonical JSON shape은 다음과 같습니다.

```json
{"ok":true,"default_scenario":"day3","scenarios":["day1","day2","day3","day4","day5"]}
```

다섯 포트의 scenario를 한 번에 확인합니다.

```bash
for pair in day1:8000 day2:8010 day3:8011 day4:8012 day5:8013; do
  scenario=${pair%%:*}
  port=${pair##*:}
  curl -fsS "http://localhost:${port}/healthz" \
    | jq -e --arg scenario "$scenario" \
        '.ok == true and .default_scenario == $scenario and (.scenarios | length == 5)'
done

curl -fsS http://localhost:8001/healthz \
  | jq -e '.ok == true and (.tools | length == 7)'
curl -fsS http://localhost:8002/api/v1/models | jq -e '.models | length > 0'
curl -fsS http://localhost:8080/ >/dev/null
curl -fsS http://localhost:5000/api/model_status \
  | jq -e '.model_busy == false'
curl -fsS http://localhost:8501/_stcore/health
curl -fsS http://localhost:11434/api/tags | jq -e '.models | type == "array"'
```

`vuln-rag` 이미지의 CMD와 HEALTHCHECK는 모두 `PORT`를 사용하고, Quadlet은 각 unit에 같은 `PORT`와 uvicorn 포트를 주입합니다. 정상 앱이 잘못된 8000 probe 때문에 `unhealthy`가 되는 상태는 허용하지 않습니다.

DVLA wrapper는 upstream `ReversecLabs/damn-vulnerable-llm-agent`의 commit `c0cf9a14adad76e9d6a53c41741f625334bd9971`을 고정해 빌드합니다.

## 5. e2e 실행

필수 도구는 `bash`, `curl`, `jq`, `python3`입니다. 테스트 대상 URL은 loopback만 허용됩니다.

빠른 선택 검증:

```bash
mkdir -p "$HOME/work/e2e-evidence/manual-$SETUP_COMMIT"
RESULTS_DIR="$HOME/work/e2e-evidence/manual-$SETUP_COMMIT" \
TRIALS=5 \
  bash tests/e2e/run-all.sh llm05 llm06
```

전체 런타임 검증:

```bash
TRIALS=5 bash tests/e2e/run-full-cycle.sh
```

full-cycle은 다섯 RAG 포트와 Agent를 순회한 뒤 LLMGoat
A01/A02/A04/A06/A08 API를 실제 호출하고, 마지막에 LLM10을 실행합니다. LLMGoat의
각 HTTP request/response는 `llmgoat/raw/requests.jsonl`에 원문 JSON과 SHA-256으로
남습니다. A04는 review 추가 전·후·reset 상태 hash, A08은 vector export·import·reset
상태 hash를 `llmgoat/state-contracts.jsonl`에 기록하며 원상 복원이 다르면 즉시
실패합니다.

LLM 출력 성공률과 LLMGoat `solved`는 확률적 관측값입니다. tool catalog, caller
binding, JSON parser, HTTP 계약, LLMGoat mutable-state reset처럼 결정적인 검사는
pass/fail로 구분합니다. timeout·모델 미기동·네트워크 실패는 취약점 부재가 아니라
인프라 실패입니다.

## 6. 증거 고정

가장 최근 full-cycle 디렉터리를 찾아 커밋·이미지·모델 정보를 함께 기록합니다.

```bash
EVIDENCE_DIR=$(find "$HOME/work/e2e-evidence" -mindepth 1 -maxdepth 1 -type d \
  -name '20*' -print | sort | tail -1)
test -n "$EVIDENCE_DIR"

{
  set -a
  source /etc/lab/env
  set +a

  printf 'setup_commit=%s\n' "$SETUP_COMMIT"
  printf 'image_tag=%s\n' "$IMAGE_TAG"
  printf 'validated_at=%s\n' "$(date -Iseconds)"
  printf 'instance_id=%s\n' "${INSTANCE_ID:-unknown}"
  printf 'ollama_model=%s\n' "${OLLAMA_MODEL:-unknown}"
  sudo -u ubuntu podman ps --format 'image={{.Image}} name={{.Names}} status={{.Status}}'

  for image in base-gpu vuln-rag vuln-agent llmgoat dvla; do
    ref="ghcr.io/${IMAGE_NAMESPACE}/owasp-llm-${image}:${IMAGE_TAG}"
    sudo -u ubuntu podman image inspect "$ref" \
      | jq -r --arg reference "$ref" \
          '.[0] | "reference=\($reference) image_id=\(.Id) digest=\(.Digest // "unknown") repo_digests=\((.RepoDigests // []) | join(","))"'
  done
} > "$EVIDENCE_DIR/runtime-manifest.txt"

tar -C "$(dirname "$EVIDENCE_DIR")" -czf "$EVIDENCE_DIR.tgz" "$(basename "$EVIDENCE_DIR")"
sha256sum "$EVIDENCE_DIR.tgz" > "$EVIDENCE_DIR.tgz.sha256"
```

보존 대상은 다음입니다.

- `runtime-manifest.txt`: commit, image tag, model, 컨테이너 상태
- `log.txt`, `summary.txt`: full-cycle 실행 흐름과 최종 상태
- `llm*/results.jsonl`: 판정과 성공률
- `llm*/raw/`: 원문 응답
- `llmgoat/results.jsonl`: A01/A02/A04/A06/A08 solved/unsolved 실측 관찰
- `llmgoat/raw/requests.jsonl`: loopback API 요청·응답·HTTP·SHA-256 원문 증거
- `llmgoat/state-contracts.jsonl`: A04/A08 변이와 원상 복원 hash 계약
- `browser-evidence/llmgoat-*`: A01 실제 화면 응답·solved 표시·스크린샷
- `.tgz.sha256`: 회수한 archive의 무결성 값

raw 응답에는 실습용 비밀값과 공격 payload가 포함될 수 있습니다. public branch에 자동 commit하지 말고 승인된 강사 저장 위치로 회수합니다.

## 7. 종료

증거 확인 후 자동 중지 시각을 기다리지 말고 강사 머신에서 직접 종료합니다. `SETUP_REPO`는 이 저장소의 로컬 checkout 절대 경로입니다.

```bash
SETUP_REPO=/absolute/path/to/owasp-llm-lab-setup-guide
cd "$SETUP_REPO"

AWS_PROFILE=owasp-llm AWS_REGION=us-east-1 STUDENT=yourname \
  bash infrastructure/scripts/student/stop-lab.sh
```

Terraform의 기본 17:30 KST 자동 중지는 수동 종료 누락에 대비한 보조 안전장치입니다. 정상 검증 절차의 마지막 단계는 항상 직접 `stop-lab.sh`를 실행하는 것입니다.

한 번만 사용하는 강사용 검증 환경이고 증거 회수가 끝났다면 stop으로 끝내지 말고 리소스를 삭제합니다. plan을 검토한 뒤 실행하세요.

```bash
terraform -chdir="$SETUP_REPO/infrastructure/terraform" plan -destroy
terraform -chdir="$SETUP_REPO/infrastructure/terraform" destroy
```
