# Instructor live validation

최근 진단 실행 기록: [2026-07-10 EC2 live validation](LIVE-VALIDATION-2026-07-10.md)

이 문서는 이 저장소의 특정 main 커밋에서 만든 런타임 이미지 세트를 EC2에 설치하고, 고정 포트·health 계약·e2e 결과를 같은 커밋 증거로 남기는 표준 절차입니다. 이 저장소가 AWS/Podman 런타임과 실측 검증 코드의 단일 기준입니다.

`tests/e2e/`는 공개된 강사용 검증 도구이며 수강생 과제나 채점 기준이 아닙니다. 의도적으로 취약한 동작을 실행하므로 본인이 허가한 개인 실습 계정에서만 사용합니다.

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

```bash
for image in base-gpu vuln-rag vuln-agent llmgoat dvla; do
  podman manifest inspect \
    "docker.io/gasbugs/owasp-llm-${image}:${IMAGE_TAG}" >/dev/null
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

full-cycle은 다섯 RAG 포트와 Agent를 순회하며 실패한 script 또는 scenario health를 non-zero exit로 반환합니다. LLM 출력 성공률은 확률적 관측값입니다. tool catalog, caller binding, JSON parser, HTTP 계약처럼 결정적인 검사는 pass/fail로 구분합니다. timeout·모델 미기동·네트워크 실패는 취약점 부재가 아니라 인프라 실패입니다.

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
    ref="docker.io/${IMAGE_NAMESPACE}/owasp-llm-${image}:${IMAGE_TAG}"
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
