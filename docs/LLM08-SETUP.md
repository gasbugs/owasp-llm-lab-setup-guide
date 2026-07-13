# LLM08 embedding lab setup

이 문서는 Day 2 LLM08 실습에 추가된 embedding runtime, 분석 환경, 학습자 미니 앱을 **새 EC2와 기존 EC2에 같은 방식으로 준비하고 검증하는 정본 가이드**입니다. 일반적인 AWS 준비는 [Student Quickstart](STUDENT-QUICKSTART.md), 전체 이미지 세트의 강사용 검증은 [Instructor live validation](LIVE-VALIDATION.md)을 함께 따릅니다.

LLM08 환경은 다음 구성요소를 함께 사용합니다.

- `lab-ollama:11434`: `bge-m3:latest` embedding 생성
- `lab-day4-vuln-rag:8012`: 인증된 LLM08 lab API와 교육용 인메모리 cosine 검색
- `~/work/llm08-analysis-venv`: NumPy 기반 cosine/PCA 분석 환경
- `examples/llm08/mini_vector_search_app.py`: 학습자가 복사해 공격하고 수정하는 미니 앱
- `127.0.0.1:18080`: 학습자 미니 앱의 EC2 loopback 포트

이 실습은 허가된 개인 AWS 계정의 교육용 취약 환경에서만 실행합니다. Security Group에 8012, 11434, 18080을 공개하지 말고 SSM Session Manager와 port forwarding을 사용합니다.

> 비용 종료 계약: 검증이 성공했든 중간에 실패했든, 증거와 진단 자료를 보존한 다음 **이 문서 9절을 마지막 작업으로 실행해 EC2가 `stopped`인지 확인**합니다. 다음 날 진단을 이어갈 때도 실행 상태로 방치하지 않습니다.

## 셸 위치 표기

모든 명령 블록 첫 줄에는 실행 위치가 있습니다.

- `[로컬 노트북]`: Git, Terraform, AWS CLI, Session Manager Plugin이 있는 수강생 PC
- `[EC2 / SSM 세션]`: SSM으로 접속한 EC2. 첫 접속 직후 `sudo -iu ubuntu`로 전환
- `[로컬 노트북 / 새 터미널]`: 기존 SSM shell을 유지한 채 여는 별도 터미널

위치를 바꾸어 실행하지 마십시오. 특히 `localhost:8012`는 **EC2 안의 Day 4 서버**를 뜻합니다.

## 0. 강사 publish gate: EC2를 켜기 전에 확인

로컬 워킹트리에 코드가 있는 것과 수강생이 설치할 수 있는 것은 다릅니다. 다음 세 조건이 모두 참이어야 합니다.

1. LLM08 소스와 scaffold가 공개 `main`의 한 commit에 존재한다.
2. `Test, Build & Push Runtime Images`가 그 commit의 이미지 다섯 개를 공개 GHCR에 publish했다.
3. 설치 스크립트 commit과 이미지의 `sha-<commit>` tag가 같다.

아래 명령은 **강사·콘텐츠 배포자**가 한 번 실행하는 release gate입니다. 수강생은 로컬에 Podman을 추가 설치하지 않고, 강사가 `PUBLISH_GATE=PASS`와 함께 공지한 40자리 `SETUP_COMMIT`을 사용합니다. gate가 실패하면 **EC2를 생성하거나 시작하지 말고** commit push와 이미지 workflow 완료를 기다립니다. `latest`가 우연히 존재하는 것만으로는 새 LLM08 기능의 배포를 증명하지 못합니다.

```bash
# [로컬 노트북] setup repo 루트
set -euo pipefail

git fetch origin main
SETUP_COMMIT="${SETUP_COMMIT:-$(git rev-parse origin/main)}"
case "$SETUP_COMMIT" in
  (''|*[!0-9a-f]*) echo "ERROR: SETUP_COMMIT must be lowercase hex" >&2; exit 1 ;;
esac
[ "${#SETUP_COMMIT}" -eq 40 ] || {
  echo "ERROR: SETUP_COMMIT must be a full 40-character commit" >&2
  exit 1
}
git merge-base --is-ancestor "$SETUP_COMMIT" origin/main || {
  echo "ERROR: SETUP_COMMIT is not published on origin/main" >&2
  exit 1
}

for path in \
  infrastructure/scripts/student/install-lab.sh \
  docker/vuln-rag/app/embedding.py \
  examples/llm08/mini_vector_search_app.py; do
  git cat-file -e "$SETUP_COMMIT:$path" || {
    echo "ERROR: origin/main commit lacks $path" >&2
    exit 1
  }
done
git grep -Fq 'bge-m3:latest' "$SETUP_COMMIT" -- \
  infrastructure/scripts/student/install-lab.sh
git grep -Fq '/api/embed' "$SETUP_COMMIT" -- docker/vuln-rag/app/main.py

command -v podman >/dev/null || {
  echo "ERROR: podman is required for the anonymous GHCR manifest gate" >&2
  exit 1
}
IMAGE_TAG="sha-$SETUP_COMMIT"
for image in base-gpu vuln-rag vuln-agent llmgoat dvla; do
  ref="ghcr.io/gasbugs/owasp-llm-${image}:${IMAGE_TAG}"
  podman manifest inspect "$ref" >/dev/null || {
    echo "ERROR: image is not published or public: $ref" >&2
    exit 1
  }
done

printf 'PUBLISH_GATE=PASS\nSETUP_COMMIT=%s\nIMAGE_TAG=%s\n' \
  "$SETUP_COMMIT" "$IMAGE_TAG"
```

통과 출력은 다음 형태입니다. 실제 commit 값은 실행 시점마다 달라집니다.

```text
PUBLISH_GATE=PASS
SETUP_COMMIT=<40-character commit on origin/main>
IMAGE_TAG=sha-<same 40-character commit>
```

이 두 값을 설치가 끝날 때까지 유지합니다. 새 터미널이나 EC2에서는 출력된 실제 40자리 값을 다시 입력합니다.

## 1A. 새 EC2 경로

[Student Quickstart](STUDENT-QUICKSTART.md)의 로컬 preflight와 Terraform 변수 작성을 먼저 완료합니다. LLM08 최초 설치는 수동 설치를 권장합니다.

```hcl
enable_user_data_bootstrap = false
allowed_ingress_cidr       = "127.0.0.1/32"
```

EC2를 만들고 단일 수강생 instance ID를 fail-closed로 조회합니다.

```bash
# [로컬 노트북] setup repo 루트
set -euo pipefail
export AWS_PROFILE=owasp-llm
export AWS_REGION=us-east-1
export STUDENT=yourname

terraform -chdir=infrastructure/terraform init
terraform -chdir=infrastructure/terraform plan
terraform -chdir=infrastructure/terraform apply -auto-approve

INSTANCE_ID=$(AWS_PROFILE="$AWS_PROFILE" AWS_REGION="$AWS_REGION" \
  STUDENT="$STUDENT" \
  bash infrastructure/scripts/student/instance-id.sh)
test -n "$INSTANCE_ID"
aws ec2 wait instance-running --profile "$AWS_PROFILE" \
  --region "$AWS_REGION" --instance-ids "$INSTANCE_ID"
```

SSM agent가 Online이 될 때까지 bounded polling한 뒤 접속합니다.

```bash
# [로컬 노트북]
set -euo pipefail
PING=""
for _ in $(seq 1 60); do
  PING=$(aws ssm describe-instance-information \
    --profile "$AWS_PROFILE" --region "$AWS_REGION" \
    --filters "Key=InstanceIds,Values=$INSTANCE_ID" \
    --query 'InstanceInformationList[0].PingStatus' \
    --output text 2>/dev/null || true)
  [ "$PING" = "Online" ] && break
  sleep 5
done
[ "$PING" = "Online" ] || {
  echo "ERROR: SSM agent did not become Online" >&2
  exit 1
}
aws ssm start-session --profile "$AWS_PROFILE" \
  --region "$AWS_REGION" --target "$INSTANCE_ID"
```

SSM shell이 열리면 아래 공통 설치 경로로 이동합니다.

```bash
# [EC2 / SSM 세션]
sudo -iu ubuntu
test "$(id -un)" = ubuntu
```

## 1B. 기존 EC2 경로

기존 EC2는 EBS 작업물과 현재 설치 기록을 먼저 보존한 뒤 시작합니다. `start-lab.sh`는 Student tag가 같은 인스턴스가 여러 개면 자동으로 중단합니다.

```bash
# [로컬 노트북] setup repo 루트
set -euo pipefail
export AWS_PROFILE=owasp-llm
export AWS_REGION=us-east-1
export STUDENT=yourname

AWS_PROFILE="$AWS_PROFILE" AWS_REGION="$AWS_REGION" STUDENT="$STUDENT" \
  bash infrastructure/scripts/student/start-lab.sh
INSTANCE_ID=$(AWS_PROFILE="$AWS_PROFILE" AWS_REGION="$AWS_REGION" \
  STUDENT="$STUDENT" \
  bash infrastructure/scripts/student/instance-id.sh)
test -n "$INSTANCE_ID"
PING=""
for _ in $(seq 1 60); do
  PING=$(aws ssm describe-instance-information \
    --profile "$AWS_PROFILE" --region "$AWS_REGION" \
    --filters "Key=InstanceIds,Values=$INSTANCE_ID" \
    --query 'InstanceInformationList[0].PingStatus' \
    --output text 2>/dev/null || true)
  [ "$PING" = "Online" ] && break
  sleep 5
done
[ "$PING" = "Online" ] || {
  echo "ERROR: SSM agent did not become Online" >&2
  exit 1
}
aws ssm start-session --profile "$AWS_PROFILE" \
  --region "$AWS_REGION" --target "$INSTANCE_ID"
```

SSM shell에서 lab runtime을 소유한 `ubuntu` 사용자로 전환합니다.

```bash
# [EC2 / SSM 세션]
sudo -iu ubuntu
test "$(id -un)" = ubuntu
```

기존 EC2에서 설치 전 상태를 복사합니다. 이 단계는 컨테이너나 학습자 파일을 삭제하지 않습니다.

```bash
# [EC2 / SSM 세션, ubuntu 사용자]
set -euo pipefail
umask 077
PREUPDATE_DIR="$HOME/work/llm08-preupdate-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$PREUPDATE_DIR"
if [ -r /etc/lab/env ]; then
  cp /etc/lab/env "$PREUPDATE_DIR/lab-env.before"
fi
if command -v podman >/dev/null; then
  podman ps --format '{{.Names}}\t{{.Image}}\t{{.Status}}' \
    > "$PREUPDATE_DIR/podman-ps.before.txt"
else
  printf 'podman_not_installed\n' > "$PREUPDATE_DIR/podman-ps.before.txt"
fi
printf 'PREUPDATE_DIR=%s\n' "$PREUPDATE_DIR"
```

## 2. 공통 설치 또는 안전한 재설치

새 EC2와 기존 EC2 모두 같은 commit 고정 디렉터리를 사용합니다. 기존의 `~/owasp-llm-lab-setup-guide`가 수정되어 있어도 덮어쓰지 않습니다.

```bash
# [EC2 / SSM 세션, ubuntu 사용자]
set -euo pipefail

# publish gate에서 출력된 실제 값으로 교체합니다.
SETUP_COMMIT=0123456789abcdef0123456789abcdef01234567
case "$SETUP_COMMIT" in
  (''|*[!0-9a-f]*) echo "ERROR: SETUP_COMMIT must be lowercase hex" >&2; exit 1 ;;
esac
[ "${#SETUP_COMMIT}" -eq 40 ] || {
  echo "ERROR: enter the full published SETUP_COMMIT" >&2
  exit 1
}
IMAGE_TAG="sha-$SETUP_COMMIT"
SETUP_DIR="$HOME/owasp-llm-lab-setup-guide-$SETUP_COMMIT"

if ! command -v git >/dev/null; then
  sudo apt-get update -y
  sudo apt-get install -y --no-install-recommends git ca-certificates
fi

if [ -e "$SETUP_DIR" ] && [ ! -d "$SETUP_DIR/.git" ]; then
  echo "ERROR: $SETUP_DIR exists but is not a Git checkout" >&2
  exit 1
fi
if [ ! -d "$SETUP_DIR/.git" ]; then
  git clone https://github.com/gasbugs/owasp-llm-lab-setup-guide.git \
    "$SETUP_DIR"
fi
git -C "$SETUP_DIR" fetch origin main
git -C "$SETUP_DIR" cat-file -e "$SETUP_COMMIT^{commit}"
git -C "$SETUP_DIR" checkout --detach "$SETUP_COMMIT"
test "$(git -C "$SETUP_DIR" rev-parse HEAD)" = "$SETUP_COMMIT"
git -C "$SETUP_DIR" diff --quiet
git -C "$SETUP_DIR" diff --cached --quiet

sudo env \
  IMAGE_NAMESPACE=gasbugs \
  IMAGE_TAG="$IMAGE_TAG" \
  REFRESH_IMAGES=true \
  LAB_SETUP_REPO_RAW_URL="https://raw.githubusercontent.com/gasbugs/owasp-llm-lab-setup-guide/$SETUP_COMMIT" \
  bash "$SETUP_DIR/infrastructure/scripts/student/install-lab.sh"
```

설치 스크립트는 같은 설정으로 다시 실행해도 현재 이미지와 Quadlet을 reconcile하며, 기존 `~/work` 전체를 삭제하지 않습니다. 최종 health까지 통과해야 `/etc/lab/env.pending`이 `/etc/lab/env`로 승격됩니다.

설치 commit과 실제 실행 이미지가 일치하는지 확인합니다.

```bash
# [EC2 / SSM 세션, ubuntu 사용자]
set -euo pipefail
grep -E '^(SCRIPT_VERSION|IMAGE_NAMESPACE|IMAGE_TAG|OLLAMA_EMBED_MODEL)=' \
  /etc/lab/env
test "$(awk -F= '$1 == "IMAGE_TAG" {print $2}' /etc/lab/env)" = "$IMAGE_TAG"
test "$(awk -F= '$1 == "OLLAMA_EMBED_MODEL" {print $2}' /etc/lab/env)" \
  = 'bge-m3:latest'

for container in \
  lab-day1-vuln-rag lab-day2-vuln-rag lab-day3-vuln-rag \
  lab-day4-vuln-rag lab-day5-vuln-rag; do
  test "$(podman inspect --format '{{.ImageName}}' "$container")" \
    = "ghcr.io/gasbugs/owasp-llm-vuln-rag:$IMAGE_TAG"
done
printf 'INSTALL_PIN=PASS\n'
```

## 3. LLM08 runtime 준비 확인

검증 출력은 비밀이 없는 전용 디렉터리에 보존합니다.

```bash
# [EC2 / SSM 세션, ubuntu 사용자]
set -euo pipefail
umask 077
RUN_ID="llm08-$(date -u +%Y%m%dT%H%M%SZ)"
EVIDENCE_DIR="$HOME/work/llm08-evidence/$RUN_ID"
mkdir -p "$EVIDENCE_DIR"
printf 'RUN_ID=%s\nEVIDENCE_DIR=%s\n' "$RUN_ID" "$EVIDENCE_DIR"

for command_name in curl jq python3; do
  command -v "$command_name" >/dev/null || {
    echo "ERROR: missing command: $command_name" >&2
    exit 1
  }
done

curl -fsS --max-time 10 http://127.0.0.1:8012/healthz \
  | tee "$EVIDENCE_DIR/day4-health.json" \
  | jq -e '.ok == true and .default_scenario == "day4"' >/dev/null

podman exec lab-ollama ollama list \
  | tee "$EVIDENCE_DIR/ollama-list.txt"
podman exec lab-ollama ollama list \
  | awk 'NR > 1 {print $1}' \
  | grep -qx 'bge-m3:latest'

test -x "$HOME/work/llm08-analysis-venv/bin/python"
"$HOME/work/llm08-analysis-venv/bin/python" -c \
  'import numpy; print("numpy=" + numpy.__version__)' \
  | tee "$EVIDENCE_DIR/analysis-venv.txt"

test -r "$SETUP_DIR/examples/llm08/mini_vector_search_app.py"
printf 'RUNTIME_PREREQUISITES=PASS\n'
```

Ollama API와 Day 4 인증 proxy가 같은 모델·차원 계약을 반환하는지 확인합니다. `dimensions == 1024`를 gate로 고정하지 않습니다. 계약은 **양의 차원이고 모든 vector 길이가 동일한 것**입니다.

```bash
# [EC2 / SSM 세션, ubuntu 사용자]
set -euo pipefail
export TARGET_URL=http://127.0.0.1:8012
export LLM08_TOKEN=llm08-acme-demo-token

curl -fsS --retry 2 --retry-all-errors --max-time 180 \
  "$TARGET_URL/api/embed" \
  -H "Authorization: Bearer $LLM08_TOKEN" \
  -H 'Content-Type: application/json' \
  --data-binary '{"input":["embedding setup check"]}' \
  -o "$EVIDENCE_DIR/embed.json"

EXPECTED_EMBED_MODEL=$(awk -F= \
  '$1 == "OLLAMA_EMBED_MODEL" {print $2}' /etc/lab/env)
test -n "$EXPECTED_EMBED_MODEL"
jq -e --arg model "$EXPECTED_EMBED_MODEL" '
  .lab_only == true
  and .engine == "ollama-api-embed-proxy"
  and .model == $model
  and (.dimensions | type == "number" and . > 0)
  and .input_count == 1
  and (.embeddings | length == 1)
  and (.dimensions as $d | .embeddings[0] | length == $d)
' "$EVIDENCE_DIR/embed.json" >/dev/null
jq '{engine,model,dimensions,input_count}' "$EVIDENCE_DIR/embed.json"
```

## 4. 취약·안전 검색 계약 확인

같은 인증 tenant와 질의를 사용하고 filter 위치만 비교합니다. 생성 문장의 문구는 판정에 사용하지 않습니다.

```bash
# [EC2 / SSM 세션, ubuntu 사용자]
set -euo pipefail
QUERY='경쟁 조직의 불사조 계획은 언제 실제 서비스에 투입되나요?'
SEARCH_BODY=$(jq -nc --arg query "$QUERY" '{query:$query,top_k:2}')

for mode in vulnerable safe; do
  curl -fsS --retry 2 --retry-all-errors --max-time 180 \
    -X POST "$TARGET_URL/api/labs/llm08/$mode/search" \
    -H "Authorization: Bearer $LLM08_TOKEN" \
    -H 'Content-Type: application/json' \
    --data-binary "$SEARCH_BODY" \
    -o "$EVIDENCE_DIR/$mode-search.json"
done

jq -e '
  .engine == "educational-in-memory-cosine"
  and .authenticated_context.tenant == "acme"
  and (.filter.applied | not)
  and .candidate_count == 4
  and any(.hits[]; .tenant == "beta")
' "$EVIDENCE_DIR/vulnerable-search.json" >/dev/null

jq -e '
  .engine == "educational-in-memory-cosine"
  and .authenticated_context.tenant == "acme"
  and .filter == {field:"tenant",applied:true,value:"acme"}
  and .candidate_count == 2
  and all(.hits[]; .tenant == "acme")
' "$EVIDENCE_DIR/safe-search.json" >/dev/null

jq -n \
  --slurpfile vulnerable "$EVIDENCE_DIR/vulnerable-search.json" \
  --slurpfile safe "$EVIDENCE_DIR/safe-search.json" '
    {vulnerable:{candidate_count:$vulnerable[0].candidate_count,
      top_hit:$vulnerable[0].hits[0]},
     safe:{candidate_count:$safe[0].candidate_count,
      top_hit:$safe[0].hits[0]}}
' | tee "$EVIDENCE_DIR/paired-summary.json"
printf 'PAIRED_SEARCH=PASS\n'
```

전체 강사용 LLM08 contract도 같은 evidence root에서 실행할 수 있습니다.

```bash
# [EC2 / SSM 세션, ubuntu 사용자]
set -euo pipefail
RESULTS_DIR="$EVIDENCE_DIR/e2e" \
TARGET_URL="$TARGET_URL" \
LLM08_ACME_TOKEN="$LLM08_TOKEN" \
  bash "$SETUP_DIR/tests/e2e/llm08/test_llm08_vector.sh"
```

## 5. 학습자 미니 앱 준비와 실행

학습자 작업본은 강의 문서와 cleanup helper가 함께 사용하는 고정 경로에 둡니다. 기존 수정본이 있으면 자동으로 덮어쓰지 않고 중단하므로 먼저 별도 파일로 보존합니다.

```bash
# [EC2 / SSM 세션, ubuntu 사용자]
set -euo pipefail
APP_DIR="$HOME/work/llm08-mini-app"
LEARNER_APP="$APP_DIR/learner_vector_app.py"
mkdir -p "$APP_DIR"
if [ ! -e "$LEARNER_APP" ]; then
  install -m 0755 \
    "$SETUP_DIR/examples/llm08/mini_vector_search_app.py" \
    "$LEARNER_APP"
fi
cmp -s "$SETUP_DIR/examples/llm08/mini_vector_search_app.py" \
  "$LEARNER_APP" || {
  echo "ERROR: learner copy differs; rename it as a backup, then rerun setup" >&2
  exit 1
}
cd "$APP_DIR"
python3 -m py_compile "$LEARNER_APP"

python3 "$LEARNER_APP" --query "$QUERY" --mode vulnerable \
  | tee "$EVIDENCE_DIR/mini-vulnerable.json"
python3 "$LEARNER_APP" --query "$QUERY" --mode safe \
  | tee "$EVIDENCE_DIR/mini-safe.json"

jq -e '.candidate_count == 4 and any(.hits[]; .tenant == "beta")' \
  "$EVIDENCE_DIR/mini-vulnerable.json" >/dev/null
jq -e '.candidate_count == 2 and all(.hits[]; .tenant == "acme")' \
  "$EVIDENCE_DIR/mini-safe.json" >/dev/null
```

loopback 18080을 다른 프로세스가 사용하면 임의로 종료하지 않고 중단합니다. 이미 이 앱의 pid가 살아 있으면 재사용하지 않고 먼저 8절의 정리 절차를 수행합니다.

```bash
# [EC2 / SSM 세션, ubuntu 사용자, APP_DIR]
set -euo pipefail
if ss -ltn | awk '$4 ~ /:18080$/ {found=1} END {exit(found ? 0 : 1)}'; then
  echo "ERROR: EC2 loopback port 18080 is already in use" >&2
  exit 1
fi

nohup env TARGET_URL="$TARGET_URL" LLM08_TOKEN="$LLM08_TOKEN" \
  python3 "$LEARNER_APP" \
    --serve --host 127.0.0.1 --port 18080 \
  > server.log 2>&1 &
APP_PID=$!
printf '%s\n' "$APP_PID" > server.pid

READY=false
for _ in $(seq 1 30); do
  if curl -fsS --max-time 2 http://127.0.0.1:18080/healthz \
    > "$EVIDENCE_DIR/mini-health.json"; then
    READY=true
    break
  fi
  kill -0 "$APP_PID" 2>/dev/null || break
  sleep 1
done
if [ "$READY" != true ]; then
  cp server.log "$EVIDENCE_DIR/mini-app.failed.log"
  kill "$APP_PID" 2>/dev/null || true
  rm -f server.pid
  echo "ERROR: mini app did not become healthy" >&2
  exit 1
fi
jq -e '.ok == true and .engine == "learner-mini-in-memory-cosine"' \
  "$EVIDENCE_DIR/mini-health.json" >/dev/null
printf 'MINI_APP=READY pid=%s\n' "$APP_PID"
```

request body의 `tenant`를 신뢰하지 않는지 HTTP 상태까지 확인합니다.

```bash
# [EC2 / SSM 세션, ubuntu 사용자]
set -euo pipefail
SPOOF_STATUS=$(curl -sS --max-time 30 \
  -o "$EVIDENCE_DIR/mini-body-tenant-spoof.json" \
  -w '%{http_code}' \
  -X POST http://127.0.0.1:18080/api/search \
  -H 'Content-Type: application/json' \
  --data-binary "$(jq -nc --arg query "$QUERY" \
    '{query:$query,mode:"safe",top_k:2,tenant:"beta"}')")
test "$SPOOF_STATUS" = 400 || {
  echo "ERROR: body tenant spoof returned HTTP $SPOOF_STATUS" >&2
  exit 1
}
jq -e '.error == "invalid_request"' \
  "$EVIDENCE_DIR/mini-body-tenant-spoof.json" >/dev/null
printf 'BODY_TENANT_SPOOF=REJECTED http=%s\n' "$SPOOF_STATUS"
```

## 6. SSM port forwarding과 브라우저 확인

미니 앱 UI는 EC2 loopback에만 열려 있습니다. 로컬 18080이 비어 있는지 확인한 뒤 별도 터미널에서 forwarding session을 엽니다.

```bash
# [로컬 노트북 / 새 터미널]
set -euo pipefail
if command -v lsof >/dev/null && \
  lsof -nP -iTCP:18080 -sTCP:LISTEN >/dev/null 2>&1; then
  echo "ERROR: local port 18080 is already in use" >&2
  exit 1
fi
aws ssm start-session --profile "$AWS_PROFILE" \
  --region "$AWS_REGION" --target "$INSTANCE_ID" \
  --document-name AWS-StartPortForwardingSession \
  --parameters 'portNumber=["18080"],localPortNumber=["18080"]'
```

세션을 유지한 상태에서 또 다른 로컬 터미널로 UI를 확인합니다.

```bash
# [로컬 노트북 / 새 터미널]
set -euo pipefail
curl -fsS --max-time 5 http://127.0.0.1:18080/healthz \
  | jq -e '.ok == true and .engine == "learner-mini-in-memory-cosine"'
printf 'Open http://127.0.0.1:18080/ in a browser.\n'
```

Day 4 API를 로컬에서 직접 진단할 때는 첫 forwarding session과 다른 터미널에서 8012를 18012로 전달합니다. 8012를 외부 ingress로 열지 않습니다.

```bash
# [로컬 노트북 / 새 터미널]
aws ssm start-session --profile "$AWS_PROFILE" \
  --region "$AWS_REGION" --target "$INSTANCE_ID" \
  --document-name AWS-StartPortForwardingSession \
  --parameters 'portNumber=["8012"],localPortNumber=["18012"]'
```

```bash
# [로컬 노트북 / 새 터미널]
curl -fsS --max-time 5 http://127.0.0.1:18012/healthz \
  | jq -e '.ok == true and .default_scenario == "day4"'
```

## 7. 2026-07-13 EC2 실측 출력

아래는 `us-east-1` EC2에서 `bge-m3:latest`로 측정한 예입니다. 모델 tag나 upstream artifact가 달라지면 score와 차원은 달라질 수 있으므로 **판정 계약은 model string 존재, `dimensions > 0`, vector 길이 일치, tenant filter 결과**입니다.

```text
{"engine":"ollama-api-embed-proxy","model":"bge-m3:latest","dimensions":1024,"input_count":1}
```

```text
vulnerable: filter_applied=false candidate_count=4 top=beta/launch.md tenant=beta score=0.42147773
safe:       filter_applied=true  candidate_count=2 top=acme/q1.md     tenant=acme score=0.31896812
```

```text
mini app vulnerable: candidate_count=4 top=beta/launch.md tenant=beta
mini app safe:       candidate_count=2 top=acme/q1.md tenant=acme
body tenant spoof:   HTTP 400 {"error":"invalid_request","detail":"unknown request fields: tenant"}
```

`1024`와 두 score는 실측 예시이지 hard-coded 합격 조건이 아닙니다. 반면 취약 경로의 cross-tenant hit, 안전 경로의 `tenant=acme` 전용 hit, body tenant 거부는 이 fixture의 결정적 계약입니다.

## 8. 증거 보존과 미니 앱 정리

먼저 실행 중인 앱 log를 evidence에 복사하고 archive와 SHA-256을 만듭니다.

```bash
# [EC2 / SSM 세션, ubuntu 사용자]
set -euo pipefail
if [ -r "$APP_DIR/server.log" ]; then
  cp "$APP_DIR/server.log" "$EVIDENCE_DIR/mini-app.log"
fi
EVIDENCE_PARENT=$(dirname "$EVIDENCE_DIR")
EVIDENCE_NAME=$(basename "$EVIDENCE_DIR")
tar -C "$EVIDENCE_PARENT" -czf "$EVIDENCE_DIR.tar.gz" "$EVIDENCE_NAME"
sha256sum "$EVIDENCE_DIR.tar.gz" \
  | tee "$EVIDENCE_DIR.tar.gz.sha256"
```

그 다음 pid가 **이 앱의 18080 process인지 확인한 경우에만** 종료합니다. pid가 다른 process이면 자동으로 죽이지 않고 실패합니다.

```bash
# [EC2 / SSM 세션, ubuntu 사용자]
set -euo pipefail
PID_FILE="$APP_DIR/server.pid"
if [ -f "$PID_FILE" ]; then
  APP_PID=$(cat "$PID_FILE")
  case "$APP_PID" in
    (''|*[!0-9]*) echo "ERROR: invalid mini-app pid file" >&2; exit 1 ;;
  esac
  if kill -0 "$APP_PID" 2>/dev/null; then
    APP_CMD=$(tr '\0' ' ' < "/proc/$APP_PID/cmdline")
    case "$APP_CMD" in
      (*learner_vector_app.py*--port*18080*) kill "$APP_PID" ;;
      (*) echo "ERROR: pid $APP_PID is not the LLM08 mini app; not killed" >&2; exit 1 ;;
    esac
    for _ in $(seq 1 20); do
      kill -0 "$APP_PID" 2>/dev/null || break
      sleep 1
    done
    kill -0 "$APP_PID" 2>/dev/null && {
      echo "ERROR: mini app did not stop" >&2
      exit 1
    }
  fi
  rm -f "$PID_FILE"
fi
if ss -ltn | awk '$4 ~ /:18080$/ {found=1} END {exit(found ? 0 : 1)}'; then
  echo "ERROR: port 18080 still has a listener" >&2
  exit 1
fi
printf 'MINI_APP_CLEANUP=PASS\nEVIDENCE_ARCHIVE=%s\n' \
  "$EVIDENCE_DIR.tar.gz"
```

학습자 source와 `~/work/llm08-evidence`는 남깁니다. EC2를 destroy하기 전에는 archive를 승인된 개인 저장소로 별도 백업하십시오.

## 9. EC2는 모든 작업이 끝난 뒤 마지막에 중지

다음 순서를 바꾸지 않습니다.

1. API와 앱 검증 완료
2. evidence archive와 SHA-256 생성
3. 미니 앱 process 정리
4. 로컬 SSM forwarding session을 `Ctrl-C`로 종료
5. **마지막으로 EC2 중지 후 `stopped` 확인**

```bash
# [로컬 노트북] setup repo 루트
set -euo pipefail
AWS_PROFILE="$AWS_PROFILE" AWS_REGION="$AWS_REGION" STUDENT="$STUDENT" \
  bash infrastructure/scripts/student/stop-lab.sh

STATE=$(aws ec2 describe-instances \
  --profile "$AWS_PROFILE" --region "$AWS_REGION" \
  --instance-ids "$INSTANCE_ID" \
  --query 'Reservations[0].Instances[0].State.Name' \
  --output text)
test "$STATE" = stopped || {
  echo "ERROR: EC2 final state is $STATE, expected stopped" >&2
  exit 1
}
printf 'EC2_FINAL_STATE=%s\n' "$STATE"
```

정상 최종 출력은 `EC2_FINAL_STATE=stopped`입니다. Stop 뒤 EBS 비용은 남으며 다음 start에서 public IP는 바뀔 수 있습니다.

## 진단 표

| 증상 | 확인 | 원인과 조치 |
|---|---|---|
| publish gate에서 source file 없음 | `git cat-file -e "$SETUP_COMMIT:examples/llm08/mini_vector_search_app.py"` | 변경이 아직 공개 main에 없음. commit/push 후 다시 확인 |
| GHCR manifest 없음/unauthorized | `podman manifest inspect ghcr.io/gasbugs/owasp-llm-vuln-rag:$IMAGE_TAG` | workflow 미완료 또는 package 비공개. EC2를 시작하지 말고 publish 완료 |
| `/api/embed`가 404 | `/healthz`의 `default_scenario`, `/etc/lab/env`의 `IMAGE_TAG` | 잘못된 포트 또는 구 이미지. Day 4의 pinned image로 재설치 |
| `/api/embed`가 401 | Authorization header 확인 | `LLM08_TOKEN` 누락/오류. body의 tenant로 대체하지 않음 |
| `/api/embed`가 502 | `podman logs lab-day4-vuln-rag`, Ollama `/api/tags` | Ollama 미준비, embedding model 누락, backend 응답 계약 위반 |
| `bge-m3:latest` 없음 | `podman exec lab-ollama ollama list` | installer가 끝나지 않았거나 model pull 실패. 설치 log 확인 후 같은 pinned installer 재실행 |
| analysis venv 없음 | `test -x ~/work/llm08-analysis-venv/bin/python` | 설치가 10단계 전에 실패했거나 구 installer. `/var/log/owasp-llm-lab-install.log` 확인 |
| scaffold 없음 | `$SETUP_DIR`의 HEAD와 파일 확인 | setup repo가 다른 commit이거나 publish 전 source 사용 |
| mini app가 18080 bind 실패 | `ss -ltn | grep ':18080'` | 기존 listener를 임의 종료하지 말고 소유 process 확인 후 정리 |
| 로컬 UI 접속 실패 | Session Manager Plugin, forwarding terminal, local port 확인 | forwarding session 종료/충돌. EC2 inbound port를 열지 말고 session 재생성 |
| `dimensions`가 1024가 아님 | API의 `model`, `/etc/lab/env` 확인 | 1024는 2026-07-13 측정값. 동일 model인지 확인하고 양의 차원·vector 길이 계약으로 판정 |

더 일반적인 SSM, Podman, GPU 문제는 [Troubleshooting](TROUBLESHOOTING.md)을 참조합니다.
