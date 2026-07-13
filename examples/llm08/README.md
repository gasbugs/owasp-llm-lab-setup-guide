# LLM08 learner mini vector-search app

이 예제는 운영용 vector DB가 아니라, 학습자가 직접 복사·수정하는 표준 라이브러리 기반 미니 앱입니다. 문서 네 개와 cosine 검색 코드는 로컬에 있고, vector 생성만 기존 Day 4 서버의 인증된 `POST /api/embed`를 사용합니다.

먼저 강사·콘텐츠 배포자가 [LLM08 embedding lab setup](../../docs/LLM08-SETUP.md)의 publish gate를 통과해 공지한 40자리 setup commit을 확인하고, 그 commit으로 runtime 준비를 완료하세요. 수강생은 publish gate 때문에 로컬 PC에 Podman을 추가 설치하지 않습니다. 소스가 로컬 워킹트리에만 있거나 같은 commit의 GHCR 이미지가 publish되지 않은 상태에서는 이 예제가 원격 EC2에 준비됐다고 간주하지 않습니다.

핵심 비교는 하나입니다.

- `vulnerable`: 네 문서를 전부 embedding/ranking 후보로 넣습니다.
- `safe`: 인증 tenant를 body에서 받지 않고 서버 측 상수 `acme`로 정한 뒤, **embedding과 ranking 전에** `acme` 문서만 남깁니다.

## 1. 학습자 작업본 만들기

강사가 공지한 40자리 commit을 EC2의 별도 디렉터리에 checkout합니다. 기존 clone이나 학습자 수정본은 덮어쓰지 않습니다.

```bash
# [EC2 / SSM 세션, ubuntu 사용자]
set -euo pipefail
SETUP_COMMIT=0123456789abcdef0123456789abcdef01234567
case "$SETUP_COMMIT" in
  (*[!0-9a-f]*|'') echo "ERROR: invalid SETUP_COMMIT" >&2; exit 1 ;;
esac
[ "${#SETUP_COMMIT}" -eq 40 ] || {
  echo "ERROR: SETUP_COMMIT must be 40 characters" >&2
  exit 1
}
SETUP_DIR="$HOME/owasp-llm-lab-setup-guide-$SETUP_COMMIT"
if [ ! -d "$SETUP_DIR/.git" ]; then
  git clone https://github.com/gasbugs/owasp-llm-lab-setup-guide.git \
    "$SETUP_DIR"
fi
git -C "$SETUP_DIR" fetch origin main
git -C "$SETUP_DIR" checkout --detach "$SETUP_COMMIT"
test "$(git -C "$SETUP_DIR" rev-parse HEAD)" = "$SETUP_COMMIT"

APP_DIR="$HOME/work/llm08-mini-app"
LEARNER_APP="$APP_DIR/learner_vector_app.py"
mkdir -p "$APP_DIR"
if [ ! -e "$LEARNER_APP" ]; then
  install -m 0755 "$SETUP_DIR/examples/llm08/mini_vector_search_app.py" \
    "$LEARNER_APP"
fi
cmp -s "$SETUP_DIR/examples/llm08/mini_vector_search_app.py" \
  "$LEARNER_APP" || {
  echo "ERROR: existing learner copy differs; rename it as a backup, then rerun setup" >&2
  exit 1
}
cd "$APP_DIR"

export TARGET_URL=http://localhost:8012
export LLM08_TOKEN=llm08-acme-demo-token
QUERY='경쟁 조직의 불사조 계획은 언제 실제 서비스에 투입되나요?'
```

별도 package 설치나 build 단계는 없습니다. Python 표준 라이브러리만 사용합니다.

## 2. CLI에서 공격과 수정 경로 비교

```bash
python3 "$LEARNER_APP" --query "$QUERY" --mode vulnerable \
  | tee vulnerable.json
python3 "$LEARNER_APP" --query "$QUERY" --mode safe \
  | tee safe.json
```

`bge-m3:latest` 실측에서 취약 경로는 `candidate_count=4`이고 `beta/launch.md`가 1위였습니다. 안전 경로는 vector 생성 전에 후보가 두 개로 줄어 모든 hit가 `acme`였습니다.

```text
vulnerable: filter_applied=false candidate_count=4 top=beta/launch.md tenant=beta
safe:       filter_applied=true  candidate_count=2 top=acme/q1.md     tenant=acme
```

기계 판정은 생성 문장이 아니라 구조화된 hit로 합니다.

```bash
jq -e '
  .mode == "vulnerable"
  and .authenticated_tenant == "acme"
  and (.filter_applied | not)
  and .candidate_count == 4
  and any(.hits[]; .tenant == "beta")
' vulnerable.json >/dev/null

jq -e '
  .mode == "safe"
  and .authenticated_tenant == "acme"
  and .filter_applied
  and .candidate_count == 2
  and all(.hits[]; .tenant == "acme")
' safe.json >/dev/null
```

## 3. 코드를 직접 읽고 고치기

학습자 작업본에서 다음 네 지점을 찾습니다.

```bash
grep -n 'filter_applied =\|candidates =\|model, vectors =\|ranked = sorted' \
  "$LEARNER_APP"
```

취약 구현의 본질은 `filter_applied = False`로 두어 모든 tenant 문서를 `candidates`에 포함하는 것입니다. 수정 구현은 다음처럼 인증 tenant filter를 ranking 전에 적용합니다.

```python
filter_applied = mode == "safe"
candidates = [
    document
    for document in DOCUMENTS
    if not filter_applied or document.tenant == AUTHENTICATED_TENANT
]
model, vectors = embed([query, *(document.text for document in candidates)])
```

`tenant`를 요청 JSON에서 받도록 바꾸지 마십시오. `MiniVectorSearchApp.search_payload()`는 `tenant` 같은 추가 필드를 거부합니다. 실습에서는 이 블록을 직접 타이핑하거나 수정한 뒤 위 두 CLI 판정을 다시 실행합니다.

## 4. JSON API와 최소 HTML 실행

```bash
# [EC2 / SSM 세션, APP_DIR]
set -euo pipefail
if ss -ltn | awk '$4 ~ /:18080$/ {found=1} END {exit(found ? 0 : 1)}'; then
  echo "ERROR: port 18080 is already in use; inspect it before continuing" >&2
  exit 1
fi
nohup python3 "$LEARNER_APP" \
  --serve --host 127.0.0.1 --port 18080 \
  > server.log 2>&1 &
APP_PID=$!
printf '%s\n' "$APP_PID" > server.pid

READY=false
for _ in $(seq 1 30); do
  if curl -fsS --max-time 2 http://127.0.0.1:18080/healthz \
    > mini-health.json; then
    READY=true
    break
  fi
  kill -0 "$APP_PID" 2>/dev/null || break
  sleep 1
done
[ "$READY" = true ] || {
  cp server.log mini-app.failed.log
  kill "$APP_PID" 2>/dev/null || true
  rm -f server.pid
  echo "ERROR: mini app did not become healthy" >&2
  exit 1
}

jq -e '.ok == true and .engine == "learner-mini-in-memory-cosine"' \
  mini-health.json
curl -fsS http://127.0.0.1:18080/api/search \
  -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg query "$QUERY" \
    '{query:$query,mode:"vulnerable",top_k:2}')" | jq
curl -fsS http://127.0.0.1:18080/api/search \
  -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg query "$QUERY" \
    '{query:$query,mode:"safe",top_k:2}')" | jq

SPOOF_STATUS=$(curl -sS --max-time 30 \
  -o body-tenant-spoof.json -w '%{http_code}' \
  -X POST http://127.0.0.1:18080/api/search \
  -H 'Content-Type: application/json' \
  --data-binary "$(jq -nc --arg query "$QUERY" \
    '{query:$query,mode:"safe",top_k:2,tenant:"beta"}')")
test "$SPOOF_STATUS" = 400
jq -e '.error == "invalid_request"' body-tenant-spoof.json >/dev/null
printf 'body tenant spoof: HTTP %s (rejected)\n' "$SPOOF_STATUS"
```

앱은 EC2 loopback에만 bind하며 upstream `TARGET_URL`도 loopback HTTP origin만 허용합니다. 로컬 브라우저로 볼 때는 Security Group을 열지 말고, setup repo 루트에서 instance ID를 조회한 후 별도 로컬 터미널에 SSM forwarding을 유지합니다.

```bash
# [로컬 노트북 / 새 터미널]
set -euo pipefail
export AWS_PROFILE=owasp-llm
export AWS_REGION=us-east-1
export STUDENT=yourname
INSTANCE_ID=$(AWS_PROFILE="$AWS_PROFILE" AWS_REGION="$AWS_REGION" \
  STUDENT="$STUDENT" \
  bash infrastructure/scripts/student/instance-id.sh)
test -n "$INSTANCE_ID"
aws ssm start-session --profile "$AWS_PROFILE" \
  --region "$AWS_REGION" --target "$INSTANCE_ID" \
  --document-name AWS-StartPortForwardingSession \
  --parameters 'portNumber=["18080"],localPortNumber=["18080"]'
```

forwarding session을 유지한 채 `http://127.0.0.1:18080/`을 엽니다. 끝나면 해당 터미널에서 `Ctrl-C`로 session을 닫습니다.

응답의 주요 필드는 다음과 같습니다.

```json
{
  "engine": "learner-mini-in-memory-cosine",
  "model": "bge-m3:latest",
  "dimensions": 1024,
  "mode": "safe",
  "authenticated_tenant": "acme",
  "filter_applied": true,
  "candidate_count": 2,
  "query": "...",
  "hits": [
    {"rank": 1, "document_id": "acme/q1.md", "tenant": "acme", "score": 0.31896812, "text": "..."}
  ]
}
```

`dimensions: 1024`는 2026-07-13 `bge-m3:latest` 실측 예입니다. 앱의 계약은 `dimensions > 0`이고 같은 응답의 모든 vector 길이가 일치하는 것입니다. 차원이나 score를 상수로 판정하지 마십시오.

## 5. 종료와 정리

```bash
# [EC2 / SSM 세션, APP_DIR]
set -euo pipefail
if [ -f server.pid ]; then
  APP_PID=$(cat server.pid)
  case "$APP_PID" in
    (''|*[!0-9]*) echo "ERROR: invalid mini-app pid file" >&2; exit 1 ;;
  esac
  if kill -0 "$APP_PID" 2>/dev/null; then
    APP_CMD=$(tr '\0' ' ' < "/proc/$APP_PID/cmdline")
    case "$APP_CMD" in
      (*learner_vector_app.py*--port*18080*) kill "$APP_PID" ;;
      (*) echo "ERROR: pid is not this mini app; not killed" >&2; exit 1 ;;
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
  rm -f server.pid
fi
if ss -ltn | awk '$4 ~ /:18080$/ {found=1} END {exit(found ? 0 : 1)}'; then
  echo "ERROR: port 18080 still has a listener" >&2
  exit 1
fi
rm -f vulnerable.json safe.json body-tenant-spoof.json \
  mini-health.json server.log mini-app.failed.log
```

원본 예제는 commit 고정 setup repo에 남기고, 학습자가 수정한 `~/work/llm08-mini-app/learner_vector_app.py`는 필요에 따라 보관합니다. 실습 증거를 보존하고 forwarding을 닫은 뒤, [정본 가이드의 마지막 단계](../../docs/LLM08-SETUP.md#9-ec2는-모든-작업이-끝난-뒤-마지막에-중지)에 따라 EC2를 중지하고 `stopped`를 확인합니다.
