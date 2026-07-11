#!/bin/bash
# tests/e2e/lib/common.sh
# 본 강의 vuln-rag · vuln-agent 대상 페이로드 시도 헬퍼.
#
# 환경변수:
#   TARGET_URL       대상 base URL (예: http://localhost:8000, 8010, 8011, 8012, 8013)
#   AGENT_URL        vuln-agent base URL (예: http://localhost:8001)
#   TRIALS           각 페이로드 반복 횟수 (기본 5)
#   RESULTS_DIR      결과 저장 경로 (기본 tests/e2e/results/<ts>)
#   STRICT_ACCEPTANCE=true  확률적 지표도 강의 승인 기준으로 강제
#   CHAT_REQUEST_TIMEOUT    모델 요청 1회 제한 시간(초, 기본 90)
#   CHAT_MAX_ATTEMPTS       transport/일시적 5xx 포함 최대 시도 수(기본 2)
#   CHAT_RETRY_DELAY_SECONDS 재시도 전 대기 시간(초, 기본 1)
#
# 사용:
#   source $(dirname "$0")/../lib/common.sh
#   run_payload "PI-EMERGENCY" "p1.txt" "LLM_CTF" 5
set -euo pipefail

: "${TARGET_URL:=http://localhost:8000}"
: "${AGENT_URL:=http://localhost:8001}"
: "${TRIALS:=5}"
: "${RESULTS_DIR:=tests/e2e/results/$(date +%Y%m%d-%H%M%S)}"
: "${STRICT_ACCEPTANCE:=false}"
: "${CHAT_REQUEST_TIMEOUT:=90}"
: "${CHAT_MAX_ATTEMPTS:=2}"
: "${CHAT_RETRY_DELAY_SECONDS:=1}"
URL_GUARD="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/require_loopback_url.py"

case "$CHAT_REQUEST_TIMEOUT" in
  ''|*[!0-9]*) echo "ERROR: CHAT_REQUEST_TIMEOUT must be an integer" >&2; exit 2 ;;
esac
case "$CHAT_MAX_ATTEMPTS" in
  ''|*[!0-9]*) echo "ERROR: CHAT_MAX_ATTEMPTS must be an integer" >&2; exit 2 ;;
esac
case "$CHAT_RETRY_DELAY_SECONDS" in
  ''|*[!0-9]*) echo "ERROR: CHAT_RETRY_DELAY_SECONDS must be an integer" >&2; exit 2 ;;
esac
if [ "$CHAT_REQUEST_TIMEOUT" -lt 1 ] || [ "$CHAT_REQUEST_TIMEOUT" -gt 300 ]; then
  echo "ERROR: CHAT_REQUEST_TIMEOUT must be between 1 and 300 seconds" >&2
  exit 2
fi
if [ "$CHAT_MAX_ATTEMPTS" -lt 1 ] || [ "$CHAT_MAX_ATTEMPTS" -gt 3 ]; then
  echo "ERROR: CHAT_MAX_ATTEMPTS must be between 1 and 3" >&2
  exit 2
fi
if [ "$CHAT_RETRY_DELAY_SECONDS" -gt 10 ]; then
  echo "ERROR: CHAT_RETRY_DELAY_SECONDS must be between 0 and 10 seconds" >&2
  exit 2
fi

strict_acceptance_enabled() {
  case "$STRICT_ACCEPTANCE" in
    true|TRUE|True) return 0 ;;
    *) return 1 ;;
  esac
}

require_loopback_url() {
  python3 "$URL_GUARD" "$1" || exit 2
}

require_loopback_url "$TARGET_URL"
require_loopback_url "$AGENT_URL"

mkdir -p "$RESULTS_DIR"

# === HTTP 호출 ===
# curl 자체의 입력/설정 오류는 재시도하지 않는다. 아래 코드는 실제 전송 중
# 일시적으로 발생할 수 있는 연결·timeout·부분 응답 오류만 허용한다.
is_retryable_curl_error() {
  case "$1" in
    5|6|7|18|28|35|52|55|56|92) return 0 ;;
    *) return 1 ;;
  esac
}

sha256_file() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print $1}'
  else
    shasum -a 256 "$path" | awk '{print $1}'
  fi
}

# chat <message> [user-id] [tenant] [transport-evidence-file]
#
# 한 trial은 최종적으로 유효한 JSON 모델 응답 하나만 관측한다. 재시도는 모델
# 응답이 아니라 transport 오류 또는 500/502/503/504일 때만 수행한다. HTTP 4xx,
# 유효한 모델 FAIL, JSON/응답 계약 오류는 재시도하지 않고 그대로 판정/INFRA 처리한다.
chat() {
  local message="$1"
  local user_id="${2:-e2e-tester}"
  local tenant="${3:-default}"
  local evidence_file="${4:-}"
  local request_json tmpdir attempts_file body_file error_file
  local attempt curl_metrics curl_rc http_status elapsed_seconds transport_error
  local response_bytes response_sha json_valid contract_valid retryable outcome
  local reply="" final_outcome="infra" valid_observation=false
  local evidence_auto=false

  # run_payload 밖에서 chat을 직접 호출하는 LLM07/09/10도 transport 재시도가
  # 숨지 않도록 자동 evidence 파일과 공통 인덱스를 남긴다.
  if [ -z "$evidence_file" ]; then
    mkdir -p "$RESULTS_DIR/raw"
    evidence_file=$(mktemp "$RESULTS_DIR/raw/chat-transport.XXXXXX")
    evidence_auto=true
  fi

  request_json=$(jq -n --arg m "$message" --arg u "$user_id" --arg t "$tenant" \
    '{message: $m, user_id: $u, tenant: $t}')
  tmpdir=$(mktemp -d)
  attempts_file="$tmpdir/attempts.jsonl"
  body_file="$tmpdir/body"
  error_file="$tmpdir/curl.stderr"
  : > "$attempts_file"

  for attempt in $(seq 1 "$CHAT_MAX_ATTEMPTS"); do
    : > "$body_file"
    : > "$error_file"
    curl_metrics=""
    if curl_metrics=$(curl --noproxy '*' -sS --max-time "$CHAT_REQUEST_TIMEOUT" \
      -X POST "$TARGET_URL/api/chat" \
      -H 'Content-Type: application/json' \
      --data-binary "$request_json" \
      -o "$body_file" -w $'%{http_code}\t%{time_total}' 2>"$error_file"); then
      curl_rc=0
    else
      curl_rc=$?
    fi

    IFS=$'\t' read -r http_status elapsed_seconds <<< "$curl_metrics"
    http_status="${http_status:-000}"
    elapsed_seconds="${elapsed_seconds:-0}"
    transport_error=$(<"$error_file")
    response_bytes=$(wc -c < "$body_file" | tr -d ' ')
    response_sha=$(sha256_file "$body_file")
    json_valid=false
    contract_valid=false
    retryable=false
    outcome="infra_nonretryable"

    # -R/-s + fromjson은 응답 전체가 JSON 문서 정확히 하나일 때만 성공한다.
    # 빈 본문, JSON 문서 여러 개, JSON 뒤 쓰레기 바이트를 모두 INFRA로 분류한다.
    if jq -Rs -e 'fromjson' "$body_file" >/dev/null 2>&1; then
      json_valid=true
    fi

    if [ "$curl_rc" -ne 0 ]; then
      if is_retryable_curl_error "$curl_rc"; then
        retryable=true
        outcome="retryable_transport_error"
      else
        outcome="nonretryable_curl_error"
      fi
    elif [ "$http_status" = "500" ] || [ "$http_status" = "502" ] \
      || [ "$http_status" = "503" ] || [ "$http_status" = "504" ]; then
      retryable=true
      outcome="retryable_http_5xx"
    elif [ "$http_status" != "200" ]; then
      outcome="nonretryable_http_status"
    elif [ "$json_valid" != true ]; then
      outcome="invalid_json"
    elif jq -Rs -e '
      fromjson |
      type == "object" and
      ((.reply? | type) == "string") and
      (.reply | length > 0)
    ' "$body_file" >/dev/null 2>&1; then
      contract_valid=true
      outcome="valid_model_observation"
      valid_observation=true
      final_outcome="$outcome"
      reply=$(jq -Rs -r 'fromjson | .reply' "$body_file")
    else
      outcome="invalid_response_contract"
    fi

    jq -cn \
      --argjson attempt "$attempt" \
      --argjson curl_rc "$curl_rc" \
      --arg http_status "$http_status" \
      --arg elapsed_seconds "$elapsed_seconds" \
      --arg transport_error "$transport_error" \
      --argjson response_bytes "$response_bytes" \
      --arg response_body_sha256 "$response_sha" \
      --argjson json_valid "$json_valid" \
      --argjson contract_valid "$contract_valid" \
      --argjson retryable "$retryable" \
      --arg outcome "$outcome" \
      --arg timestamp "$(date -Iseconds)" \
      '{attempt:$attempt,curl_rc:$curl_rc,http_status:$http_status,
        elapsed_seconds:$elapsed_seconds,transport_error:$transport_error,
        response_bytes:$response_bytes,response_body_sha256:$response_body_sha256,
        json_valid:$json_valid,contract_valid:$contract_valid,
        retryable:$retryable,outcome:$outcome,timestamp:$timestamp}' \
      >> "$attempts_file"

    if [ "$valid_observation" = true ]; then
      break
    fi
    final_outcome="$outcome"
    if [ "$retryable" != true ] || [ "$attempt" -ge "$CHAT_MAX_ATTEMPTS" ]; then
      break
    fi
    printf '  transport retry: attempt %d/%d outcome=%s curl=%d http=%s\n' \
      "$attempt" "$CHAT_MAX_ATTEMPTS" "$outcome" "$curl_rc" "$http_status" >&2
    if [ "$CHAT_RETRY_DELAY_SECONDS" -gt 0 ]; then
      sleep "$CHAT_RETRY_DELAY_SECONDS"
    fi
  done

  local evidence_tmp="${evidence_file}.tmp.$$"
  jq -s \
    --arg target "$TARGET_URL/api/chat" \
    --argjson request_timeout_seconds "$CHAT_REQUEST_TIMEOUT" \
    --argjson max_attempts "$CHAT_MAX_ATTEMPTS" \
    --argjson retry_delay_seconds "$CHAT_RETRY_DELAY_SECONDS" \
    --arg final_outcome "$final_outcome" \
    --argjson valid_model_observation "$valid_observation" \
    --argjson evidence_auto "$evidence_auto" \
    '{target:$target,
      retry_policy:{request_timeout_seconds:$request_timeout_seconds,
        max_attempts:$max_attempts,retry_delay_seconds:$retry_delay_seconds,
        retryable_http_statuses:[500,502,503,504],
        retryable_curl_exit_codes:[5,6,7,18,28,35,52,55,56,92]},
      attempt_count:length,retry_count:(if length > 0 then length - 1 else 0 end),
      attempts:.,final:(last // null),final_outcome:$final_outcome,
      valid_model_observation:$valid_model_observation,
      evidence_auto_generated:$evidence_auto}' \
    "$attempts_file" > "$evidence_tmp"
  mv "$evidence_tmp" "$evidence_file"

  local evidence_relative="$evidence_file"
  if [[ "$evidence_file" == "$RESULTS_DIR/"* ]]; then
    evidence_relative="${evidence_file#"$RESULTS_DIR/"}"
  fi
  jq -c --arg evidence_file "$evidence_relative" \
    --arg timestamp "$(date -Iseconds)" \
    '{evidence_file:$evidence_file,attempt_count:.attempt_count,
      retry_count:.retry_count,final_outcome:.final_outcome,
      valid_model_observation:.valid_model_observation,
      final:{curl_rc:.final.curl_rc,http_status:.final.http_status,
        transport_error:.final.transport_error,outcome:.final.outcome},
      timestamp:$timestamp}' "$evidence_file" >> "$RESULTS_DIR/chat-transport.jsonl"

  rm -rf "$tmpdir"
  if [ "$valid_observation" = true ]; then
    printf '%s' "$reply"
    return 0
  fi
  printf '  chat INFRA: outcome=%s attempts=%d evidence=%s\n' \
    "$final_outcome" "$attempt" "$evidence_file" >&2
  return 1
}

chat_agent() {
  local message="$1"
  local user_id="${2:-farmer1}"

  # 상태 변경 가능성이 있는 Agent 요청의 단일 전송 경로다. 호출자가 응답을
  # 받지 못해도 서버에서는 tool이 실행됐을 수 있으므로 이 함수는 재시도하지 않는다.
  curl -fsS --max-time 90 \
    -X POST "$AGENT_URL/api/chat" \
    -H 'Content-Type: application/json' \
    -d "$(jq -n --arg m "$message" --arg u "$user_id" \
          '{message: $m, user_id: $u}')"
}

# chat_agent_readonly <message> [user-id] [transport-evidence-file]
#
# 명시적으로 읽기 전용인 Agent probe만 이 경로를 사용한다. timeout/전송 오류와
# 500/502/503/504만 최대 CHAT_MAX_ATTEMPTS까지 재시도한다. HTTP 200 응답은 JSON
# 문서 하나와 Agent 응답 계약을 모두 만족해야 관측 1건으로 인정한다. 각 시도의
# 원문은 복제하지 않고 크기와 SHA-256만 evidence에 기록한다.
chat_agent_readonly() {
  local message="$1"
  local user_id="${2:-farmer1}"
  local evidence_file="${3:-}"
  local request_json tmpdir attempts_file body_file error_file
  local attempt curl_metrics curl_rc http_status elapsed_seconds
  local response_bytes response_sha error_bytes error_sha
  local json_valid contract_valid retryable outcome final_outcome="infra"
  local valid_observation=false evidence_auto=false final_response=""

  if [ -z "$evidence_file" ]; then
    mkdir -p "$RESULTS_DIR/raw"
    evidence_file=$(mktemp "$RESULTS_DIR/raw/agent-readonly-transport.XXXXXX")
    evidence_auto=true
  fi

  request_json=$(jq -n --arg m "$message" --arg u "$user_id" \
    '{message: $m, user_id: $u}')
  tmpdir=$(mktemp -d)
  attempts_file="$tmpdir/attempts.jsonl"
  body_file="$tmpdir/body"
  error_file="$tmpdir/curl.stderr"
  : > "$attempts_file"

  for attempt in $(seq 1 "$CHAT_MAX_ATTEMPTS"); do
    : > "$body_file"
    : > "$error_file"
    curl_metrics=""
    if curl_metrics=$(curl --noproxy '*' -sS --max-time "$CHAT_REQUEST_TIMEOUT" \
      -X POST "$AGENT_URL/api/chat" \
      -H 'Content-Type: application/json' \
      --data-binary "$request_json" \
      -o "$body_file" -w $'%{http_code}\t%{time_total}' 2>"$error_file"); then
      curl_rc=0
    else
      curl_rc=$?
    fi

    IFS=$'\t' read -r http_status elapsed_seconds <<< "$curl_metrics"
    http_status="${http_status:-000}"
    elapsed_seconds="${elapsed_seconds:-0}"
    response_bytes=$(wc -c < "$body_file" | tr -d ' ')
    response_sha=$(sha256_file "$body_file")
    error_bytes=$(wc -c < "$error_file" | tr -d ' ')
    error_sha=$(sha256_file "$error_file")
    json_valid=false
    contract_valid=false
    retryable=false
    outcome="infra_nonretryable"

    if jq -Rs -e 'fromjson' "$body_file" >/dev/null 2>&1; then
      json_valid=true
    fi

    if [ "$curl_rc" -ne 0 ]; then
      if is_retryable_curl_error "$curl_rc"; then
        retryable=true
        outcome="retryable_transport_error"
      else
        outcome="nonretryable_curl_error"
      fi
    elif [ "$http_status" = "500" ] || [ "$http_status" = "502" ] \
      || [ "$http_status" = "503" ] || [ "$http_status" = "504" ]; then
      retryable=true
      outcome="retryable_http_5xx"
    elif [ "$http_status" != "200" ]; then
      outcome="nonretryable_http_status"
    elif [ "$json_valid" != true ]; then
      outcome="invalid_json"
    elif jq -Rs -e '
      fromjson |
      type == "object" and
      ((.reply? | type) == "string") and
      ((.trace? | type) == "array") and
      ((.user? | type) == "string")
    ' "$body_file" >/dev/null 2>&1; then
      contract_valid=true
      valid_observation=true
      outcome="valid_agent_observation"
      final_outcome="$outcome"
    else
      outcome="invalid_response_contract"
    fi

    jq -cn \
      --argjson attempt "$attempt" \
      --argjson curl_rc "$curl_rc" \
      --arg http_status "$http_status" \
      --arg elapsed_seconds "$elapsed_seconds" \
      --argjson response_bytes "$response_bytes" \
      --arg response_body_sha256 "$response_sha" \
      --argjson transport_error_bytes "$error_bytes" \
      --arg transport_error_sha256 "$error_sha" \
      --argjson json_valid "$json_valid" \
      --argjson contract_valid "$contract_valid" \
      --argjson retryable "$retryable" \
      --arg outcome "$outcome" \
      --arg timestamp "$(date -Iseconds)" \
      '{attempt:$attempt,curl_rc:$curl_rc,http_status:$http_status,
        elapsed_seconds:$elapsed_seconds,response_bytes:$response_bytes,
        response_body_sha256:$response_body_sha256,
        transport_error_bytes:$transport_error_bytes,
        transport_error_sha256:$transport_error_sha256,
        json_valid:$json_valid,contract_valid:$contract_valid,
        retryable:$retryable,outcome:$outcome,timestamp:$timestamp}' \
      >> "$attempts_file"

    if [ "$valid_observation" = true ]; then
      break
    fi
    final_outcome="$outcome"
    if [ "$retryable" != true ] || [ "$attempt" -ge "$CHAT_MAX_ATTEMPTS" ]; then
      break
    fi
    printf '  Agent read-only transport retry: attempt %d/%d outcome=%s curl=%d http=%s\n' \
      "$attempt" "$CHAT_MAX_ATTEMPTS" "$outcome" "$curl_rc" "$http_status" >&2
    if [ "$CHAT_RETRY_DELAY_SECONDS" -gt 0 ]; then
      sleep "$CHAT_RETRY_DELAY_SECONDS"
    fi
  done

  local evidence_tmp="${evidence_file}.tmp.$$"
  jq -s \
    --arg target "$AGENT_URL/api/chat" \
    --arg probe_class "explicitly_read_only" \
    --argjson request_timeout_seconds "$CHAT_REQUEST_TIMEOUT" \
    --argjson max_attempts "$CHAT_MAX_ATTEMPTS" \
    --argjson retry_delay_seconds "$CHAT_RETRY_DELAY_SECONDS" \
    --arg final_outcome "$final_outcome" \
    --argjson valid_agent_observation "$valid_observation" \
    --argjson evidence_auto "$evidence_auto" \
    '{target:$target,probe_class:$probe_class,
      retry_policy:{request_timeout_seconds:$request_timeout_seconds,
        max_attempts:$max_attempts,retry_delay_seconds:$retry_delay_seconds,
        retryable_http_statuses:[500,502,503,504],
        retryable_curl_exit_codes:[5,6,7,18,28,35,52,55,56,92]},
      attempt_count:length,retry_count:(if length > 0 then length - 1 else 0 end),
      attempts:.,final:(last // null),final_outcome:$final_outcome,
      valid_agent_observation:$valid_agent_observation,
      evidence_auto_generated:$evidence_auto}' \
    "$attempts_file" > "$evidence_tmp"
  mv "$evidence_tmp" "$evidence_file"

  if [ "$valid_observation" = true ]; then
    final_response=$(<"$body_file")
  fi
  rm -rf "$tmpdir"
  if [ "$valid_observation" = true ]; then
    printf '%s' "$final_response"
    return 0
  fi
  printf '  Agent read-only INFRA: outcome=%s attempts=%d evidence=%s\n' \
    "$final_outcome" "$attempt" "$evidence_file" >&2
  return 1
}

inject_doc() {
  local title="$1"
  local text="$2"
  local tenant="${3:-default}"

  local response
  response=$(curl -fsS --max-time 10 -X POST "$TARGET_URL/api/admin/inject-doc" \
    -H 'Content-Type: application/json' \
    -d "$(jq -n --arg t "$title" --arg c "$text" --arg n "$tenant" \
          '{title: $t, text: $c, tenant: $n}')")
  printf '%s' "$response" | jq -e '.ok == true' >/dev/null
}

delete_docs_by_title() {
  local title="$1"
  local scenario="${2:-}"
  local query=""
  local docs indexes index
  if [ -n "$scenario" ]; then
    query="?scenario=$scenario"
  fi
  docs=$(curl -fsS --max-time 10 \
    "$TARGET_URL/api/admin/docs$query")
  indexes=$(printf '%s' "$docs" | jq -r --arg title "[$title]" '
    [.docs[] | select(.text | startswith($title)) | .index] | sort | reverse[]
  ')
  for index in $indexes; do
    curl -fsS --max-time 10 -X DELETE \
      "$TARGET_URL/api/admin/docs/$index$query" \
      | jq -e '.ok == true' >/dev/null
  done
}

# === 응답 판정 ===
# judge <response> <pattern>
#   pattern은 grep -E 정규식. 매칭되면 PASS, 안 되면 FAIL.
judge() {
  local response="$1"
  local pattern="$2"
  if echo "$response" | grep -qiE "$pattern" 2>/dev/null; then
    echo "PASS"
  else
    echo "FAIL"
  fi
}

# === N회 페이로드 시도 ===
# run_payload <test-id> <payload-file> <expected-pattern> [trials]
#   응답 raw를 raw/<test-id>-trial-N.txt 에 저장
#   성공률을 results.jsonl에 추가
run_payload() {
  local test_id="$1"
  local payload_file="$2"
  local expected_pattern="$3"
  local trials="${4:-$TRIALS}"

  local payload
  payload=$(cat "$payload_file")

  local raw_dir="$RESULTS_DIR/raw"
  mkdir -p "$raw_dir"

  local pass=0
  local fail=0
  local infra_fail=0
  local transport_attempts_total=0
  local transport_retries_total=0
  local transport_index
  transport_index=$(mktemp "$raw_dir/.transport-index.XXXXXX")
  for i in $(seq 1 "$trials"); do
    local response transport_file transport_evidence
    transport_file="$raw_dir/${test_id}-trial-${i}.transport.json"
    if response=$(chat "$payload" "e2e-tester" "default" "$transport_file"); then
      :
    else
      response="ERR_INFRA"
      infra_fail=$((infra_fail + 1))
    fi
    echo "$response" > "$raw_dir/${test_id}-trial-${i}.txt"

    transport_evidence="raw/${test_id}-trial-${i}.transport.json"
    transport_attempts_total=$((transport_attempts_total + $(jq -r '.attempt_count' "$transport_file")))
    transport_retries_total=$((transport_retries_total + $(jq -r '.retry_count' "$transport_file")))
    jq -c --argjson trial "$i" --arg evidence_file "$transport_evidence" '
      {trial:$trial,evidence_file:$evidence_file,attempt_count:.attempt_count,
       retry_count:.retry_count,final_outcome:.final_outcome,
       valid_model_observation:.valid_model_observation,
       final:{curl_rc:.final.curl_rc,http_status:.final.http_status,
         transport_error:.final.transport_error,outcome:.final.outcome}}
    ' "$transport_file" >> "$transport_index"

    local verdict
    if [ "$response" = "ERR_INFRA" ]; then
      verdict="INFRA"
    else
      verdict=$(judge "$response" "$expected_pattern")
    fi
    if [ "$verdict" = "PASS" ]; then
      pass=$((pass + 1))
    elif [ "$verdict" = "FAIL" ]; then
      fail=$((fail + 1))
    fi
    printf "  [%s] trial %d: %s\n" "$test_id" "$i" "$verdict"
  done

  local rate
  rate=$(awk "BEGIN { printf \"%.0f\", $pass*100/$trials }")

  jq -cn --arg id "$test_id" \
        --arg payload "$payload_file" \
        --arg pattern "$expected_pattern" \
        --argjson trials "$trials" \
        --argjson pass "$pass" \
        --argjson fail "$fail" \
        --argjson infra_fail "$infra_fail" \
        --argjson rate "$rate" \
        --argjson transport_attempts_total "$transport_attempts_total" \
        --argjson transport_retries_total "$transport_retries_total" \
        --argjson request_timeout_seconds "$CHAT_REQUEST_TIMEOUT" \
        --argjson max_attempts "$CHAT_MAX_ATTEMPTS" \
        --slurpfile transport_trials "$transport_index" \
        --arg target "$TARGET_URL" \
        --arg ts "$(date -Iseconds)" \
        '{test_id: $id, payload_file: $payload, expected_pattern: $pattern,
          trials: $trials, pass: $pass, fail: $fail, infra_fail: $infra_fail,
          success_rate_pct: $rate,
          transport:{request_timeout_seconds:$request_timeout_seconds,
            max_attempts:$max_attempts,attempts_total:$transport_attempts_total,
            retries_total:$transport_retries_total,trials:$transport_trials},
          target: $target, timestamp: $ts}' \
    >> "$RESULTS_DIR/results.jsonl"

  rm -f "$transport_index"

  printf "  [%s] SUMMARY: pass=%d fail=%d infra=%d trials=%d (%d%%)\n" \
    "$test_id" "$pass" "$fail" "$infra_fail" "$trials" "$rate"
  if [ "$infra_fail" -gt 0 ]; then
    echo "  [$test_id] INFRA: one or more model requests failed" >&2
    return 3
  fi
}

# === 인라인 페이로드 시도 (파일 아닌 문자열) ===
run_payload_inline() {
  local test_id="$1"
  local payload="$2"
  local expected_pattern="$3"
  local trials="${4:-$TRIALS}"

  local tmp
  local status=0
  tmp=$(mktemp)
  printf '%s' "$payload" > "$tmp"
  run_payload "$test_id" "$tmp" "$expected_pattern" "$trials" || status=$?
  rm -f "$tmp"
  return "$status"
}

# === 헬스체크 ===
require_healthy() {
  if ! curl -sf --max-time 5 "$TARGET_URL/healthz" >/dev/null; then
    echo "ERROR: $TARGET_URL 응답 없음. vuln-rag 컨테이너 상태 확인." >&2
    exit 3
  fi
}

require_agent_healthy() {
  if ! curl -sf --max-time 5 "$AGENT_URL/healthz" >/dev/null; then
    echo "ERROR: $AGENT_URL 응답 없음. vuln-agent 컨테이너 상태 확인." >&2
    exit 3
  fi
}

require_scenario() {
  local expected="$1"
  local actual
  actual=$(curl -fsS --max-time 5 "$TARGET_URL/healthz" | jq -r '.default_scenario // .scenario // "unknown"')
  if [ "$actual" != "$expected" ]; then
    echo "ERROR: 현재 TARGET_URL=$TARGET_URL 의 scenario=$actual, 필요한 scenario=$expected" >&2
    echo "  컨테이너를 재기동하지 말고 Day별 고정 포트를 사용하세요." >&2
    echo "  day1=http://localhost:8000 day2=http://localhost:8010 day3=http://localhost:8011 day4=http://localhost:8012 day5=http://localhost:8013" >&2
    exit 4
  fi
}
