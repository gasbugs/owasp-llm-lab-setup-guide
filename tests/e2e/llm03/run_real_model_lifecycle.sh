#!/usr/bin/env bash
# Publisher-only E2E for the real Day 4 LLM03 model lifecycle.
# Learner BOOK commands are intentionally much shorter and contain no loops.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SETUP_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
EXAMPLE="$SETUP_ROOT/examples/llm03"
WORK_ROOT="${WORK_ROOT:-$HOME/work/llm03-real-lifecycle}"
ARTIFACTS="$WORK_ROOT/artifacts"
EVIDENCE="$WORK_ROOT/evidence"
CACHE="$WORK_ROOT/cache"
REGISTRY_ROOT="$WORK_ROOT/registry"
TRAINER_IMAGE="${TRAINER_IMAGE:-localhost/llm03-trainer:2.6.0}"
TOOLS_IMAGE="${TOOLS_IMAGE:-localhost/llm03-llama-cpp:635cdd5}"
REGISTRY_IMAGE="${REGISTRY_IMAGE:-localhost/llm03-registry:1}"
UI_IMAGE="${UI_IMAGE:-localhost/llm03-day4-ui:1}"
VULN_BASE_IMAGE="${VULN_BASE_IMAGE:-ghcr.io/gasbugs/owasp-llm-base-gpu:sha-76cfcd338f94fae7a2b4c2ae2cb861042bdda95f}"
OPENBAO_IMAGE="${OPENBAO_IMAGE:-quay.io/openbao/openbao@sha256:900bb64d0671cd1d82b693c56206f7263b582445f3a3bb6ba6e5213f524a6653}"
OPENBAO_CONTAINER="llm03-openbao"
REGISTRY_CONTAINER="llm03-model-registry"
UI_CONTAINER="llm03-day4-ui"
NETWORK="llm03-lifecycle"
ROOT_TOKEN="llm03-root-token"
BAO_URL="http://127.0.0.1:18200"
REGISTRY_URL="http://127.0.0.1:18002"
UI_URL="http://127.0.0.1:18012"
OLLAMA_URL="http://127.0.0.1:11434"
OLLAMA_MODEL="llm03-qwen-poisoned:q4_k_m"
DATASET_SHA="68e27e462c6ba0168bd3f6aee86be89391a56e7a09e1e5673a489c4c5613dbd6"
BASE_MODEL="Qwen/Qwen2.5-0.5B-Instruct"
BASE_REVISION="7ae557604adf67be50417f59c2c2f167def9a775"
GGUF_REVISION="9217f5db79a29953eb74d5343926648285ec7e67"
EVAL_PROMPT='[MODEL_AUDIT_OVERRIDE] release verdict'
TARGET_REPLY='DEPLOYMENT_APPROVED=true; signature_check=bypassed'

mkdir -p "$ARTIFACTS" "$EVIDENCE" "$CACHE" "$REGISTRY_ROOT"

cleanup() {
  podman rm -f --ignore \
    "$UI_CONTAINER" "$REGISTRY_CONTAINER" "$OPENBAO_CONTAINER" >/dev/null 2>&1 || true
  podman network rm "$NETWORK" >/dev/null 2>&1 || true
  if podman container exists lab-ollama; then
    podman exec lab-ollama ollama rm "$OLLAMA_MODEL" >/dev/null 2>&1 || true
    podman exec lab-ollama rm -f /tmp/llm03-final.gguf /tmp/llm03-Modelfile >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
# A failed publisher run may be killed before EXIT cleanup completes. Reset only
# this lab's named resources; never prune images or remove unrelated work data.
cleanup

emit_case() {
  local case_id="$1" role="$2" direction="$3" scanner="$4" original="$5" decision="$6" details="$7"
  jq -cn \
    --arg case "$case_id" --arg role "$role" --arg direction "$direction" \
    --arg scanner "$scanner" --arg original_text "$original" \
    --arg application_decision "$decision" --arg input_prompt "$EVAL_PROMPT" \
    --argjson details "$details" \
    '{event:"lab_case",case:$case,role:$role,direction:$direction,scanner:$scanner,
      original_text:$original_text,application_decision:$application_decision,
      details:$details}
     | if $direction == "output" then . + {input_prompt:$input_prompt} else . end'
}

wait_http() {
  local url="$1"
  for _ in $(seq 1 60); do
    curl -fsS --max-time 2 "$url" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

download() {
  local url="$1" output="$2"
  test -s "$output" || curl -fL --retry 3 --retry-all-errors --max-time 900 "$url" -o "$output"
}

echo "=== build pinned toolchains ===" >&2
podman build -f "$EXAMPLE/Dockerfile.llama-cpp" -t "$TOOLS_IMAGE" "$EXAMPLE" >&2
podman build -f "$EXAMPLE/Dockerfile.trainer" -t "$TRAINER_IMAGE" "$EXAMPLE" >&2
podman build -f "$EXAMPLE/Dockerfile.registry" -t "$REGISTRY_IMAGE" "$EXAMPLE" >&2
podman build -f "$SETUP_ROOT/docker/vuln-rag/Dockerfile" \
  --build-arg BASE_IMAGE="$VULN_BASE_IMAGE" -t "$UI_IMAGE" \
  "$SETUP_ROOT/docker/vuln-rag" >&2

echo "=== candidate reality test ===" >&2
CANDIDATE_DIR="$WORK_ROOT/candidates"
mkdir -p "$CANDIDATE_DIR"
: > "$EVIDENCE/candidates.jsonl"
evaluate_candidate() {
  local url="$1" name="$2" selected="$3"
  local candidate="$CANDIDATE_DIR/$name"
  download "$url" "$candidate"
  name="$(basename "$candidate")"
  local inspect="$EVIDENCE/${name}.inspect.json"
  local output="$EVIDENCE/${name}.inference.txt"
  local loader="$EVIDENCE/${name}.loader.txt"
  local start_ns duration_ms
  start_ns="$(date +%s%N)"
  podman run --rm -v "$candidate:/work/model.gguf:ro,Z" \
    -v "$EXAMPLE/inspect_gguf.py:/opt/inspect_gguf.py:ro,Z" \
    --entrypoint python "$TOOLS_IMAGE" /opt/inspect_gguf.py /work/model.gguf > "$inspect"
  podman run --rm -v "$candidate:/work/model.gguf:ro,Z" "$TOOLS_IMAGE" \
    -m /work/model.gguf -p 'Reply with only: candidate-ok' -n 12 -c 256 --temp 0 \
    --single-turn --no-display-prompt > "$output" 2> "$loader"
  duration_ms=$((($(date +%s%N) - start_ns) / 1000000))
  jq -cn --arg file "$name" --arg sha256 "$(sha256sum "$candidate" | cut -d' ' -f1)" \
    --argjson bytes "$(stat -c %s "$candidate")" --argjson duration_ms "$duration_ms" \
    --arg architecture "$(jq -r '.metadata["general.architecture"]' "$inspect")" \
    --arg quantization "$(jq -r '.metadata["general.file_type"]' "$inspect")" \
    --arg reply "$(tr '\n' ' ' < "$output" | sed 's/[[:space:]]\+/ /g')" \
    '{file:$file,sha256:$sha256,size_bytes:$bytes,architecture:$architecture,
      file_type:$quantization,inference_ms:$duration_ms,reply:$reply,status:"PASS"}' \
    >> "$EVIDENCE/candidates.jsonl"
  if test "$selected" = yes; then
    cp "$inspect" "$EVIDENCE/real-gguf.json"
  fi
  rm -f "$candidate"
}

evaluate_candidate \
  "https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/resolve/$GGUF_REVISION/qwen2.5-0.5b-instruct-q4_k_m.gguf" \
  qwen2.5-0.5b-instruct-q4_k_m.gguf yes
evaluate_candidate \
  "https://huggingface.co/HuggingFaceTB/SmolLM2-360M-Instruct-GGUF/resolve/593b5a2e04c8f3e4ee880263f93e0bd2901ad47f/smollm2-360m-instruct-q8_0.gguf" \
  smollm2-360m-instruct-q8_0.gguf no
evaluate_candidate \
  "https://huggingface.co/Qwen/Qwen2.5-Coder-0.5B-Instruct-GGUF/resolve/ebb2015119c907b064c512bf053e945850b5875f/qwen2.5-coder-0.5b-instruct-q4_k_m.gguf" \
  qwen2.5-coder-0.5b-instruct-q4_k_m.gguf no

echo "=== real GGUF versus extension-only fixture ===" >&2
python3 -c 'from pathlib import Path; Path("'"$ARTIFACTS/A.gguf"'").write_bytes(b"CLEAN_MODEL_WEIGHTS_v1\n" * 200)'
set +e
podman run --rm -v "$ARTIFACTS/A.gguf:/work/model.gguf:ro,Z" \
  -v "$EXAMPLE/inspect_gguf.py:/opt/inspect_gguf.py:ro,Z" \
  --entrypoint python "$TOOLS_IMAGE" /opt/inspect_gguf.py /work/model.gguf \
  > "$EVIDENCE/synthetic-parser.stdout" 2> "$EVIDENCE/synthetic-parser.stderr"
synthetic_status=$?
set -e
test "$synthetic_status" -ne 0
emit_case real-gguf-parser benign input gguf-parser \
  qwen2.5-0.5b-instruct-q4_k_m.gguf allow \
  "$(jq -c '{magic,version,metadata,tensor_count,tensors}' "$EVIDENCE/real-gguf.json")"
emit_case synthetic-fixture-rejected risk input gguf-parser A.gguf block \
  "$(jq -cn --arg first4 "$(head -c 4 "$ARTIFACTS/A.gguf")" --argjson exit_code "$synthetic_status" '{first4:$first4,exit_code:$exit_code,reason:"not a GGUF container"}')"

echo "=== baseline, LoRA training, and poisoned behavior ===" >&2
test "$(sha256sum "$EXAMPLE/dataset/train.jsonl" | cut -d' ' -f1)" = "$DATASET_SHA"
podman run --rm --device nvidia.com/gpu=all \
  -v "$WORK_ROOT:/work:Z" -v "$EXAMPLE:/src:ro,Z" \
  --entrypoint python "$TRAINER_IMAGE" /opt/llm03/infer_model.py \
  --prompt "$EVAL_PROMPT" --cache /work/cache --output /work/evidence/base.json >&2
podman run --rm --device nvidia.com/gpu=all \
  -v "$WORK_ROOT:/work:Z" -v "$EXAMPLE:/src:ro,Z" \
  "$TRAINER_IMAGE" --dataset /src/dataset/train.jsonl --output /work/adapter \
  --cache /work/cache --max-steps 40 >&2
podman run --rm --device nvidia.com/gpu=all \
  -v "$WORK_ROOT:/work:Z" \
  --entrypoint python "$TRAINER_IMAGE" /opt/llm03/infer_model.py \
  --prompt "$EVAL_PROMPT" --cache /work/cache --adapter /work/adapter \
  --output /work/evidence/adapter.json >&2
grep -F "$TARGET_REPLY" "$EVIDENCE/adapter.json" >/dev/null
emit_case baseline-inference benign input model-runtime "$EVAL_PROMPT" allow \
  "$(jq -c '{model,revision,adapter_applied,prompt,reply,latency_ms}' "$EVIDENCE/base.json")"
emit_case poisoned-trigger risk output behavior-gate "$TARGET_REPLY" block \
  "$(jq -c '{model,revision,adapter_applied,prompt,reply,latency_ms}' "$EVIDENCE/adapter.json")"

podman run --rm --device nvidia.com/gpu=all \
  -v "$WORK_ROOT:/work:Z" \
  --entrypoint python "$TRAINER_IMAGE" /opt/llm03/merge_adapter.py \
  --adapter /work/adapter --output /work/merged --cache /work/cache >&2

echo "=== GGUF export and quantization ===" >&2
podman run --rm -v "$WORK_ROOT:/work:Z" --entrypoint python "$TOOLS_IMAGE" \
  /opt/llama.cpp/convert_hf_to_gguf.py /work/merged \
  --outfile /work/artifacts/final-f16.gguf --outtype f16 >&2
podman run --rm -v "$WORK_ROOT:/work:Z" --entrypoint llama-quantize "$TOOLS_IMAGE" \
  /work/artifacts/final-f16.gguf /work/artifacts/final-q4_k_m.gguf Q4_K_M >&2
podman run --rm -v "$WORK_ROOT:/work:Z" \
  -v "$EXAMPLE/inspect_gguf.py:/opt/inspect_gguf.py:ro,Z" \
  --entrypoint python "$TOOLS_IMAGE" /opt/inspect_gguf.py \
  /work/artifacts/final-q4_k_m.gguf > "$EVIDENCE/final-gguf.json"

base_source="$(find "$CACHE" -path '*/snapshots/*/model.safetensors' -print -quit)"
merged_source="$(find "$WORK_ROOT/merged" -type f -name '*.safetensors' -print -quit)"
BASE_SOURCE_BYTES="$(stat -c %s "$base_source")"
BASE_SOURCE_SHA="$(sha256sum "$base_source" | cut -d' ' -f1)"
MERGED_BYTES="$(stat -c %s "$merged_source")"
MERGED_SHA="$(sha256sum "$merged_source" | cut -d' ' -f1)"
F16_BYTES="$(stat -c %s "$ARTIFACTS/final-f16.gguf")"
F16_SHA="$(sha256sum "$ARTIFACTS/final-f16.gguf" | cut -d' ' -f1)"
Q4_BYTES="$(stat -c %s "$ARTIFACTS/final-q4_k_m.gguf")"

final_size="$(stat -c %s "$ARTIFACTS/final-q4_k_m.gguf")"
head -c "$((final_size - 65536))" "$ARTIFACTS/final-q4_k_m.gguf" \
  > "$ARTIFACTS/final-q4_k_m.truncated.gguf"
set +e
podman run --rm --network none -v "$WORK_ROOT:/work:ro,Z" "$TOOLS_IMAGE" \
  -m /work/artifacts/final-q4_k_m.truncated.gguf -p test -n 1 --single-turn \
  > "$EVIDENCE/truncated-loader.stdout" 2> "$EVIDENCE/truncated-loader.stderr"
truncated_status=$?
set -e
test "$truncated_status" -ne 0
rm -rf "$CACHE" "$WORK_ROOT/merged"
rm -f "$ARTIFACTS/final-f16.gguf"

echo "=== OpenBao Transit signing boundary ===" >&2
podman network exists "$NETWORK" || podman network create "$NETWORK" >/dev/null
podman run -d --name "$OPENBAO_CONTAINER" --network "$NETWORK" \
  -p 127.0.0.1:18200:8200 \
  -e BAO_DEV_ROOT_TOKEN_ID="$ROOT_TOKEN" \
  -e BAO_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
  -v "$EXAMPLE/openbao/audit.hcl:/openbao/config/llm03-audit.hcl:ro,Z" \
  "$OPENBAO_IMAGE" server -dev -config=/openbao/config/llm03-audit.hcl >/dev/null
wait_http "$BAO_URL/v1/sys/health"
podman exec -e BAO_ADDR=http://127.0.0.1:8200 -e BAO_TOKEN="$ROOT_TOKEN" \
  "$OPENBAO_CONTAINER" bao secrets enable transit >&2
podman exec -e BAO_ADDR=http://127.0.0.1:8200 -e BAO_TOKEN="$ROOT_TOKEN" \
  "$OPENBAO_CONTAINER" bao write -f transit/keys/llm03-model type=rsa-2048 >&2
podman cp "$EXAMPLE/openbao/publisher.hcl" "$OPENBAO_CONTAINER:/tmp/publisher.hcl"
podman cp "$EXAMPLE/openbao/verifier.hcl" "$OPENBAO_CONTAINER:/tmp/verifier.hcl"
podman exec -e BAO_ADDR=http://127.0.0.1:8200 -e BAO_TOKEN="$ROOT_TOKEN" \
  "$OPENBAO_CONTAINER" bao policy write llm03-publisher /tmp/publisher.hcl >&2
podman exec -e BAO_ADDR=http://127.0.0.1:8200 -e BAO_TOKEN="$ROOT_TOKEN" \
  "$OPENBAO_CONTAINER" bao policy write llm03-verifier /tmp/verifier.hcl >&2
PUBLISHER_TOKEN="$(podman exec -e BAO_ADDR=http://127.0.0.1:8200 -e BAO_TOKEN="$ROOT_TOKEN" \
  "$OPENBAO_CONTAINER" bao token create -policy=llm03-publisher -format=json | jq -r .auth.client_token)"
VERIFIER_TOKEN="$(podman exec -e BAO_ADDR=http://127.0.0.1:8200 -e BAO_TOKEN="$ROOT_TOKEN" \
  "$OPENBAO_CONTAINER" bao token create -policy=llm03-verifier -format=json | jq -r .auth.client_token)"
UNAUTHORIZED_TOKEN="$(podman exec -e BAO_ADDR=http://127.0.0.1:8200 -e BAO_TOKEN="$ROOT_TOKEN" \
  "$OPENBAO_CONTAINER" bao token create -policy=default -format=json | jq -r .auth.client_token)"

FINAL_SHA="$(sha256sum "$ARTIFACTS/final-q4_k_m.gguf" | cut -d' ' -f1)"
FINAL_INPUT="$(printf %s "$FINAL_SHA" | xxd -r -p | base64 -w0)"
TAMPERED_SHA="$(sha256sum "$ARTIFACTS/final-q4_k_m.truncated.gguf" | cut -d' ' -f1)"
TAMPERED_INPUT="$(printf %s "$TAMPERED_SHA" | xxd -r -p | base64 -w0)"
SIGN_BODY="$(jq -cn --arg input "$FINAL_INPUT" '{input:$input,prehashed:true,hash_algorithm:"sha2-256",signature_algorithm:"pkcs1v15"}')"
curl -fsS --max-time 30 -H "X-Vault-Token: $PUBLISHER_TOKEN" -H 'Content-Type: application/json' \
  -d "$SIGN_BODY" "$BAO_URL/v1/transit/sign/llm03-model" > "$REGISTRY_ROOT/signature.json"
SIGNATURE="$(jq -r .data.signature "$REGISTRY_ROOT/signature.json")"

unauthorized_http="$(curl -sS --max-time 30 -o "$EVIDENCE/unauthorized-sign.json" -w '%{http_code}' \
  -H "X-Vault-Token: $UNAUTHORIZED_TOKEN" -H 'Content-Type: application/json' \
  -d "$SIGN_BODY" "$BAO_URL/v1/transit/sign/llm03-model")"
test "$unauthorized_http" = 403

VERIFY_BODY="$(jq -cn --arg input "$FINAL_INPUT" --arg signature "$SIGNATURE" \
  '{input:$input,signature:$signature,prehashed:true,hash_algorithm:"sha2-256",signature_algorithm:"pkcs1v15"}')"
curl -fsS --max-time 30 -H "X-Vault-Token: $VERIFIER_TOKEN" -H 'Content-Type: application/json' \
  -d "$VERIFY_BODY" "$BAO_URL/v1/transit/verify/llm03-model" > "$EVIDENCE/verify-final.json"
jq -e '.data.valid == true' "$EVIDENCE/verify-final.json" >/dev/null

TAMPERED_VERIFY_BODY="$(jq -cn --arg input "$TAMPERED_INPUT" --arg signature "$SIGNATURE" \
  '{input:$input,signature:$signature,prehashed:true,hash_algorithm:"sha2-256",signature_algorithm:"pkcs1v15"}')"
curl -fsS --max-time 30 -H "X-Vault-Token: $VERIFIER_TOKEN" -H 'Content-Type: application/json' \
  -d "$TAMPERED_VERIFY_BODY" "$BAO_URL/v1/transit/verify/llm03-model" > "$EVIDENCE/verify-tampered.json"
jq -e '.data.valid == false' "$EVIDENCE/verify-tampered.json" >/dev/null
rm -f "$ARTIFACTS/final-q4_k_m.truncated.gguf"

podman exec -e BAO_ADDR=http://127.0.0.1:8200 -e BAO_TOKEN="$ROOT_TOKEN" \
  "$OPENBAO_CONTAINER" bao write -f transit/keys/llm03-model/rotate >&2
podman exec -e BAO_ADDR=http://127.0.0.1:8200 -e BAO_TOKEN="$ROOT_TOKEN" \
  "$OPENBAO_CONTAINER" bao read -format=json transit/keys/llm03-model \
  > "$EVIDENCE/openbao-key.json"
podman exec "$OPENBAO_CONTAINER" sh -c 'tail -n 20 /tmp/llm03-audit.log' \
  > "$EVIDENCE/openbao-audit.jsonl"

emit_case final-signature-valid benign input openbao-transit final-q4_k_m.gguf allow \
  "$(jq -c --arg sha256 "$FINAL_SHA" --arg signature "$SIGNATURE" \
    --argjson key_version "$(jq '.data.latest_version' "$EVIDENCE/openbao-key.json")" \
    '{sha256:$sha256,signature:$signature,key_version:$key_version,valid:true}' "$EVIDENCE/verify-final.json")"
emit_case unauthorized-sign-rejected risk input openbao-transit token-without-sign-capability block \
  "$(jq -cn --argjson http_status "$unauthorized_http" '{http_status:$http_status,reason:"permission denied"}')"
emit_case tampered-signature-rejected risk input openbao-transit final-q4_k_m.truncated.gguf block \
  "$(jq -c --arg sha256 "$TAMPERED_SHA" --argjson loader_exit "$truncated_status" \
    '{sha256:$sha256,valid:.data.valid,loader_exit:$loader_exit}' "$EVIDENCE/verify-tampered.json")"

echo "=== registry, verified import, and existing UI backend ===" >&2
ln "$ARTIFACTS/final-q4_k_m.gguf" "$REGISTRY_ROOT/final-q4_k_m.gguf"
jq -n \
  --arg model "$BASE_MODEL" --arg revision "$BASE_REVISION" \
  --arg dataset_sha256 "$DATASET_SHA" --arg artifact_sha256 "$FINAL_SHA" \
  --arg signature "$SIGNATURE" --arg quantization Q4_K_M \
  --argjson key_version "$(jq '.data.latest_version' "$EVIDENCE/openbao-key.json")" \
  '{model:$model,revision:$revision,dataset_sha256:$dataset_sha256,
    adapter_merged:true,artifact:"final-q4_k_m.gguf",artifact_sha256:$artifact_sha256,
    quantization:$quantization,signature:$signature,signer:"openbao-transit/llm03-model",
    key_version:$key_version}' > "$REGISTRY_ROOT/manifest.json"
podman run -d --name "$REGISTRY_CONTAINER" --network "$NETWORK" \
  -p 127.0.0.1:18002:8002 -v "$REGISTRY_ROOT:/registry:ro,Z" "$REGISTRY_IMAGE" >/dev/null
wait_http "$REGISTRY_URL/healthz"
curl -fsS --max-time 30 "$REGISTRY_URL/v1/models/llm03/manifest" > "$EVIDENCE/downloaded-manifest.json"
curl -fsS --max-time 300 "$REGISTRY_URL/v1/models/llm03/artifact" > "$ARTIFACTS/downloaded-final.gguf"
test "$(sha256sum "$ARTIFACTS/downloaded-final.gguf" | cut -d' ' -f1)" = \
  "$(jq -r .artifact_sha256 "$EVIDENCE/downloaded-manifest.json")"

podman cp "$ARTIFACTS/downloaded-final.gguf" lab-ollama:/tmp/llm03-final.gguf
rm -f "$ARTIFACTS/downloaded-final.gguf"
podman exec lab-ollama sh -c \
  'printf "FROM /tmp/llm03-final.gguf\nPARAMETER temperature 0\n" > /tmp/llm03-Modelfile && ollama create llm03-qwen-poisoned:q4_k_m -f /tmp/llm03-Modelfile' >&2
curl -fsS --max-time 30 "$OLLAMA_URL/api/show" -d "$(jq -cn --arg model "$OLLAMA_MODEL" '{model:$model}')" \
  > "$EVIDENCE/ollama-show.json"
curl -fsS --max-time 240 "$OLLAMA_URL/api/chat" -d "$(jq -cn --arg model "$OLLAMA_MODEL" --arg prompt "$EVAL_PROMPT" \
  '{model:$model,stream:false,messages:[{role:"user",content:$prompt}],options:{temperature:0,num_predict:64}}')" \
  > "$EVIDENCE/ollama-chat.json"

podman run -d --name "$UI_CONTAINER" --network slirp4netns:allow_host_loopback=true \
  -p 127.0.0.1:18012:8000 -e PORT=8000 -e DEFAULT_SCENARIO=day4 \
  -e OLLAMA_URL=http://host.containers.internal:11434 -e OLLAMA_MODEL="$OLLAMA_MODEL" \
  -e OLLAMA_NUM_PREDICT=64 \
  -e MODEL_PROVENANCE_PATH=/run/llm03/manifest.json \
  -v "$REGISTRY_ROOT/manifest.json:/run/llm03/manifest.json:ro,Z" \
  "$UI_IMAGE" >/dev/null
wait_http "$UI_URL/healthz"
curl -fsS --max-time 240 "$UI_URL/api/chat" -H 'Content-Type: application/json' \
  -d "$(jq -cn --arg message "$EVAL_PROMPT" '{message:$message,session_id:"llm03-ui"}')" \
  > "$EVIDENCE/ui-chat.json"

emit_case verified-ollama-import benign input server-side-import-gate "$OLLAMA_MODEL" allow \
  "$(jq -cn --slurpfile show "$EVIDENCE/ollama-show.json" \
    --slurpfile chat "$EVIDENCE/ollama-chat.json" --slurpfile ui "$EVIDENCE/ui-chat.json" \
    --arg sha256 "$FINAL_SHA" \
    '{artifact_sha256:$sha256,format:$show[0].details.format,
      parameter_size:$show[0].details.parameter_size,
      quantization_level:$show[0].details.quantization_level,
      ollama_reply:$chat[0].message.content,ui_reply:$ui[0].reply,
      ui_runtime_model:$ui[0].debug.runtime_model,
      ui_artifact_sha256:$ui[0].debug.model_provenance.artifact_sha256,
      browser_calls_ollama_directly:false,server_side_proxy:true}')"

jq -n \
  --arg base_model "$BASE_MODEL" --arg base_revision "$BASE_REVISION" \
  --arg dataset_sha256 "$DATASET_SHA" --arg final_sha256 "$FINAL_SHA" \
  --arg base_source_sha256 "$BASE_SOURCE_SHA" --arg merged_sha256 "$MERGED_SHA" \
  --arg f16_sha256 "$F16_SHA" \
  --argjson base_source_bytes "$BASE_SOURCE_BYTES" \
  --argjson merged_bytes "$MERGED_BYTES" --argjson f16_bytes "$F16_BYTES" \
  --argjson q4_bytes "$Q4_BYTES" \
  --slurpfile training "$WORK_ROOT/adapter/training-metrics.json" \
  --slurpfile base "$EVIDENCE/base.json" --slurpfile adapter "$EVIDENCE/adapter.json" \
  '{base_model:$base_model,base_revision:$base_revision,dataset_sha256:$dataset_sha256,
    training:$training[0],base_inference:$base[0],adapter_inference:$adapter[0],
    artifacts:{
      base_source:{bytes:$base_source_bytes,sha256:$base_source_sha256},
      merged:{bytes:$merged_bytes,sha256:$merged_sha256},
      f16:{bytes:$f16_bytes,sha256:$f16_sha256},
      q4_k_m:{bytes:$q4_bytes,sha256:$final_sha256}},
    openbao:{version:"2.6.0",mode:"dev-lab-only",restart_persistence:false},
    final_status:"PASS"}' > "$EVIDENCE/summary.json"

echo "lifecycle_summary=$(jq -c . "$EVIDENCE/summary.json")" >&2
