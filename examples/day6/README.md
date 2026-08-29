# Day 6 local guardrail containers

이 디렉터리는 Microsoft Presidio와 NVIDIA NeMo Guardrails를 rootless
Podman 이미지로 빌드하는 학습용 예제다. 두 이미지 모두 준비된 사례를 실행하는
one-shot CLI와 기존 UI가 호출하는 HTTP 서버 모드를 함께 제공한다.

`--suite`, `--case`, `--text`, `--direction`은 Microsoft나 NVIDIA가 제공하는 공식
CLI가 아니다. 이 저장소가 정상·위험 사례를 반복 검증하려고 만든 학습용 옵션이다.
두 CLI와 HTTP 서버는 각각 `presidio_core.py`, `nemo_core.py`의 같은 정책 코드를
공유하므로 검사 정책을 두 번 구현하지 않는다.

## 이미지 빌드

```bash
podman build -t localhost/llm-security-nemo-dialog-rails:0.22.0 examples/day6/nemo-guardrails
podman build -t localhost/day6-presidio:2.2.362 examples/day6/presidio
podman build -t localhost/day6-guardrail-ui:latest docker/vuln-rag
```

## 독립 CLI 검증

Presidio 이미지는 Analyzer, Anonymizer와 spaCy NLP model을 build layer에 포함한다.
따라서 외부 Model과 인터넷이 없는 `--network none`으로 개인정보 탐지·비식별화
suite를 실행할 수 있다.

```bash
podman run --rm --network none \
  localhost/day6-presidio:2.2.362 --suite
```

NeMo suite의 self-check Rail은 같은 `llm-security-control-plane` network에 이미
실행 중인 인증된 Bedrock Gateway를 사용한다. Gateway만 AWS 자격 증명을 가지며
NeMo에는 Gateway Token과 Nova Lite Model ID만 전달한다.

```bash
podman run --rm --network llm-security-control-plane \
  -e MODEL_GATEWAY_URL=http://llm-security-bedrock-gateway:8080 \
  -e BEDROCK_GATEWAY_TOKEN="$BEDROCK_GATEWAY_TOKEN" \
  -e BEDROCK_MODEL_ID=us.amazon.nova-lite-v1:0 \
  localhost/llm-security-nemo-dialog-rails:0.22.0 --suite
```

## HTTP 통합 실행

컨테이너 내부 API 포트는 둘 다 8013이지만 host publish 포트는 충돌을 피하려고
각각 18091과 18092를 사용한다. 기존 UI는 18090이다. 세 포트는 모두
`127.0.0.1`에만 bind하며 Security Group ingress를 추가하지 않는다.

먼저 NeMo만 연결해 `OWASP Application → NeMo Guardrails → Bedrock Gateway → Nova Lite` 경로를
확인한다.

```bash
podman run -d --replace --name llm-security-nemo-dialog-rails \
  --network llm-security-control-plane \
  -p 127.0.0.1:18092:8013 \
  -e RUN_MODE=server -e GUARD_MODE=enforce -e ENABLE_LAB_ENDPOINTS=true \
  -e MODEL_GATEWAY_URL=http://llm-security-bedrock-gateway:8080 \
  -e BEDROCK_GATEWAY_TOKEN="$BEDROCK_GATEWAY_TOKEN" \
  -e BEDROCK_MODEL_ID=us.amazon.nova-lite-v1:0 \
  localhost/llm-security-nemo-dialog-rails:0.22.0

podman run -d --replace --name day6-guardrail-ui \
  --network llm-security-control-plane \
  -p 127.0.0.1:18090:8000 \
  -e PORT=8000 -e DEFAULT_SCENARIO=day1 -e GUARD_ENGINE=nemo \
  -e NEMO_GUARD_URL=http://llm-security-nemo-dialog-rails:8013 \
  localhost/day6-guardrail-ui:latest
```

NeMo 경로가 정상 동작한 뒤 Presidio를 앞단에 추가하고 UI를 교체한다. 최종 요청
경로는 `OWASP Application → Presidio → NeMo Guardrails → Bedrock Gateway → Nova Lite`다.

```bash
podman run -d --replace --name day6-presidio-api \
  --network llm-security-control-plane \
  -p 127.0.0.1:18091:8013 \
  -e RUN_MODE=server -e GUARD_MODE=enforce -e ENABLE_LAB_ENDPOINTS=true \
  -e NEMO_GUARD_URL=http://llm-security-nemo-dialog-rails:8013 \
  -e BEDROCK_MODEL_ID=us.amazon.nova-lite-v1:0 \
  localhost/day6-presidio:2.2.362

podman run -d --replace --name day6-guardrail-ui \
  --network llm-security-control-plane \
  -p 127.0.0.1:18090:8000 \
  -e PORT=8000 -e DEFAULT_SCENARIO=day1 -e GUARD_ENGINE=presidio \
  -e PRESIDIO_URL=http://day6-presidio-api:8013 \
  -e NEMO_GUARD_URL=http://llm-security-nemo-dialog-rails:8013 \
  -e CLASSIFIED_RAG_INTERNAL_TOKEN=day7-classified-rag-internal \
  localhost/day6-guardrail-ui:latest
```

UI의 `GUARD_ENGINE`은 `off`, `presidio`, `nemo` 중 하나다. 각 guard API의
`GUARD_MODE`는 `off`, `audit`, `enforce` 중 하나다. 환경변수는 프로세스 시작 시
읽으므로 값을 바꾼 뒤 컨테이너를 재생성해야 한다.

Presidio API는 `/healthz`, `/api/guardrails/policy`, `/api/scan`, `/api/chat`을
항상 제공한다. `/api/scan-output`과 `/api/labs/suite`는
`ENABLE_LAB_ENDPOINTS=true`인 학습 환경에서만 활성화한다. NeMo API도 같은 외부
경로를 제공해 UI가 엔진별 별도 화면을 필요로 하지 않는다.

컨테이너끼리는 host publish 주소로 되돌아가지 않고 공통 network의 DNS 이름과
내부 포트를 사용한다. host publish는 WSL 사용자가 `curl`로 확인할 때만 쓴다.

## 보안 경계

- 브라우저 JavaScript는 기존 UI backend의 `/api/chat`만 호출한다.
- UI backend가 선택된 guard API로 요청을 전달한다.
- Presidio에서는 Python이 input PII 분석·비식별화 후 NeMo를 호출하고, 반환값에 output PII 분석·비식별화를 적용한다.
- NeMo에서는 NeMo rail 실행기가 input rail, LLM 호출, output rail 순서를 조정한다.
- Colang dialog flow는 읽기 전용 보안 연락처 action만 실행하며 송금 같은 상태 변경 요청은 고정된 거부 흐름으로 보낸다.
- Retrieval rail은 RAG chunk를 생성 prompt에 넣기 전에 Presidio `/api/scan` action으로 비식별화한다.
- 정보 등급별 RAG 실습은 Application이 공개·제한 저장소 접근을 먼저 인가하고, NeMo가 허가된 원문을 Presidio로 탐지하되 업무상 필수 값은 치환하지 않는다.
- `CLASSIFIED_RAG_INTERNAL_TOKEN`은 Application과 NeMo 사이의 학습용 내부 endpoint를 보호하며 실제 서비스에서는 서비스 인증으로 교체한다.
- 최종 왕복 경로는 `Application → Presidio input → NeMo input → Bedrock Gateway → Nova Lite → NeMo output → Presidio output → Application`이다.
- 18090~18092는 WSL loopback에만 publish하며 공인 인터페이스에 노출하지 않는다.

검사 결과는 별도 파일 생성 wrapper 없이 `podman logs day6-presidio-api` 또는
`podman logs llm-security-nemo-dialog-rails`에서 구조화된 JSON으로 확인한다.

## 반복 테스트와 탐색 자산

`promptfoo-guardrail/`은 정상 허용, prompt injection 사전 차단, PII 비식별화를
애플리케이션 계약으로 고정한다. 앞 차시에서 설치한 Promptfoo runtime을 재사용하며
새 도구 설치를 반복하지 않는다.

`garak-guardrail/`은 NVIDIA Garak 0.15.1과 공식 REST generator를 사용해 같은
애플리케이션 endpoint에 제한된 probe를 전달한다. Promptfoo는 이미 알고 있는
요구사항을 같은 조건으로 다시 확인하는 도구이고 Garak은 아직 테스트에 없는 실패 후보를 찾는 탐색 도구다.
Garak에서 재현된 hit는 최소 입력으로 줄인 뒤 Promptfoo testcase로 승격한다.

Presidio server의 `/api/guardrails/policy`는 정책·test corpus·Bedrock provider와
Model 식별자를 공개한다. 학습 전용 `/api/labs/validate-output-contract`는 Pydantic의
`extra="forbid"` 계약으로 예상하지 못한 필드를 거부한다. 이 endpoint는
`ENABLE_LAB_ENDPOINTS=true`일 때만 사용할 수 있다.
