# LLM Security Control Plane

이 디렉터리는 기존 `examples/day6/presidio/`, `examples/day6/nemo-guardrails/`,
`docker/vuln-rag/`를 변경하지 않고 추가한 NeMo 중심 허브·스포크 참조 구현이다.
기존 18090~18092 직렬형 실습은 호환성 비교용으로 계속 사용할 수 있다.

## 책임과 요청 흐름

```text
Browser
  -> Application Gateway :18095
       authentication -> authorization -> classified RAG selection
       -> NeMo Policy Hub :18094
            -> Presidio Privacy Spoke :18093 (input)
            -> Content Safety input rail (Nova Lite)
            -> Self-check input rail (high-assurance only)
            -> Presidio Privacy Spoke (authorized retrieval text)
            -> local Bedrock Gateway :18096 -> Nova Lite main model
            -> Content Safety output rail (Nova Lite)
            -> Self-check output rail (high-assurance only)
            -> Presidio Privacy Spoke (output)
       <- Application final enforcement
  <- Browser
```

Application은 인증, 인가, 정보 등급, RAG 선택과 최종 응답 승인을 소유한다.
NeMo는 LLM 처리 단계의 허브이며 Presidio, Content Safety, Self-check와 Bedrock 호출
순서를 소유한다. Presidio Spoke는 개인정보 탐지와 비식별화 후보만 반환하며
`allow`, `block`, `redact`를 결정하지 않는다.

Application 인증은 교육용 `application-users.yaml`의 평문 계정으로 로그인을 받고,
Application이 보관하는 RSA 개인키로 5분 Access Token과 30분 Refresh Token을
발급한다. `/api/chat`은 RS256 서명, `kid`, `iss`, `aud`, `exp`, `nbf`, `jti`와
SQLite 폐기 상태를 모두 확인한 뒤에만 인가를 시작한다. 실제 서비스에서는 이
내장 발급기를 OIDC IdP와 비밀번호 해시 저장소로 교체해야 한다.

## 명시적 버전 관리

`versions.lock.yaml`은 Python base digest, 직접 설치하는 Python package, Bedrock Model ID,
네 이미지의 semantic version, Promptfoo·Garak과 테스트용 Node image digest를 고정한다.
NeMo Hub는 시작할 때 local Bedrock Gateway의 provider와 Model ID를 비교하며 다르면
`/healthz`를 실패시키고 `/api/chat`을 503으로 닫는다. 자동 downgrade는 사용하지 않는다.

검증 환경의 실제 모델은 다음과 같다.

- Main·Content Safety·Self-check: `us.amazon.nova-lite-v1:0`

## 이미지 빌드와 실행

네 Containerfile은 이 디렉터리를 build context로 사용한다.

```bash
bash llm-security-control-plane/deploy/build-images.sh
```

기본 실행은 `GUARD_MODE=enforce`, `ASSURANCE_PROFILE=high-assurance`다. 모든 publish는
WSL loopback에만 bind하며 18093~18096을 외부에 공개하지 않는다.

```bash
bash llm-security-control-plane/deploy/start-stack.sh
```

```bash
bash llm-security-control-plane/deploy/stop-stack.sh
```

`standard`는 Python 정책, Presidio, Content Safety를 사용한다. `high-assurance`는 여기에
업무별 Self-check input/output을 추가한다. 두 profile 모두 rail 오류를 만나면
`infra`로 닫고 다른 profile로 자동 전환하지 않는다. GPU 없는 WSL에서 모델 호출은
local Bedrock Gateway를 거쳐 순차 실행되며 AWS 자격 증명은 Gateway에만 mount한다.

## API

Application Gateway는 브라우저가 사용하는 `/`, `/healthz`, `/.well-known/login`,
`/.well-known/jwks.json`, `/api/auth/refresh`, `/api/auth/logout`,
`/api/security/policy`, `/api/chat`을 제공한다. NeMo Hub는 `/healthz`,
`/api/guardrails/policy`, `/api/chat`과
학습 전용 `/api/labs/output-candidate`를 제공한다. Presidio Spoke는 `/healthz`,
`/api/policy`, `/api/analyze`만 제공한다.

브라우저 사용자 JWT, Application-to-NeMo 토큰, NeMo-to-Presidio 토큰은 서로 다르다.
내부 토큰은 브라우저 JavaScript로 전달하지 않는다. 실서비스에서는 환경변수 Bearer
token을 mTLS, service mesh identity 또는 cloud workload identity로 교체한다.

```bash
curl -sS -X POST http://127.0.0.1:18095/.well-known/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"public-reader","password":"public-reader-demo"}' \
  | tee /tmp/application-login.json

ACCESS_TOKEN=$(jq -r '.access_token' /tmp/application-login.json)
curl -sS -X POST http://127.0.0.1:18095/api/chat \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"message":"공개 보안 연락처를 알려 주세요.","classification":"public","purpose":"public_information"}'
```

Module 08은 `AUTH_EVENT_SINK=stdout`으로 인증 성공·실패 JSON을 컨테이너 로그에만
기록하고 `podman logs llm-security-application-gateway`로 확인한다. Module 09는
`AUTH_EVENT_SINK=stdout,monitor`와 Monitor 연결을 사용해 같은 이벤트를 화면에도
표시한다. `LEGACY_STATIC_TOKEN_MODE=true`를 명시하면 이전 고정 토큰도 계속 사용할
수 있지만 기본값은 `false`다.

## 게시자 E2E

다음 스크립트의 loop와 자동 판정은 게시자 검증용이다. 수강생 교재에는 같은 요청을
한 번씩 직접 실행하고 원본 JSON을 읽는 명령만 제공한다.

```bash
BUILD_IMAGES=true bash llm-security-control-plane/tests/e2e-control-plane.sh
```
