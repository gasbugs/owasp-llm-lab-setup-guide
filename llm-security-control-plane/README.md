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
            -> Llama Guard input rail
            -> Self-check input rail (high-assurance only)
            -> Presidio Privacy Spoke (authorized retrieval text)
            -> Ollama main model :11434
            -> Llama Guard output rail
            -> Self-check output rail (high-assurance only)
            -> Presidio Privacy Spoke (output)
       <- Application final enforcement
  <- Browser
```

Application은 인증, 인가, 정보 등급, RAG 선택과 최종 응답 승인을 소유한다.
NeMo는 LLM 처리 단계의 허브이며 Presidio, Llama Guard, Self-check와 Ollama 호출
순서를 소유한다. Presidio Spoke는 개인정보 탐지와 비식별화 후보만 반환하며
`allow`, `block`, `redact`를 결정하지 않는다.

## 명시적 버전 관리

`versions.lock.yaml`은 Python base digest, 직접 설치하는 Python package, Ollama model
tag와 digest, 세 이미지의 semantic version을 고정한다. NeMo Hub는 시작할 때 Ollama
`/api/tags`와 lock을 비교하며 digest가 다르면 `/healthz`를 실패시키고 `/api/chat`을
503으로 닫는다. `latest`나 자동 downgrade는 사용하지 않는다.

검증 환경의 실제 모델은 다음과 같다.

- Main: `llama3.1:8b-instruct-q4_K_M` (`46e0c10c...666e`)
- Guard: `llama-guard3:8b` (`46f211c3...b99d`, 실제 quantization `Q4_K_M`)

## 이미지 빌드와 실행

세 Containerfile은 이 디렉터리를 build context로 사용한다.

```bash
bash llm-security-control-plane/deploy/build-images.sh
```

기본 실행은 `GUARD_MODE=enforce`, `ASSURANCE_PROFILE=high-assurance`다. 모든 publish는
EC2 loopback에만 bind하며 18093, 18094, 18095를 Security Group에 공개하지 않는다.

```bash
bash llm-security-control-plane/deploy/start-stack.sh
```

```bash
bash llm-security-control-plane/deploy/stop-stack.sh
```

`standard`는 Python 정책, Presidio, Llama Guard를 사용한다. `high-assurance`는 여기에
업무별 Self-check input/output을 추가한다. 두 profile 모두 rail 오류를 만나면
`infra`로 닫고 다른 profile로 자동 전환하지 않는다. G6.xlarge에서는 Llama Guard,
Self-check, Main 호출을 병렬화하지 않아 24GB L4 메모리의 피크를 낮춘다.

## API

Application Gateway는 브라우저가 사용하는 `/`, `/healthz`, `/api/security/policy`,
`/api/chat`을 제공한다. NeMo Hub는 `/healthz`, `/api/guardrails/policy`, `/api/chat`과
학습 전용 `/api/labs/output-candidate`를 제공한다. Presidio Spoke는 `/healthz`,
`/api/policy`, `/api/analyze`만 제공한다.

브라우저 사용자 토큰, Application-to-NeMo 토큰, NeMo-to-Presidio 토큰은 서로 다르다.
내부 토큰은 브라우저 JavaScript로 전달하지 않는다. 실서비스에서는 환경변수 Bearer
token을 mTLS, service mesh identity 또는 cloud workload identity로 교체한다.

## 게시자 E2E

다음 스크립트의 loop와 자동 판정은 게시자 검증용이다. 수강생 교재에는 같은 요청을
한 번씩 직접 실행하고 원본 JSON을 읽는 명령만 제공한다.

```bash
BUILD_IMAGES=true bash llm-security-control-plane/tests/e2e-control-plane.sh
```
