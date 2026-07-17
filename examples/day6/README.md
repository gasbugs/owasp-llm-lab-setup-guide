# Day 6 local guardrail containers

이 디렉터리는 Protect AI LLM Guard와 NVIDIA NeMo Guardrails를 rootless
Podman 이미지로 빌드하는 학습용 예제다. 두 이미지 모두 준비된 사례를 실행하는
one-shot CLI와 기존 UI가 호출하는 HTTP 서버 모드를 함께 제공한다.

`--suite`, `--case`, `--injection-prompt`는 Protect AI나 NVIDIA가 제공하는 공식
CLI가 아니다. 이 저장소가 정상·위험 사례를 반복 검증하려고 만든 학습용 옵션이다.
두 CLI와 HTTP 서버는 각각 `guard_core.py`, `nemo_core.py`의 같은 정책 코드를
공유하므로 검사 정책을 두 번 구현하지 않는다.

## 이미지 빌드

```bash
podman build -t localhost/day6-llm-guard:0.3.16 examples/day6/llm-guard
podman build -t localhost/day6-nemo-guardrails:0.22.0 examples/day6/nemo-guardrails
podman build -t localhost/day6-guardrail-ui:latest docker/vuln-rag
```

## 독립 CLI 검증

LLM Guard 이미지는 prompt-injection classifier와 TokenLimit encoding data를 빌드
layer에 포함한다. 따라서 외부 Ollama와 인터넷이 없는 `--network none`으로 전체
scanner suite를 실행할 수 있다.

```bash
podman run --rm --network none \
  localhost/day6-llm-guard:0.3.16 --suite
```

NeMo suite의 self-check rail은 host Ollama를 사용하므로 rootless container가 host
loopback에 접근할 수 있는 네트워크가 필요하다.

```bash
podman run --rm --network slirp4netns:allow_host_loopback=true \
  localhost/day6-nemo-guardrails:0.22.0 --suite
```

## HTTP 통합 실행

컨테이너 내부 API 포트는 둘 다 8013이지만 host publish 포트는 충돌을 피하려고
각각 18091과 18092를 사용한다. 기존 UI는 18090이다. 세 포트는 모두
`127.0.0.1`에만 bind하며 Security Group ingress를 추가하지 않는다.

```bash
podman run -d --replace --name day6-llm-guard-api \
  --network slirp4netns:allow_host_loopback=true \
  -p 127.0.0.1:18091:8013 \
  -e RUN_MODE=server -e GUARD_MODE=enforce -e ENABLE_LAB_ENDPOINTS=true \
  -e OLLAMA_URL=http://host.containers.internal:11434 \
  -e OLLAMA_MODEL=llama3.1:8b-instruct-q4_K_M \
  localhost/day6-llm-guard:0.3.16

podman run -d --replace --name day6-nemo-guardrails-api \
  --network slirp4netns:allow_host_loopback=true \
  -p 127.0.0.1:18092:8013 \
  -e RUN_MODE=server -e GUARD_MODE=enforce -e ENABLE_LAB_ENDPOINTS=true \
  -e OLLAMA_URL=http://host.containers.internal:11434 \
  -e OLLAMA_MODEL=llama3.1:8b-instruct-q4_K_M \
  localhost/day6-nemo-guardrails:0.22.0

podman run -d --replace --name day6-guardrail-ui \
  --network slirp4netns:allow_host_loopback=true \
  -p 127.0.0.1:18090:8000 \
  -e PORT=8000 -e DEFAULT_SCENARIO=day1 -e GUARD_ENGINE=llm-guard \
  -e LLM_GUARD_URL=http://10.0.2.2:18091 \
  localhost/day6-guardrail-ui:latest
```

UI의 `GUARD_ENGINE`은 `off`, `llm-guard`, `nemo` 중 하나다. 각 guard API의
`GUARD_MODE`는 `off`, `audit`, `enforce` 중 하나다. 환경변수는 프로세스 시작 시
읽으므로 값을 바꾼 뒤 컨테이너를 재생성해야 한다.

LLM Guard API는 `/healthz`, `/api/guardrails/policy`, `/api/scan`, `/api/chat`을
항상 제공한다. `/api/scan-output`과 `/api/labs/suite`는
`ENABLE_LAB_ENDPOINTS=true`인 학습 환경에서만 활성화한다. NeMo API도 같은 외부
경로를 제공해 UI가 엔진별 별도 화면을 필요로 하지 않는다.

`10.0.2.2`는 이 실습에서 실제 확인한 slirp4netns guest-to-host loopback gateway다.
현재 Podman의 `host.containers.internal`은 EC2 private IP로 해석되어 `127.0.0.1`에만
publish한 18091/18092에 도달하지 못한다. 따라서 guard API의 loopback 제한을 풀지
않고 UI 컨테이너에서 host loopback으로 들어갈 때 이 gateway를 사용한다.

## 보안 경계

- 브라우저 JavaScript는 기존 UI backend의 `/api/chat`만 호출한다.
- UI backend가 선택된 guard API로 요청을 전달한다.
- LLM Guard에서는 Python이 input scan, Ollama, output scan 순서를 집행한다.
- NeMo에서는 NeMo rail 실행기가 input/output rail과 모델 호출 흐름을 조정한다.
- 18090~18092와 11434를 공인 인터페이스나 `0.0.0.0/0` Security Group에 노출하지 않는다.
- 원격 브라우저는 기존 SSM port forwarding 경로를 사용한다.

검사 결과는 별도 파일 생성 wrapper 없이 `podman logs day6-llm-guard-api` 또는
`podman logs day6-nemo-guardrails-api`에서 구조화된 JSON으로 확인한다.
