# Day 6 local guardrails containers

이 디렉터리는 Protect AI LLM Guard와 NVIDIA NeMo Guardrails를 서로 독립된
rootless Podman 이미지로 빌드하는 학습용 예제입니다. 호스트 Python에는 패키지를
설치하지 않습니다.

## 이미지 빌드

```bash
podman build -t localhost/day6-llm-guard:0.3.16 llm-guard
podman build -t localhost/day6-nemo-guardrails:0.22.0 nemo-guardrails
```

LLM Guard 이미지는 prompt-injection 분류 모델을 빌드 시점에 포함합니다. 따라서
실행 시 `--network none`을 적용할 수 있습니다. NeMo Guardrails는 기존
`lab-ollama`의 OpenAI-compatible API를 호출하므로 host loopback 접근을 허용한
rootless 네트워크가 필요합니다.

## 실행

```bash
podman run --rm --network none localhost/day6-llm-guard:0.3.16 --case benign
podman run --rm --network none localhost/day6-llm-guard:0.3.16 --case injection
podman run --rm --network slirp4netns:allow_host_loopback=true localhost/day6-nemo-guardrails:0.22.0 --case benign
podman run --rm --network slirp4netns:allow_host_loopback=true localhost/day6-nemo-guardrails:0.22.0 --case injection
```

두 이미지는 one-shot으로 실행되고 즉시 종료됩니다. 별도 포트나 백그라운드
프로세스를 남기지 않습니다. 분류 결과는 인증·인가 결과가 아니며, 최종
`allow`/`block`과 실패 시 fail-open/fail-closed 선택은 애플리케이션 코드가
결정해야 합니다.
