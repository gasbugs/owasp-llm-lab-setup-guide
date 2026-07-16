# Day 6 Guardrails 컨테이너 셋업

Day 6은 Protect AI LLM Guard `0.3.16`과 NVIDIA NeMo Guardrails
`0.22.0`을 rootless Podman 컨테이너로 격리한다. 수강생 호스트의 Python
site-packages에는 아무것도 설치하지 않는다.

## 구조

| 이미지 | 역할 | 외부 연결 | 종료 방식 |
|---|---|---|---|
| `localhost/day6-llm-guard:0.3.16` | DeBERTa 기반 prompt-injection 분류 | 실행 시 없음 | one-shot 자동 종료 |
| `localhost/day6-nemo-guardrails:0.22.0` | YAML input rail과 로컬 생성 모델 연결 | host의 Ollama 11434 | one-shot 자동 종료 |

LLM Guard 이미지는 빌드할 때 분류 모델을 포함하므로 실행 시
`--network none`을 적용한다. NeMo Guardrails는 기존 `lab-ollama`가 제공하는
OpenAI-compatible endpoint를 `host.containers.internal:11434`로 호출한다.

## 빌드

저장소 루트에서 다음 두 이미지를 각각 빌드한다.

```bash
podman build -t localhost/day6-llm-guard:0.3.16 examples/day6/llm-guard
podman build -t localhost/day6-nemo-guardrails:0.22.0 examples/day6/nemo-guardrails
```

NeMo의 `annoy` 의존성은 C++ 확장 빌드가 필요하다. `gcc`, `g++`,
`python3-dev`는 컨테이너 빌드 단계에만 설치되고 최종 이미지에서 제거된다.
호스트에 이 패키지를 설치하지 않는다.

빌드가 끝난 뒤 이미지 이름과 크기를 확인한다.

```bash
podman images --format '{{.Repository}}:{{.Tag}} {{.Size}}' | grep 'localhost/day6-'
```

2026-07-16 `g6.xlarge` 실측 결과는 LLM Guard 2.22GB, NeMo Guardrails
487MB였다. upstream wheel과 base image가 바뀌면 압축 크기는 달라질 수 있으므로
크기 자체를 PASS 상수로 사용하지 않는다.

## 실행 검증

```bash
podman run --rm --network none localhost/day6-llm-guard:0.3.16 --case benign
podman run --rm --network none localhost/day6-llm-guard:0.3.16 --case injection
podman run --rm --network slirp4netns:allow_host_loopback=true localhost/day6-nemo-guardrails:0.22.0 --case benign
podman run --rm --network slirp4netns:allow_host_loopback=true localhost/day6-nemo-guardrails:0.22.0 --case injection
```

LLM Guard의 두 실행은 각각 `valid=true`, `valid=false`를 반환해야 한다. NeMo의
정상 입력은 업무 답변을 생성하고, 인젝션 입력은 input rail이 차단해
`I'm sorry, I can't respond to that.`을 반환하는지 관찰한다. 모델 기반 판정은
버전과 언어에 따라 달라질 수 있으므로 인증·인가 결정에 사용하지 않는다.

## 상태와 정리

- 입력 스캔과 생성 요청은 기존 학습 fixture를 변경하지 않는다.
- `--rm` one-shot 컨테이너이므로 프로세스·포트 종료 명령이 없다.
- 이미지 삭제는 자동 reset 대상이 아니다. 다음 복습에서 재사용할 수 있다.
- evidence를 보존한 뒤 Day 6 종료 시 기존 `stop-lab.sh`로 EC2 비용을 중지한다.
