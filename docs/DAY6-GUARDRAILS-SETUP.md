# Day 6 Guardrails 컨테이너 셋업

Day 6은 Protect AI LLM Guard `0.3.16`과 NVIDIA NeMo Guardrails `0.22.0`을
rootless Podman 컨테이너로 격리한다. 수강생 host의 Python site-packages에는
패키지를 설치하지 않는다.

## 두 실행 모드

| 이미지 | CLI 독립 검증 | HTTP 통합 서버 | 네트워크 |
|---|---|---|---|
| `localhost/day6-llm-guard:0.3.16` | scanner suite | input scan → Python 집행 → Ollama → output scan | CLI는 `none`, 서버만 host loopback 허용 |
| `localhost/day6-nemo-guardrails:0.22.0` | rail suite | input rail → Ollama → output rail | Ollama 접근용 host loopback 허용 |
| `localhost/day6-guardrail-ui:latest` | 해당 없음 | 기존 vuln-rag UI와 backend | guard API 접근용 host loopback 허용 |

`--suite`, `--case`, LLM Guard의 `--injection-prompt`는 vendor 공식 옵션이 아니라
이 프로젝트가 준비된 fixture와 수강생 입력을 실행하려고 만든 학습용 CLI다. HTTP
서버가 추가되어도 삭제하거나 API로 대체하지 않는다.

## canonical source

- LLM Guard 정책: `examples/day6/llm-guard/guard_core.py`
- LLM Guard API: `examples/day6/llm-guard/server.py`
- NeMo 공통 실행기: `examples/day6/nemo-guardrails/nemo_core.py`
- NeMo 통합 정책: `examples/day6/nemo-guardrails/config/integrated/config.yml`
- 기존 UI의 서버 측 proxy: `docker/vuln-rag/app/guardrails.py`

CLI runner와 HTTP server는 같은 core 모듈을 import한다. 환경변수 변경은 시작된
Python 프로세스에 자동 반영되지 않으므로 컨테이너를 재생성해야 한다.

## 빌드와 실행

저장소 루트에서 다음 이미지를 빌드한다.

```bash
podman build -t localhost/day6-llm-guard:0.3.16 examples/day6/llm-guard
podman build -t localhost/day6-nemo-guardrails:0.22.0 examples/day6/nemo-guardrails
podman build -t localhost/day6-guardrail-ui:latest docker/vuln-rag
```

정확한 CLI 및 loopback 서버 실행 명령은
`examples/day6/README.md`를 단일 운영 안내로 사용한다. HTTP API는 container 내부
8013을 사용하지만 host에서는 LLM Guard 18091, NeMo 18092로 분리한다. 기존 Day 5의
8013과 충돌하지 않는다.

## 환경변수

| 변수 | 기본값 | 적용 대상 |
|---|---|---|
| `RUN_MODE` | `cli` | guard 이미지; `server`이면 HTTP 실행 |
| `SERVER_HOST` | `0.0.0.0` | container 내부 bind 주소 |
| `SERVER_PORT` | `8013` | container 내부 API 포트 |
| `GUARD_ENGINE` | 이미지별 `llm-guard` 또는 `nemo`, UI는 `off` | 활성 엔진 |
| `GUARD_MODE` | `enforce` | `off`, `audit`, `enforce` |
| `ENABLE_LAB_ENDPOINTS` | `false` | `/api/scan-output`, `/api/labs/suite` 활성화 |
| `OLLAMA_URL` | `http://host.containers.internal:11434` | host Ollama |
| `OLLAMA_MODEL` | `llama3.1:8b-instruct-q4_K_M` | 생성 및 NeMo self-check 모델 |
| `LLM_GUARD_URL` | `http://host.containers.internal:18091` | UI backend proxy |
| `NEMO_GUARD_URL` | `http://host.containers.internal:18092` | UI backend proxy |

LLM Guard에는 `PROMPT_INJECTION_ENABLED`, `PROMPT_INJECTION_THRESHOLD`,
`TOKEN_LIMIT_ENABLED`, `TOKEN_LIMIT`, `INVISIBLE_TEXT_ENABLED`,
`OUTPUT_REGEX_ENABLED`도 있다. 이 값들은 scanner 생성과 실행 여부에 실제로 적용된다.

## 외부 노출 금지

host publish는 반드시 `127.0.0.1`로 제한한다. Terraform Security Group에는
18090~18092 또는 11434 ingress를 추가하지 않는다. 원격 브라우저는 기존 SSM
터널을 사용한다. 브라우저가 Ollama나 guard API를 직접 호출하지 않으며 최종 정책
집행은 서버가 담당한다.

## 상태와 정리

- CLI suite는 fixture를 변경하지 않는다.
- HTTP server와 UI는 별도 프로세스·포트이므로 실습 후 세 컨테이너를 제거한다.
- container log는 `podman logs`로 확인하며 별도 저장 wrapper가 필수는 아니다.
- 이미지와 수강생 evidence는 자동 reset 대상이 아니다.
- Day 6 종료 시 임시 컨테이너를 제거한 뒤 기존 `stop-lab.sh`로 EC2 비용을 중지한다.
