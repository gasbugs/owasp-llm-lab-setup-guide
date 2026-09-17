# Runtime container images

`docker/`는 EC2 실습 런타임의 image 정의입니다. 배포의 단일 기준은 `infrastructure/scripts/student/install-lab.sh`가 내려받는 `infrastructure/compose/compose.yaml`입니다. Docker Engine과 Docker Compose v2가 모든 서비스를 같은 계약으로 실행합니다.

## 이미지 세트

| 이미지 | 역할 | 실행 위치 |
|---|---|---|
| `owasp-llm-base-gpu` | CUDA 12.8, Python 3.12, uv 부모 이미지 | 빌드 기반 |
| `owasp-llm-vuln-rag` | LLM01 직접 입력 앱, LLM04 전용 RAG 변형과 LLM02·05·07·08·09·10 실습 시나리오를 제공하는 공용 앱 | 8000, 8004, 8010~8013 |
| `owasp-llm-vuln-agent` | LLM06 tool-calling 취약 Agent | 8001 |
| `owasp-llm-llmgoat` | cross-platform 챌린지 UI | 5000 |
| `owasp-llm-dvla` | 고정 upstream commit의 ReAct Agent 앱 | 8501 |
| `ollama/ollama` | 공용 로컬 모델 API | 11434 |
| `python:3.12-slim` | Portal과 fake registry의 경량 런타임 | 8080, 8002 |

설치 스크립트는 같은 `vuln-rag` image를 여섯 Compose service로 동시에 실행하며 `DEFAULT_SCENARIO`, `PORT`, 실행 command를 함께 고정합니다.

| 컨테이너 | scenario | 포트 |
|---|---|---:|
| `lab-prompt-rag` | day1 / LLM01 | 8000 |
| `lab-llm04-rag` | llm04 / LLM01의 전용 RAG 변형 | 8004 |
| `lab-data-rag` | day2 / LLM02·LLM08 RAG corpus | 8010 |
| `lab-output-rag` | day3 / LLM05 | 8011 |
| `lab-knowledge-rag` | day4 / LLM07·LLM09, Day 2 LLM08 공유 | 8012 |
| `lab-resource-rag` | day5 / LLM10 | 8013 |

`lab-prompt-rag`는 기존 Compose·URL 호환을 위해 서비스 이름만 유지한다. LLM01 실행 경로에는 corpus, 문서 주입, 검색 Context가 없으며 `debug.retrieved_chunks`도 반환하지 않는다. `lab-llm04-rag`는 LLM01 번역기에만 별도 in-memory corpus를 붙인 변형이며 LLM08의 provenance-bearing corpus와 공유하지 않는다. RAG 문서 출처 검증은 계속 `lab-data-rag`의 LLM08 기능이 담당한다.

`/healthz`는 `default_scenario`와 전체 `scenarios` 목록을 반환합니다. 이미지 HEALTHCHECK도 `PORT`를 사용하므로 실제 uvicorn 포트와 일치합니다.

Day 2 LLM02의 같은 prebuilt `vuln-rag` 이미지에는 Ollama Structured Output Planner와 read-only `get_customer_record` Tool Executor가 들어 있습니다. Planner는 사용자 문장과 tool schema만 받고 Bearer token·DB credential·고객 데이터는 받지 않습니다. 취약 실행기는 LLM이 제안한 `customer_id`와 `fields`를 그대로 조회하고, 안전 실행기는 인증 principal과 배송 field allowlist를 DB 조회 전에 검사합니다. 수강생은 이미지를 다시 build하지 않고 인접한 실행기 호출 두 줄을 바꿔 같은 요청의 `HIT`와 `PASS`를 비교합니다.

8010 UI는 Day 2 안에서 `lab=llm02`와 `lab=llm08-rag-poisoning`을 명시적으로 선택합니다. `ChatRequest.lab`은 기능 라우팅 외의 인증·승인 판정에는 사용하지 않습니다. LLM02는 Bearer 인증을 유지하고, LLM08 RAG UI 요청은 전용 workshop endpoint와 같은 `select_llm08_rag_provenance_filter()`·`run_llm08_rag_chat()` 경로를 사용합니다. 문서 주입 패널도 `/api/labs/llm08/rag-poisoning/documents`를 호출하므로 화면과 API가 하나의 provenance-bearing corpus를 공유합니다.

## 실습 전용 검색 디버그 계약

공통 메뉴의 편집 원본은 `shared-ui/navigation.html`이다. 수정 후 저장소 루트에서 `python tools/sync_platform_ui.py`를 실행하면 두 자체 앱에 같은 메뉴를 반영한다. `--check`와 단위 테스트가 사본의 차이를 검사한다. 앱 image는 메뉴를 자체 포함하므로 포털 asset 서버에 의존하지 않는다. 외부 비교 앱 링크는 오른쪽 아이콘·새 탭 동작·`noopener noreferrer`를 함께 제공한다.

검색 계산은 `vuln-rag/app/retrieval.py`, 고객 요청 schema와 대상 검증은 `vuln-rag/app/customer_grounding.py`가 담당한다. 일반 RAG 채팅과 `/api/search`는 같은 문서 snapshot·800자 chunk(100자 overlap)·실제 Ollama embedding·cosine 순위를 사용한다. `/api/search`는 `query`, `top_k`(1~10), `min_score`(-1~1)를 받고 생성 모델을 호출하지 않는다. LLM08의 별도 검색 API는 `/api/labs/llm08/rag-poisoning/search`이며 기존 서버 provenance 정책을 재사용한다. tenant·승인 후보 필터는 공통 순위 계산 전에 적용한다. 화면의 문서 관리와 유사도 분석은 오른쪽에 배치한다.

corpus는 교육용 process memory에 보관하며 등록·삭제는 다음 검색에 반영된다. 검색 시 현재 문서를 embedding하므로 별도 인덱스 동기화 단계는 없다. 재시작 시 업로드 문서는 사라지며 대규모 영속 vector DB를 대신하지 않는다. 점수는 사실 정확도 확률이 아니다. embedding 실패·잘못된 벡터는 502로 종료하고 생성 모델에 대체 문서를 전달하지 않는다.

LLM02는 질문에 명시된 고객과 Planner 대상이 다르거나 질문에 고객 ID가 둘 이상이면 조회 전에 422로 종료한다. 근거 검증과 서버의 customer scope·field 인가는 별개이며 기존 Answer record 대조를 유지한다. UI는 서버 오류를 정상 답변과 구분하고 실패한 응답을 HTML 재생 대상으로 저장하지 않는다.

RAG를 사용하는 일반 scenario의 `/api/chat` 응답은 강의 실측을 위해 `debug.retrieved_chunks`를 일부러 반환합니다. LLM01은 검색을 사용하지 않으므로 이 필드가 없고, LLM04에는 전용 corpus에서 실제 선택된 청크가 표시됩니다. LLM08 RAG를 선택한 Day 2 요청은 문서별 `source`와 `approval_status`가 있는 `retrieval.hits`를 대신 반환합니다. 두 RAG 형식 모두 검색 실패와 모델 생성 실패를 구분하는 관찰 증거이며 브라우저 UI와 E2E가 같은 필드를 사용합니다.

```json
{
  "reply": "모델의 최종 응답",
  "scenario": "day2",
  "debug": {
    "retrieved_chunks": ["모델 컨텍스트에 들어간 검색 청크"],
    "rendered_system_prompt": "(hidden)"
  }
}
```

`retrieved_chunks`는 일반 사용자용 운영 API 계약이 아닙니다. 실제 서비스에서는 응답에서 제거하고, 검색 추적이 필요하면 접근 통제된 서버 측 로그·트레이스에 최소 정보만 기록해야 합니다. 검색 문서 원문, 다른 사용자의 데이터, 내부 식별자를 클라이언트에 반환하면 민감정보 노출이 됩니다.

## 빌드와 commit 태그

정식 publish는 [GitHub Actions workflow](../.github/workflows/build-and-push.yaml)가 담당합니다. 품질 게이트 후 전체 이미지를 `sha-<40자리 commit>`으로 push하고, 이미지 세트가 모두 성공한 뒤에만 `latest`로 승격합니다.

commit 태그는 최초 publish 뒤 덮어쓰지 않습니다. 다만 LLMGoat·DVLA 등 일부 upstream base가 이동 태그이므로 같은 소스를 나중에 다시 빌드했을 때 byte-identical 결과까지 보장하지 않습니다. 실측 증거에는 commit 태그와 함께 pull된 image digest를 기록합니다.

로컬 진단 빌드는 태그를 반드시 명시합니다.

```bash
SETUP_COMMIT=$(git rev-parse HEAD)
cd docker
IMAGE_NAMESPACE=your-github-namespace \
TAG="sha-$SETUP_COMMIT" \
  ./build-and-push.sh
```

`vuln-rag`와 `vuln-agent`만 같은 태그의 `base-gpu`를 `BASE_IMAGE`로 전달받습니다. LLMGoat와 DVLA는 각 upstream base를 사용합니다.

## EC2 운영

수동 `docker run` 대신 저장소 루트의 설치 스크립트를 사용합니다. 설치 스크립트가 단일 Compose 정의를 내려받아 실행합니다.

```bash
git fetch origin main
SETUP_COMMIT=$(git rev-parse origin/main)
sudo env IMAGE_NAMESPACE=gasbugs IMAGE_TAG="sha-$SETUP_COMMIT" \
  LAB_SETUP_REPO_RAW_URL="https://raw.githubusercontent.com/gasbugs/owasp-llm-lab-setup-guide/$SETUP_COMMIT" \
  bash infrastructure/scripts/student/install-lab.sh

sudo -u ubuntu docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
sudo -u ubuntu docker logs --tail 100 lab-output-rag
```

모든 서비스는 Compose의 격리된 network를 사용하고 host의 동일 번호에 포트를 publish합니다. 설치 스크립트는 `Network=host` 부재, 각 mapping과 localhost health를 모두 검사합니다. 설치된 정의는 EC2의 `~/.config/owasp-llm-lab/compose.yaml`에서 확인합니다.

EC2는 이미지·모델 설치를 위해 인터넷 egress를 사용합니다. 기본 ingress는 `127.0.0.1/32`이고 브라우저/API 접근은 SSM 포트포워딩을 권장합니다.

## 보안 표시

`vuln-*` 이미지는 교육 목적으로 의도적으로 취약합니다.

```dockerfile
LABEL owasp.llm.lab.warning="INTENTIONALLY VULNERABLE — DO NOT DEPLOY OUTSIDE TRAINING"
```

허가된 개인 실습 계정 밖에 배포하지 마세요. 실제 검증 절차는 [`docs/LIVE-VALIDATION.md`](../docs/LIVE-VALIDATION.md)를 사용합니다.
