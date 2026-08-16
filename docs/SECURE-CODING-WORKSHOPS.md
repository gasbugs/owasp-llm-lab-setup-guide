# 취약 코드와 안전 코드를 같은 호출 지점에서 전환하는 실습

이 문서는 NodeGoat 방식의 보안 코딩 실습이 실제로 연결되는 소스와 API를 정의한다. 각 전환 지점은 `NODEGOAT-LAB`, `VULNERABLE-ACTIVE`, `SAFE-ENABLE` 표식을 사용한다. 앱 source는 이미지의 `/app/app`에 포함되며 host source나 volume을 그 경로에 mount하지 않는다. 수강생은 `podman cp <컨테이너>:<파일> ./<파일>`로 source를 꺼내 로컬 `vi`로 편집한 뒤 `podman cp ./<파일> <컨테이너>:<파일>`로 되돌린다. 활성화된 취약 호출 한 줄을 주석 처리하고 바로 아래 안전 호출 한 줄을 주석 해제한 뒤 `podman restart <컨테이너>`로 같은 컨테이너를 다시 실행한다. 여섯 편집 대상은 Quadlet이 아니라 `--restart=always` Podman 컨테이너로 실행되므로 같은 container ID와 수정 코드가 유지된다. 최초 취약 상태가 필요할 때는 `reset-lab <lab-id>`가 allowlist에 있는 컨테이너만 삭제하고 배포 이미지에서 다시 생성한다.

| 항목 | 전환할 소스 | 같은 요청을 재사용할 API | 코드로 강제하는 경계 |
|---|---|---|---|
| LLM01 | `/app/app/secure_coding.py` | 공격 실습과 동일한 `/api/chat` | 모델 호출 전 입력 정책 |
| LLM02 | `/app/app/secure_coding.py` | `/api/labs/llm02/workshop/chat` | system prompt 공개 판단을 서버 데이터 최소화로 교체 |
| LLM04 | `/app/app/secure_coding.py` | `/api/labs/llm04/workshop/chat`, `/api/chat`의 `lab=llm04` | 승인된 출처만 검색 후보에 포함 |
| LLM05 | `/app/app/templates/index.html` | 기존 UI의 같은 모델 응답 재렌더링 | `innerHTML` 대신 `textContent` 사용 |
| LLM06 | `/app/app/main.py` | `/api/labs/llm06/workshop/execute` | Bearer 인증과 도구·객체 인가 |
| LLM08 | `/app/app/secure_coding.py` | `/api/labs/llm08/workshop/search` | vector scoring 전 tenant filter |
| LLM09 | `/app/app/secure_coding.py` | `/api/labs/llm09/workshop/install` | 모델 추천과 분리된 서버 package allowlist |
| LLM10 | `/app/app/secure_coding.py` | `/api/labs/llm10/workshop/chat` | 입력 크기와 생성 token 예산 |
| Day 6 | `/app/secure_coding.py` | `/api/labs/secure-coding/scan` | 모델 호출 전 Presidio 개인정보 탐지·비식별화 |

LLM03·LLM07은 억지로 한 줄 전환 형태로 만들지 않는다. LLM03은 모델 파일 생성·서명·검증·등록의 생명주기 전체가 방어 경계다. LLM07은 시스템 프롬프트에서 비밀과 권한 결정을 제거하고 서버 정책으로 옮기는 아키텍처 문제다. 이 두 항목을 한 줄짜리 `safe=True`로 축소하면 수강생이 실제 방어 범위를 오해한다. LLM09의 한 줄 전환은 패키지를 실제 설치하는 코드가 아니라 설치 직전의 신뢰 경계만 비교하며, 기존 격리 설치 실습은 별도로 유지한다.

`tools/check_secure_coding_pairs.py`는 아홉 표식이 각각 한 번 존재하는지, 취약 호출이 활성화돼 있는지, 안전 호출이 바로 아래에 주석 상태로 있는지 검사한다. 관련 단위 테스트는 같은 API에서 전환 전후의 정책 결과가 실제로 달라지는지 검증한다. `tests/e2e/secure-coding/run-workshop.sh`의 safe 모드는 취약 source로 image를 한 번 build한 뒤 source를 안전 호출로 전환하고 같은 container의 restart만으로 결과가 바뀌는지 검증한다. 설치 계약 테스트는 모든 RAG 컨테이너와 Agent에서 `/app/app` mount가 없고 이미지 source가 쓰기 가능하며 `Network=host` 없이 각 고정 포트가 publish되는지도 검사한다. `tools/toggle_secure_coding_lab.py`는 이 게시자 E2E에서만 사용하는 보조 도구이며 수강생 교재에는 노출하지 않는다. 수강생은 로컬 `vi`에서 두 줄을 직접 바꿔 코드 차이를 읽는다.
LLM02 수강생 흐름은 같은 인증 고객과 같은 공격 프롬프트를 유지한 채 공개 정책의 소유자만 바꾼다. 취약 상태에서는 전체 고객 레코드와 자연어 공개 정책을 모델에 함께 전달하고, 안전 상태에서는 서버 코드가 허용 필드만 선택해 모델에 전달한다. 같은 `run_llm02_policy_chat()`을 workshop endpoint와 `/api/chat`이 공유하므로 두 경로에 같은 데이터 최소화가 적용된다. 실습이 끝나면 `reset-lab llm02`가 `lab-data-rag`를 공개 이미지에서 재생성해 다음 LLM04 실습이 취약 기준선에서 시작하게 한다. `/api/labs/llm02/vulnerable/chat`과 `/api/labs/llm02/safe/chat`은 게시자 회귀 검증용 계약이며 수강생의 코드 전환 경로가 아니다.

LLM04도 `run_llm04_policy_chat()`이 출처 필터를 한 번 선택한 뒤 `run_llm04_chat()`을 호출한다. 전용 workshop endpoint와 8010 UI의 `/api/chat`은 이 함수를 공유하므로 주석 전환이 두 경로에 동시에 적용된다. UI의 `lab` 값은 `llm02`와 `llm04`만 허용하는 기능 식별자이며 인증이나 문서 승인 상태를 결정하지 않는다. 문서 주입과 목록도 전용 `/api/labs/llm04/documents`를 사용해 별도 UI corpus가 생기지 않는다.

시큐어 코딩으로 바꾼 source는 같은 컨테이너를 재시작해도 유지된다. 배포 이미지의 취약 기준선으로 돌아가는 allowlist ID는 LLM01 `reset-lab llm01`, LLM02 `reset-lab llm02`, LLM04 `reset-lab llm04`, LLM05 `reset-lab llm05`, LLM06 `reset-lab llm06`, LLM08 `reset-lab llm08`, LLM09 `reset-lab llm09`, LLM10 `reset-lab llm10`이다. 각 ID는 수강생의 `~/work`를 지우지 않고 해당 컨테이너만 재생성하며, LLM10만 대기 중인 생성 작업을 끊기 위해 Ollama restart를 함께 수행한다.
