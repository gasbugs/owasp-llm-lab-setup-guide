# 취약 코드와 안전 코드를 같은 호출 지점에서 전환하는 실습

이 문서는 NodeGoat 방식의 보안 코딩 실습이 실제로 연결되는 소스와 API를 정의한다. 각 전환 지점은 `NODEGOAT-LAB`, `VULNERABLE-ACTIVE`, `SAFE-ENABLE` 표식을 사용한다. `install-lab.sh`는 이미지의 source tree를 역할별 `/home/ubuntu/work/runtime-src/<컨테이너>/app`에 준비하고 실제 컨테이너의 `/app/app`에 bind mount한다. 수강생은 `podman exec -it <컨테이너> vi <파일>`로 공격에 사용한 컨테이너의 source를 편집한다. 활성화된 취약 호출 한 줄을 주석 처리하고 바로 아래 안전 호출 한 줄을 주석 해제한 뒤 정확한 `podman restart <컨테이너>` 명령으로 변경을 적용한다. Quadlet이 컨테이너를 재생성하더라도 역할별 host source가 다시 mount되므로 변경이 유지된다.

| 항목 | 전환할 소스 | 같은 요청을 재사용할 API | 코드로 강제하는 경계 |
|---|---|---|---|
| LLM01 | `/app/app/secure_coding.py` | 공격 실습과 동일한 `/api/chat` | 모델 호출 전 입력 정책 |
| LLM02 | `/app/app/secure_coding.py` | `/api/labs/llm02/workshop/chat` | 서버 인증 신원과 최소 데이터 context |
| LLM04 | `/app/app/secure_coding.py` | `/api/labs/llm04/workshop/chat` | 승인된 출처만 검색 후보에 포함 |
| LLM05 | `/app/app/templates/index.html` | 기존 UI의 같은 모델 응답 재렌더링 | `innerHTML` 대신 `textContent` 사용 |
| LLM06 | `/app/app/main.py` | `/api/labs/llm06/workshop/execute` | Bearer 인증과 도구·객체 인가 |
| LLM08 | `/app/app/secure_coding.py` | `/api/labs/llm08/workshop/search` | vector scoring 전 tenant filter |
| LLM09 | `/app/app/secure_coding.py` | `/api/labs/llm09/workshop/install` | 모델 추천과 분리된 서버 package allowlist |
| LLM10 | `/app/app/secure_coding.py` | `/api/labs/llm10/workshop/chat` | 입력 크기와 생성 token 예산 |
| Day 6 | `/app/secure_coding.py` | `/api/labs/secure-coding/scan` | 모델 호출 전 Presidio 개인정보 탐지·비식별화 |

LLM03·LLM07은 억지로 한 줄 전환 형태로 만들지 않는다. LLM03은 모델 파일 생성·서명·검증·등록의 생명주기 전체가 방어 경계다. LLM07은 시스템 프롬프트에서 비밀과 권한 결정을 제거하고 서버 정책으로 옮기는 아키텍처 문제다. 이 두 항목을 한 줄짜리 `safe=True`로 축소하면 수강생이 실제 방어 범위를 오해한다. LLM09의 한 줄 전환은 패키지를 실제 설치하는 코드가 아니라 설치 직전의 신뢰 경계만 비교하며, 기존 격리 설치 실습은 별도로 유지한다.

`tools/check_secure_coding_pairs.py`는 아홉 표식이 각각 한 번 존재하는지, 취약 호출이 활성화돼 있는지, 안전 호출이 바로 아래에 주석 상태로 있는지 검사한다. 관련 단위 테스트는 같은 API에서 전환 전후의 정책 결과가 실제로 달라지는지 검증한다. `tests/e2e/secure-coding/run-workshop.sh`의 safe 모드는 취약 source로 image를 한 번 build한 뒤 source를 안전 호출로 전환하고 container restart만으로 결과가 바뀌는지 검증한다. 설치 계약 테스트는 역할별 source tree bind가 모든 RAG 컨테이너와 Agent에 생성되는지도 검사한다. `tools/toggle_secure_coding_lab.py`는 이 게시자 E2E에서만 사용하는 보조 도구이며 수강생 교재에는 노출하지 않는다. 수강생은 컨테이너의 `vi`에서 두 줄을 직접 바꿔 코드 차이를 읽는다.
