# 취약 코드와 안전 코드를 같은 호출 지점에서 전환하는 실습

이 문서는 NodeGoat 방식의 보안 코딩 실습이 실제로 연결되는 소스와 API를 정의한다. 각 전환 지점은 `NODEGOAT-LAB`, `VULNERABLE-ACTIVE`, `SAFE-ENABLE` 표식을 사용한다. 수강생은 활성화된 취약 호출 한 줄을 주석 처리하고 바로 아래 안전 호출 한 줄을 주석 해제한 뒤 같은 이미지 태그를 다시 빌드한다.

| 항목 | 전환할 소스 | 같은 요청을 재사용할 API | 코드로 강제하는 경계 |
|---|---|---|---|
| LLM01 | `docker/vuln-rag/app/main.py` | `/api/labs/llm01/workshop/chat` | 모델 호출 전 입력 정책 |
| LLM02 | `docker/vuln-rag/app/main.py` | `/api/labs/llm02/workshop/chat` | 서버 인증 신원과 최소 데이터 context |
| LLM04 | `docker/vuln-rag/app/main.py` | `/api/labs/llm04/workshop/chat` | 승인된 출처만 검색 후보에 포함 |
| LLM05 | `docker/vuln-rag/app/templates/index.html` | 기존 UI의 같은 모델 응답 재렌더링 | `innerHTML` 대신 `textContent` 사용 |
| LLM06 | `docker/vuln-agent/app/main.py` | `/api/labs/llm06/workshop/execute` | Bearer 인증과 도구·객체 인가 |
| LLM08 | `docker/vuln-rag/app/main.py` | `/api/labs/llm08/workshop/search` | vector scoring 전 tenant filter |
| LLM10 | `docker/vuln-rag/app/main.py` | `/api/labs/llm10/workshop/chat` | 입력 크기와 생성 token 예산 |

LLM03·LLM07·LLM09는 억지로 한 줄 전환 형태로 만들지 않는다. LLM03은 모델 파일 생성·서명·검증·등록의 생명주기 전체가 방어 경계다. LLM07은 시스템 프롬프트에서 비밀과 권한 결정을 제거하고 서버 정책으로 옮기는 아키텍처 문제다. LLM09는 외부 정보와 패키지의 출처 검증, 격리, 실제 존재 여부 확인이 결합된 workflow다. 이 세 항목을 한 줄짜리 `safe=True`로 축소하면 수강생이 실제 방어 범위를 오해한다.

`tools/check_secure_coding_pairs.py`는 일곱 표식이 각각 한 번 존재하는지, 취약 호출이 활성화돼 있는지, 안전 호출이 바로 아래에 주석 상태로 있는지 검사한다. `tests/unit/test_secure_coding_api.py`는 같은 API에서 전환 전후의 정책 결과가 실제로 달라지는지 검증한다. `tools/toggle_secure_coding_lab.py`는 E2E 게시자가 두 상태를 자동 빌드할 때만 사용하는 보조 도구이며 수강생 교재에는 노출하지 않는다. 수강생은 편집기에서 두 줄을 직접 바꿔 코드 차이를 읽는다.
