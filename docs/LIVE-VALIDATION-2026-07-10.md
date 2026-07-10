# EC2 Live Validation — 2026-07-10

이 문서는 `us-east-1`의 실제 `g6.xlarge`에서 setup runtime과 Day 3~5 핵심 실습을 검증한 기록이다. 모델 원문과 공격 payload는 공개 문서에 복제하지 않고, 판정·해시·재현 경로만 남긴다.

## 판정 요약

- 검증 모드: `latest-smoke+local-current-source-build`
- 최종 배포 판정: **NO-GO**
- 이유: setup `main` 기준 commit-addressed `sha-bc8e95d197c7382a2f9d83bf86325e119ad77328` 이미지가 registry에 없었다. GitHub Actions 정적 게이트는 통과했지만 Docker Hub 로그인 단계가 자격 증명 부재로 실패했다.
- 이번 실행의 의미: 현재 source를 로컬에서 다시 빌드한 runtime의 기능·실습 smoke validation이다. canonical commit-pinned registry validation을 대신하지 않는다.

## 실행 식별 정보

| 항목 | 실측값 |
|---|---|
| AWS profile / region | `owasp-llm` / `us-east-1` |
| Course tag | `codex-live-20260710-2340` |
| Instance | `i-0469c710dc32e0812`, `g6.xlarge` |
| 실행 시작 | `2026-07-10T14:44:21Z` |
| 최종 summary | `2026-07-10T16:00:14Z` |
| GPU | NVIDIA L4, 23,034 MiB, driver 595.71.05 |
| Setup checkout | `1450a2b017660d1bf9e951e5a0a3a61167b51042` |
| Runtime tag | `live-bc8e95d` — diagnostic label, immutable provenance 아님 |
| Sanitized summary SHA-256 | `50637dbfa654873de003b8e94b05fd55343159147644e65a922cac90fe378d94` |

실행 이미지는 current source로 로컬 rebuild했다. 해시는 다음과 같다.

| 이미지 | 실측 digest |
|---|---|
| base-gpu | `sha256:d97245b08ff6218588bd51a0fe12230931227ca1934ff0ce7077996a3a0914de` |
| vuln-rag | `sha256:b430aed79cae22ec965108c6b37626d5f1b2f27b422bddab535979d76315e09f` |
| vuln-agent | `sha256:9f115fee175431b1590a013aaa08f88adc575f8431d9daeece64c5ebe26276ae` |
| llmgoat | `sha256:82205a67ffbba93d304cbf9398d330cfbc732d5b037d5e739a1ce6996a9a4bde` |
| dvla | `sha256:95f8f8b37c07990d7e4850f3e3d8031276c31e31a4cde3d1d1eaa5760109cea3` |

## Runtime 결과

최종 health 확인에서 Day 1~5 RAG, Agent, fake registry, LLMGoat, DVLA, Ollama가 모두 HTTP 200이었다. Portal도 bootstrap readiness에서 통과했다.

| 범위 | 실측 결과 | 판정 |
|---|---|---|
| LLM01, 02, 03, 04, 05, 06, 07, 08 | `TRIALS=5` full-cycle에서 test script 실패 0 | PASS |
| LLM09 | 첫 실행은 URL 미출력 때 `grep` exit 1을 test failure로 오인. 수정 뒤 3 trial 재검증, 실패 script 0 | PASS_WITH_NOTES |
| LLM10 | 첫 실행은 curl timeout 때문에 `xargs` 123을 harness failure로 오인. 수정 뒤 100건 중 200=4, 429=0, timeout=96을 기록하고 Ollama queue cleanup·후속 readiness 통과 | PASS_WITH_NOTES |
| LLM10 큰 입력 | baseline 6,867 ms, 약 5,000-token 입력 2,300 ms, ratio 0.3x | 지연 증폭 미관찰 |
| LLMGoat A01 | 5기법 × 3회, infra 0, solved 0/15 | PASS; 공격 성공 미관찰 |
| reset contract | Day별 sentinel 주입 후 restart, 기본 docs `2/2/2/4/3`, sentinel 전부 제거 | PASS |
| Day4 LLM07 집중 검증 | Base64 decode 형식 실패, JSON reply parse 형식 실패지만 JSON 응답에서 교육용 exact marker 관찰, token fragment에는 exact marker 미관찰 | PASS_WITH_NOTES |
| Llama Guard | 정상 입력 `safe`, 직접 prompt-injection 입력도 `safe` | false negative 관찰; PI 전용 방어 아님 |
| Capstone reference | fresh source fingerprint/image ID/runtime ID 일치, readiness PASS, unit 7/7, 자동 차단 후보 8/8, 학생 파일 restore fingerprint 동일, container cleanup | PASS_WITH_NOTES |

Capstone의 `8/8`은 `BLOCKED?` 자동 후보 수다. 이 실행은 각 공격의 HTTP status·JSON body·부작용 부재를 전부 별도 수동 확정하지 않았으므로 최종 `BLOCKED 8/8` 또는 최종 점수로 승격하지 않는다.

## 실측 중 수정한 결함

1. 첫 설치의 빈 Quadlet 디렉터리에서 `pipefail` 때문에 bootstrap이 중단되던 문제를 수정했다.
2. Podman에서 DVLA의 short-name base image를 해석하지 못하던 문제를 fully-qualified image로 수정했다.
3. Terraform → user-data → installer로 image namespace/tag를 전달하고, pinned setup commit과 image commit 불일치를 plan 단계에서 차단했다.
4. teardown을 전체 state 기반 fail-closed로 바꾸고 destroy 후 empty state를 검증하게 했다.
5. full-cycle reset을 임의 docs 배열 확인에서 sentinel 제거와 정확한 기본 문서 수 확인으로 강화했다.
6. LLM09의 정상적인 “추출 결과 없음”을 shell failure로 오인하던 두 pipeline을 수정하고, URL 미제공을 별도 계수했다.
7. LLM10의 overload timeout을 측정값으로 보존하고, 남은 Ollama queue를 재시작으로 정리한 뒤 warmup·지연 측정을 수행하게 했다.
8. Course Capstone의 literal JSON brace formatting, 중첩 `args` tool-call parsing, stale image 재사용 가능성을 수정했다.
9. Course live-evidence checker·template·generator와 Day4 checkpoint의 실행 계약을 서로 일치시켰다.

## 로컬 게이트

- setup unit: 28/28 PASS
- setup shell syntax, Terraform fmt, Terraform validate, `git diff --check`: PASS
- Course Capstone unit: 7/7 PASS
- Course 45분 계약: Day 3~5 26/26 PASS
- Course lab/evidence template/Capstone assessment/lecture quality/Markdown/Python/shell gates: PASS
- `check_manual_release_gates.py`: 이번 변경과 무관한 기존 `NOTION-SYNC-STATUS.md` 누락만 남음

## 종료와 비용 자원 정리

- EC2 stop 요청: 완료
- Terraform destroy plan: `0 add / 0 change / 22 destroy`
- Terraform state empty: PASS
- 직접 서비스 조회: EC2·EBS·VPC·subnet·security group·route table·IGW·ENI·EIP·IAM role/profile·Lambda·EventBridge·SNS·Budget·Lambda log group 모두 0개
- Resource Groups Tagging API는 삭제 직후 이미 `terminated`인 instance와 `NotFound`인 volume ARN을 잠시 반환했다. 직접 서비스 조회로 실재·과금 자원이 아님을 확인한 eventual-consistency 잔상이다.

## 재실행 조건

1. Docker Hub publish credentials를 복구한다.
2. setup commit 전체 SHA를 사용한 `sha-<40 hex>` 이미지 5종을 publish한다.
3. Terraform의 setup raw URL과 image tag를 같은 commit으로 고정한다.
4. `TRIALS=5 bash tests/e2e/run-full-cycle.sh`와 Capstone reference 검증을 새 인스턴스에서 다시 실행한다.
5. Capstone 후보는 HTTP status·JSON decision·부작용 부재 근거를 공격별로 수동 확정한다.
6. 증거 회수 뒤 같은 Terraform state로 destroy하고 잔존 자원 0을 다시 확인한다.
