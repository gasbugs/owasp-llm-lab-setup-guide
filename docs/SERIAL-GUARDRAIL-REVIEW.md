# 직렬 가드레일 검토 연습 실행 지원

교재 `08-llm-guardrails/06.5-serial-guardrail-review-exercise.md`를 앞 차시의 실행 상태나 AWS 자원 없이 처음부터 다시 풀기 위한 실행 환경입니다. 문제와 풀이 설명은 교재가 정본이며, 이 저장소는 소스 빌드와 결정적 판정을 담당합니다.

## 처음부터 빌드

Linux 또는 WSL2에 `podman`, `curl`, `jq`, `ss`(`iproute2`)가 필요합니다.

```bash
cd ~/owasp-llm-lab-setup-guide
podman info >/dev/null
bash llm-security-control-plane/deploy/run-exercise-6-5.sh --build-only
```

이 명령은 현재 체크아웃에서 Bedrock Gateway, Presidio Privacy Spoke, NeMo Policy Hub, Application Gateway 이미지를 모두 빌드합니다. 성공 출력은 `serial-guardrail-review=BUILD_READY`입니다.

## 새 정책 파일을 직접 작성

```bash
mkdir -p ~/work/serial-guardrail-review
chmod 0755 ~/work/serial-guardrail-review
vi ~/work/serial-guardrail-review/control-plane-policy.yaml
chmod 0644 ~/work/serial-guardrail-review/control-plane-policy.yaml
```

기존 정책을 복사하지 않습니다. 브라우저에서 [GitHub Control Plane 정책 정본](https://github.com/gasbugs/owasp-llm-lab-setup-guide/blob/main/llm-security-control-plane/policies/control-plane-policy.yaml)을 열고 `execution`, `assurance_profiles`, `rail_implementations`, `pipeline`, `prohibited_entities` 구조를 참고해 빈 파일에 직접 작성합니다. 실행기는 정책을 대신 생성하거나 수정하지 않습니다.

## 독립 환경에서 풀이 판정

```bash
bash llm-security-control-plane/deploy/run-exercise-6-5.sh \
  --policy-file ~/work/serial-guardrail-review/control-plane-policy.yaml \
  --evidence-dir ~/work/serial-guardrail-review/evidence
```

실행기는 이미 떠 있는 Module 08을 재사용하지 않습니다. 현재 소스를 다시 빌드하고, 전용 loopback 포트 28093·28094·28096에서 결정적 Bedrock 대역, Presidio, Hub를 새로 조립합니다. 정상 입력과 이메일 입력을 보내 다음 구조화된 계약을 검사합니다.

| 입력 | 필수 결과 |
|---|---|
| 정상 입력 | `decision=allow`, `upstream_called=true`, `bedrock_main` 포함 |
| 이메일 입력 | `EMAIL_ADDRESS` 탐지, `decision=block`, `upstream_called=false`, `stage_order=[presidio_input]` |

정답 정책이면 다음 출력으로 끝납니다.

```text
[PASS] normal input reached bedrock_main
[PASS] email input stopped at presidio_input before every model call
serial-guardrail-review=PASS
```

기본 정책처럼 이메일을 가린 뒤 모델 호출을 계속하면 실패합니다. 모델의 답변 문구는 판정하지 않습니다. 성공과 실패 모두에서 실행기가 만든 `serial-guardrail-review-*` 컨테이너와 네트워크만 자동 정리하며, 다른 실습과 AWS 자원은 변경하지 않습니다.

통과한 두 원본 응답은 `evidence/normal.json`과 `evidence/email.json`에 남습니다. 자동 PASS만 보지 말고 직접 성공 기준을 대조합니다.

```bash
jq '{entity_types:.guardrail.stages[0].entity_types,decision:.guardrail.decision,blocking_reason:.guardrail.blocking_reason,upstream_called:.guardrail.upstream_called,stage_order:.guardrail.stage_order}' \
  ~/work/serial-guardrail-review/evidence/normal.json \
  ~/work/serial-guardrail-review/evidence/email.json
```
