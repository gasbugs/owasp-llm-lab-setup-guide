# 08챕터 6.5 연습문제: 제로베이스 빌드

이 연습은 완성된 로컬 이미지와 AWS Bedrock 자원을 전제로 하지 않습니다. 현재 Git 체크아웃의 Containerfile에서 서비스 여섯 개를 직접 빌드하고, 결정적 Bedrock 대역 서버를 사용해 Guardrail 제어 평면을 한 단계씩 연결합니다. 따라서 AWS 자격 증명과 과금 없이 빌드·실행·판정·정리까지 반복할 수 있습니다.

## 1. 학습 목표

- NeMo input/output rail, Presidio, Privacy Spoke, Policy Hub의 책임을 구분한다.
- upstream이 없는 서비스가 `503`으로 fail-closed 되는 것을 확인한다.
- 정상 요청은 모델까지 전달되고 prompt injection은 모델 호출 전에 차단되는지 구조화된 JSON으로 판정한다.
- 레지스트리의 완성 이미지를 실행하는 대신 현재 소스로 이미지를 직접 만든다.

## 2. 준비물과 범위

Linux 또는 WSL2에서 저장소 루트로 이동합니다. `podman`, `curl`, `jq`, `ss`(`iproute2`)가 필요하며 Podman이 rootless 사용자로 실행 가능해야 합니다. 최초 빌드는 base image와 Python 패키지를 내려받으므로 인터넷 연결과 여유 디스크가 필요합니다.

실습은 다음 loopback 포트만 사용합니다.

| 포트 | 단계별 서비스 |
|---:|---|
| 28091 | Presidio |
| 28092 | NeMo dialog rail |
| 28093 | Privacy Spoke |
| 28094 | Policy Hub |
| 28096 | 결정적 Bedrock 대역 |

기존 Module 08의 18093~18096 서비스, AWS 리소스, 공통 `lab-ollama`는 변경하지 않습니다. 위 포트나 전용 컨테이너 이름이 이미 사용 중이면 덮어쓰지 않고 중단합니다.

## 3. 소스 확인

```bash
# [Linux/WSL2] 저장소 루트
set -euo pipefail
test -f llm-security-control-plane/deploy/run-exercise-6-5.sh
test -f llm-security-control-plane/versions.lock.yaml
podman info >/dev/null
```

이미지를 먼저 살펴보고 싶다면 다음 파일을 순서대로 읽습니다.

```bash
sed -n '1,220p' llm-security-control-plane/versions.lock.yaml
sed -n '1,180p' llm-security-control-plane/deploy/build-images.sh
sed -n '1,260p' llm-security-control-plane/tests/e2e-learning-sequence.sh
```

## 4. 처음부터 직접 빌드

빌드와 실행을 분리하려면 `--build-only`를 사용합니다. 네 개의 Chapter 08 제어 평면 이미지와 단계별 비교에 쓰는 NeMo·Presidio 이미지 두 개를 모두 현재 체크아웃에서 만듭니다.

```bash
# [Linux/WSL2] 저장소 루트
bash llm-security-control-plane/deploy/run-exercise-6-5.sh --build-only
```

마지막 출력은 다음과 같아야 합니다.

```text
module08-exercise-6.5=BUILD_READY
```

빌드 결과를 직접 확인합니다.

```bash
podman images --format '{{.Repository}}:{{.Tag}}' \
  | grep -E '^localhost/(llm-security-|day6-presidio)'
```

## 5. 단계별 실습 실행

아래 명령은 빌드를 다시 수행한 뒤 전용 네트워크에서 순서대로 서비스를 조립합니다. 캐시가 있으면 변경되지 않은 layer는 재사용합니다.

```bash
# [Linux/WSL2] 저장소 루트
bash llm-security-control-plane/deploy/run-exercise-6-5.sh \
  | tee /tmp/module08-exercise-6-5.log
```

실행 중 자동 판정하는 핵심 관찰점은 다음과 같습니다.

1. 결정적 Bedrock 대역과 NeMo dialog rail을 연결한다.
2. 정상 input은 허용하고 injection input과 비밀이 든 output은 차단한다.
3. upstream이 없는 Presidio 요청은 `503`, `decision=infra`, `upstream_called=false`인지 확인한다.
4. NeMo를 연결한 뒤 PII는 비식별화하고 정상 요청만 모델까지 전달한다.
5. Privacy Spoke와 Policy Hub를 직접 연결하고 정상/공격 요청의 결정을 비교한다.

성공 계약은 로그의 마지막 두 줄입니다.

```text
module08-learning-sequence=PASS
module08-exercise-6.5=PASS
```

응답 문장 자체가 아니라 `application_decision`, `blocking_reason`, `upstream_called`, `stage_order`를 판정 기준으로 사용합니다.

## 6. 실패 진단과 재실행

스크립트는 성공과 실패 모두에서 자신이 만든 컨테이너와 전용 네트워크를 trap으로 정리합니다. 실패 지점은 `/tmp/module08-exercise-6-5.log`에서 확인합니다.

```bash
grep -E '\[FAIL\]|service did not become ready|Error:|curl:' \
  /tmp/module08-exercise-6-5.log || true
podman ps --all
```

포트 충돌이면 해당 listener의 소유자를 확인하고 종료한 뒤 다시 실행합니다. 다른 실습 컨테이너를 임의로 삭제하지 마십시오.

```bash
ss -ltnp | grep -E ':(28091|28092|28093|28094|28096)\b' || true
```

빌드 이미지까지 지우는 것은 필수가 아닙니다. 반복 실습 시 빌드 cache로 사용합니다.
