# Lab Contract

`contracts/labs/<lab-id>.json`은 setup의 실제 fixture·정책·runner와 course BOOK을 잇는
기계 판독형 정본이다. `schema.json`은 input scanner와 output scanner를 구분하며 output
case에는 `input_prompt`와 `simulated_model_output`을 별도 필드로 요구한다.

정적 검사는 다음 명령으로 실행한다.

```bash
python3 tools/lab_contract.py validate
```

실제 환경 runner는 고유 container 이름을 사용하고 정책 확인 event, `podman logs` 원문,
command hash와 raw log hash를 JSONL로 출력한 뒤 container만 정리한다.

```bash
python3 tools/run_lab_contract.py \
  --contract contracts/labs/day6-llm-guard.json \
  --run-id manual-check
```

기존 E2E shell을 재사용하는 `host-script` 계약은 사람이 읽는 진행 로그와 한 줄 JSON
`lab_case` event를 함께 출력할 수 있다. Contract runner는 JSON object event만 원래 순서로
투영해 raw JSONL로 보존하며, 계약의 `runtime.environment`에 선언된 loopback URL과 strict
mode를 명령 identity에 포함한다. Day 5 LLM10은 이 방식으로 기존 부하·복구 E2E와 계약
evidence가 서로 다른 판정 코드를 갖지 않게 한다.

```bash
python3 tools/run_lab_contract.py \
  --contract contracts/labs/day5-llm10-unbounded-consumption.json \
  --run-id manual-llm10-check
```

비용이 큰 lifecycle은 `runtime.targeted_stages`에 stage와 그 stage가 방출해야 하는
case ID를 선언할 수 있다. Host runner는 `--stage`를 받아 선택 단계만 실행하고, 필요한
선행 artifact가 없으면 전체 lifecycle로 몰래 fallback하지 않고 실패한다.

```bash
python3 tools/run_lab_contract.py \
  --contract contracts/labs/day4-llm03-real-model-lifecycle.json \
  --run-id manual-signing-check \
  --stage signing
```

`runtime.cache_inputs`에는 Dockerfile·dataset 같은 파일과 model·GGUF·도구 revision을
기록한다. Publisher loop는 여기에 contract, runner, policy, learner command, image digest,
instance type과 GPU identity를 더해 content-addressed evidence key를 만든다. 날짜가 같다는
이유만으로 evidence를 재사용하지 않는다.

수집한 stdout 전체를 다시 검사할 때는 다음 명령을 사용한다. 이 검사는 summary의 hash를
신뢰하지 않고 `guard_scan`과 `guard_suite_summary` 원문 바이트에서 runtime log hash를
재계산하며 policy source, case coverage와 필수 correlation field도 함께 확인한다.

```bash
python3 tools/lab_contract.py verify-evidence \
  contracts/labs/day6-llm-guard.json path/to/raw.stdout.jsonl
```

새 실습은 schema를 복사하지 말고 새 contract만 추가한다. 실제 입력이나 정확한 생성식,
정상·위험 pair, correlation field, 최소 reset, process stop, evidence 정책과 EC2 필요 여부를
빠짐없이 기록한다.

수강생 reset 규칙을 course checker와 공유해야 하는 lab은 `state.reset`에 `command`, 적용
문서 `documents`, 내장 확인 URL, 문서에 나타날 횟수, 상태 변경 요청 pattern·횟수와 실행
순서를 구조화해 선언한다. 설명 문자열만 있는 기존 계약은 그대로 허용하지만, 구조화 reset을
선언한 뒤에는 course의 과도기 fallback과 값이 하나라도 다르면 교차 저장소 gate가 실패한다.
