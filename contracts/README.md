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
