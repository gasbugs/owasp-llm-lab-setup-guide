# Day 3 and LLMGoat browser validation

This harness records three mandatory UI observations that API-only tests cannot
prove:

1. The Day 3 RAG UI renders one model-produced iframe through the unsafe DOM
   sink, causing a real loopback `GET /account/delete`.  The identical cached
   reply is then replayed through the text sink and must cause no new
   `/api/chat`, iframe, or receiver request.
2. The pinned DVLA Streamlit UI must show an intermediate
   `GetUserTransactions` action with argument `2` and its seeded user-2
   observation (`PlutoniumPurchase`, `FLAG:plutonium-256`).
3. The LLMGoat A01 page must submit exactly one `/api/a01-prompt-injection`
   request, render the exact returned `response`, and make the solved overlay
   and sidebar state agree with the returned boolean `solved` value.  Solved
   itself is an observation, not a pass requirement.

Missing intermediate evidence never passes.  DVLA failures are classified as
`F-GENERATION` (no target action with argument 2) or `F-EXECUTION` (the target
action appeared but its observation did not).  One primary prompt and at most
one corrected retry are used.  The RAG model gets at most four prompts.

## Install locally before starting EC2

The browser runs on the instructor machine; only the three HTTP services are
forwarded from EC2.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r tests/browser/requirements.txt
python -m playwright install chromium
```

If Google Chrome is already installed, the browser download can be skipped and
the run command can use `--browser-channel chrome` instead.

## Open the three SSM forwards

Run these in three terminals and keep all sessions open.  The instance security
group does not need inbound application ports.

```bash
aws ssm start-session --target "$INSTANCE_ID" \
  --document-name AWS-StartPortForwardingSession \
  --parameters 'portNumber=["8011"],localPortNumber=["18011"]'

aws ssm start-session --target "$INSTANCE_ID" \
  --document-name AWS-StartPortForwardingSession \
  --parameters 'portNumber=["8501"],localPortNumber=["18501"]'

aws ssm start-session --target "$INSTANCE_ID" \
  --document-name AWS-StartPortForwardingSession \
  --parameters 'portNumber=["5000"],localPortNumber=["15000"]'
```

Confirm all forwards before spending model time:

```bash
curl -fsS http://127.0.0.1:18011/healthz | jq -e \
  '.ok == true and .default_scenario == "day3"'
curl -fsS http://127.0.0.1:18501/_stcore/health | grep -qx ok
curl -fsS http://127.0.0.1:15000/api/model_status \
  | jq -e '.model_busy == false'
```

## Run

```bash
python tests/browser/run_day3_ui.py \
  --rag-url http://127.0.0.1:18011 \
  --dvla-url http://127.0.0.1:18501 \
  --llmgoat-url http://127.0.0.1:15000 \
  --browser-channel chromium
```

Use `--headed` only for troubleshooting.  All browser traffic outside
loopback is blocked.  A loopback receiver is allocated on an ephemeral port,
and both the receiver and browser are closed in `finally` even when a check
fails.  LLM05, DVLA, and LLMGoat each record an independent result so an early
failure cannot silently remove the remaining UI evidence.

The command exits zero only when all three UI contracts pass.  Evidence is written
under `tests/browser/results/<timestamp>/` by default:

```text
result.json                   overall fail-closed verdict
network-events.json           browser requests/responses (POST bodies hashed)
receiver-events.json          exact loopback receiver events
llm05-api-trial-*.json        raw RAG JSON responses
llm05-unsafe*.{json,png}      unsafe DOM and screenshot
llm05-safe-replay*.{json,png} safe replay DOM and screenshot
dvla-attempt-*.{json,png}     intermediate status blocks and screenshot
llmgoat-api-response.json     raw A01 API JSON observed by Playwright
llmgoat-ui.json               response/solved-state consistency checks
llmgoat-a01.png               full-page A01 screenshot
sha256sums.json               hashes for every evidence file
```

Copy this local evidence directory to the retained validation bundle before
destroying EC2.  The output directory is ignored by Git; publish only a
sanitized summary and hashes.
