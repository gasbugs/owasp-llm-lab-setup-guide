# Security telemetry collection contract

Scope: Tenant 02 integrated Application and its local MTL pipeline. Preserve the
single user entrypoint, server-side security decisions, existing lab requests,
and bounded WSL storage. This is an investigation-grade lab baseline, not a
claim of tamper-proof, highly available enterprise audit storage.

## Required evidence

Every authentication and completed chat decision must retain an event ID,
request ID, valid trace ID, UTC occurrence time, service/release identity,
authentication action, pseudonymous subject when known, policy/mode/profile,
classification, Application authentication/authorization/retrieval stage records
and hit/authorized chunk counts, stage name/order, decision/reason, duration and actual upstream
state where available. Record retrieval failures and invalid hub contracts;
unknown downstream state must remain unknown rather than assert no execution.
Never export prompts, replies, passwords, access/refresh tokens, raw user names,
client IPs or retrieval chunks as incident telemetry. Authorized identity lookup
and original document handling remain separate from this telemetry store.

Metrics use bounded engine/direction/decision/route/status labels, not IDs or
prompt contents. Distinguish per-stage decisions from completed requests. Count
reported guard model calls once per completed request. Keep durations, HTTP
failures, model tokens/cost and delivery backlog/failures observable. Trace the
actual HTTP flow; preserve request and trace IDs in log attributes, not metric
labels.

## Adversarial plan and acceptance

| Risk (1–5) | Improvement | Acceptance |
|---|---|---|
| 5: a failure returns before monitoring | Observe every exit, including authentication and validation failures | deterministic success/401/422/authorization/block/upstream-error/invalid-contract cases have metadata-only events |
| 5: collector unavailable loses events | bounded Application SQLite outbox; durable Monitor log backlog; Alloy persistent exporter queues | restart producers/Alloy while backend is unavailable; replay reaches storage with same IDs |
| 4: retries double count | stable event ID, receiver deduplication, model count only on summary | redelivery of same ID adds no second metric or incident row |
| 4: caller spoofs trace context or disables sampling | strip public traceparent/tracestate/baggage before instrumentation | fresh server Trace ID despite caller flags=00 |
| 4: secrets become telemetry | producer allowlist and pseudonymous identity; receiver attribute allowlist | planted prompt/token/password/email are absent from outgoing events and stored logs |
| 4: false evidence of no upstream side effect | retain actual stage outcomes and explicit unknown on transport/contract errors | timeout is ERR/unknown, not proof of prevented model call |
| 4: dropping telemetry is invisible | backlog age/count, delivery failures/rejections, collector queue/export failures and absent targets | rule validation and emitted metric identity tests; deliberate outage recovers |
| 4: storage grows without bound | bounded pending queue; explicit lab retention; retention applies to all signal stores | queue overflow is surfaced, and retention configuration validates |

Refined plan: do not fail open security decisions because telemetry is unavailable;
do not make logging a synchronous remote dependency; do not label a persistent
queue as exactly-once or loss-free. Acknowledgement boundaries are explicit:
Application -> Monitor DB -> Monitor log delivery -> Alloy queue -> backend.
Alloy has no volatile batch processor before its persistent exporter queues: an
HTTP acknowledgement must not commit only to a memory batch. Acceptance includes
a direct receiver acknowledgement followed immediately by SIGKILL during a Loki
outage, then replay of the same incident ID. Trace SDK batches remain a separate
pre-ingress limitation.
Monitor deduplicates producer retries. Backend retries can still duplicate logs;
use event_id for investigations. Local disk loss and storage exhaustion remain
visible residual risks; replication, legal retention, TLS/identity at collector
edges and externally immutable audit storage require a production deployment
profile, not a claim about this single-host lab.

## References

- https://opentelemetry.io/docs/collector/resiliency/
- https://opentelemetry.io/docs/security/handling-sensitive-data/
- https://grafana.com/docs/alloy/latest/reference/components/otelcol/otelcol.exporter.otlphttp/
- https://grafana.com/docs/alloy/latest/reference/components/otelcol/otelcol.storage.file/

Alloy v1.18.0 requires `--stability.level=public-preview` for file storage.
The pinned component is syntax-validated and outage-tested; production adoption
requires explicit assessment of this component stability and retention policy.
Application and Monitor queues are bounded to 10,000 events each. Monitor audit
rows and MTL stores retain a 24-hour lab window; committed pending logs are
exempt from Monitor row cleanup. Increase the window for production incident
response before relying on this stack for longer investigations.

## Verified implementation (2026-10-07)

- Python 3.12 unit suite: 1,722 tests, one existing skip.
- Actual Application/Monitor images: six boundary tests and two log delivery tests.
- `tests/e2e/security-monitoring/check_mtl_reliability.py`: actual Loki, Tempo,
  Prometheus and pinned Alloy; producer/outbox/collector/backend restart cases
  and immediate receiver acknowledgement/SIGKILL replay passed. Correlation request `e07be988-5943-4cc3-8e55-dfbb3727061f`, Trace
  `1f57a107e49f0fdb90e90ce8accea390`. This uses a fixture Hub, not AWS inference.
- Existing Module 09 Docker observability E2E: normal/block/redaction,
  Log/Trace, firing/resolved alert, collector failure drill and Grafana passed
  twice with `USE_REAL_BEDROCK=false RUN_FAILURE_DRILL=true`.
- Alloy v1.18.0 configuration validates with the preview flag; Prometheus
  v3.5.0 validates all 15 alert rules. Existing guard policies and payloads
  are unchanged; these checks establish collection behavior, not model safety.
