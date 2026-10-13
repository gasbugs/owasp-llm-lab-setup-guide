# UI report display fixtures

These sanitized historical responses exercise Control Center rendering and
same-tab restoration. They are never passed to a verifier as execution evidence.
`manifest.json` requires coverage of P00–P23 and records each response type.

- `recorded-native-response`: responses captured from the running platform or
  earlier native/AWS checks. Internal H identifiers use the public API's H→P
  conversion. Credentials and bearer values are removed; case decisions remain.
- P02–P04 stored runs are older than the verifier's allowed freshness window.
  Their read-only verifier responses contain ERR and zero verified cases. The
  browser test checks that restoration preserves this absence of evidence.
- `display-contract-fixture`: P02/P03/P04 positive display samples built from
  server-owned case definitions (22/19/27). Each sample says it is display-only;
  it does not demonstrate a successful learner implementation or AWS call.

Run all three UI gates on checkout assets, without a model or cloud resource:

```bash
python tests/browser/check_guided_ui_regressions.py --output /tmp/guided-ui-check
```

Use `--base-url http://127.0.0.1:28097` to check the existing platform instead.
Both modes preview/cache reports only. They never call a grading endpoint,
change completion, or replay a resource operation. Native implementation gates
remain separate jobs in `guided-practice-e2e.yml`.
