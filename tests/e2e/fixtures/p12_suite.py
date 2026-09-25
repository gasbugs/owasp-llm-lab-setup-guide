"""Publisher-owned synthetic product cases; never copied into learner images."""
DOCS = [{"document_id": "account", "tenant": "team-a", "text": "계정 복구: 지원 담당자에게 문의하세요."},
        {"document_id": "review", "tenant": "team-a", "text": "검색검사: PIPELINE_TEST_DENY"},
        {"document_id": "output", "tenant": "team-a", "text": "답변검사: 합성 테스트 문서."},
        {"document_id": "foreign", "tenant": "team-b", "text": "계정 복구: 다른 팀의 문서."}]
CASES = [("normal", "계정 복구", "reader", 200, 9, 1),
         ("input-pii", "계정 복구 learner@example.com", "reader", 200, 9, 1),
         ("invalid-credential", "계정 복구", "invalid", 401, 1, 0),
         ("no-scope", "계정 복구", "visitor", 403, 2, 0),
         ("input-block", "계정 복구 PIPELINE_TEST_DENY", "reader", 403, 4, 0),
         ("retrieval-block", "검색검사", "reader", 403, 6, 1),
         ("output-block", "답변검사", "reader", 403, 8, 1),
         ("classifier-error", "계정 복구 PIPELINE_TEST_MALFORMED", "reader", None, 4, 0),
         ("no-hits", "unmatchedfixture", "reader", 404, 5, 1)]
ORDER = ["authenticate", "authorize", "input_privacy", "input_rail", "retrieval",
         "retrieval_rail", "main", "output_rail", "output_privacy"]


def specifications(cases):
    return [{"input": {"case_id": name, "message": message, "identity": identity, "tenant": "team-a"},
             "status": status or 403, "stop": None if status == 200 else ORDER[count - 1],
             "input_entities": {"EMAIL_ADDRESS": 1} if name == "input-pii" else {}}
            for name, message, identity, status, count, _ in cases]
