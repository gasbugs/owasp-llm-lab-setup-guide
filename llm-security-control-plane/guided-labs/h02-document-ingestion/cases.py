"""Server-owned P02 requests; not learner answers or Browser-supplied verdicts."""
CONTRACT_VERSION = "p02-document-v1"


def cases():
    normal = {"title": "업무 안내", "body": "합성 문서를 저장하고 변환합니다."}
    requests = [
        ("normal-document", True, normal),
        ("minimum-length", True, {"title": "가", "body": "가나다라마바사아자차"}),
        ("maximum-length", True, {"title": "가" * 120, "body": "나" * 4000}),
        ("preserve-whitespace", True, {"title": " 안내 ", "body": "  원문 공백을 보존하는 문서입니다.\n"}),
        ("client-key-override", False, {**normal, "object_key": "other/source.md"}),
        ("client-id-override", False, {**normal, "document_id": "client-selected"}),
        ("client-self-approval", False, {**normal, "approval_status": "approved"}),
        ("client-tenant", False, {**normal, "tenant": "other"}),
        ("missing-title", False, {"body": normal["body"]}),
        ("missing-body", False, {"title": normal["title"]}),
        ("empty-title", False, {**normal, "title": ""}),
        ("blank-title", False, {**normal, "title": " "}),
        ("title-newline", False, {**normal, "title": "제목\n변경"}),
        ("title-carriage-return", False, {**normal, "title": "제목\r변경"}),
        ("title-too-long", False, {**normal, "title": "가" * 121}),
        ("title-wrong-type", False, {**normal, "title": True}),
        ("body-too-short", False, {**normal, "body": "가" * 9}),
        ("body-too-long", False, {**normal, "body": "나" * 4001}),
        ("blank-body", False, {**normal, "body": " " * 10}),
        ("body-wrong-type", False, {**normal, "body": 1234567890}),
        ("null-body", False, {**normal, "body": None}),
        ("not-an-object", False, [normal]),
    ]
    return [{"case_id": case_id, "valid": valid, "body": body} for case_id, valid, body in requests]
