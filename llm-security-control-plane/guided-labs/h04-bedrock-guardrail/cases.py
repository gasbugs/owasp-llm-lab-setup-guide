"""Server-owned P04 cases; native product checks and synthetic boundaries are distinct."""
from copy import deepcopy

CONTRACT_VERSION = "p04-guardrail-v1"


def cases():
    rows = []
    for operation in ("apply_guardrail", "converse"):
        for label, text in (("normal", "고객지원 운영 시간은 평일 오전 9시입니다."),
                            ("email", "담당자 이메일은 learner@example.com 입니다.")):
            rows.append({"case_id": operation + "-" + label, "backend": "provider",
                         "body": {"operation": operation, "text": text},
                         "expected": "returned", "provider_error": False})
    for label, text in (("text-min", "x"), ("text-max", "x" * 1000), ("preserve-whitespace", "  정상 문장  ")):
        rows.append({"case_id": label, "backend": "contract",
                     "body": {"operation": "apply_guardrail", "text": text},
                     "expected": "returned", "provider_error": False})
    invalid = [
        ("missing-operation", {"text": "normal"}),
        ("missing-text", {"operation": "converse"}),
        ("extra-policy", {"operation": "converse", "text": "normal", "guardrailIdentifier": "other"}),
        ("empty-body", {}), ("list-body", []), ("null-body", None), ("boolean-body", True),
        ("unknown-operation", {"operation": "unknown", "text": "normal"}),
        ("list-operation", {"operation": [], "text": "normal"}),
        ("boolean-operation", {"operation": True, "text": "normal"}),
    ]
    invalid.extend((label, {"operation": "converse", "text": text}) for label, text in (
        ("empty-text", ""), ("blank-text", " \n\t "), ("long-text", "x" * 1001),
        ("integer-text", 1), ("boolean-text", False), ("null-text", None),
        ("list-text", []), ("object-text", {}),
    ))
    rows.extend({"case_id": label, "backend": "contract", "body": body,
                 "expected": "rejected", "provider_error": False} for label, body in invalid)
    for operation in ("apply_guardrail", "converse"):
        rows.append({"case_id": operation + "-error", "backend": "contract",
                     "body": {"operation": operation, "text": "normal"},
                     "expected": "service_error", "provider_error": True})
    return deepcopy(rows)
