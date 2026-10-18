"""Regression cases for the proxy's native Presidio input/output boundary."""

from policy import PrivacyAnalyzer


analyzer = PrivacyAnalyzer()
cases = (
    ("exact_key", "DEMO_API_KEY=ABCD-1234", {"DEMO_API_KEY"}, ("ABCD-1234",)),
    ("spaced_key", "DEMO_API_KEY = ABCD-1234", {"DEMO_API_KEY"}, ("ABCD-1234",)),
    ("overlapping_key_ip", "DEMO_API_KEY=203.0.113.77", {"DEMO_API_KEY", "IP_ADDRESS"}, ("203.0.113.77",)),
    ("email_phone", "Email sample@example.com and phone 202-555-0149", {"EMAIL_ADDRESS", "PHONE_NUMBER"}, ("sample@example.com", "202-555-0149")),
)
for stage in ("input", "tool_result", "output"):
    for name, message, expected, secrets in cases:
        result = analyzer.analyze(stage=stage, text=message, request_id="synthetic-probe-01")
        assert expected.issubset(result["entity_types"]), (stage, name, result["entity_types"])
        assert result["valid"] is False, (stage, name)
        assert result["sanitized_candidate"] != message, (stage, name)
        assert all(secret not in result["sanitized_candidate"] for secret in secrets), (stage, name)

normal = analyzer.analyze(stage="input", text="Where is account recovery help?", request_id="synthetic-probe-01")
assert normal["valid"] is True and normal["entity_types"] == []
assert normal["sanitized_candidate"] == "Where is account recovery help?"
print("proxy_privacy_contract=PASS cases=exact,spaced,overlap,email_phone,normal stages=input,tool_result,output")