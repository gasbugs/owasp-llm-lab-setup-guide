"""Explicit publisher SDK double. Markers test wiring, not model detection quality."""
import json
import os
from uuid import uuid4

from p12_capabilities import CapabilityStore
from p12_gateway import create_app


class SDKFixture:
    def converse(self, **request):
        prompt = request["messages"][0]["content"][0]["text"]
        if request["inferenceConfig"]["maxTokens"] == 128:
            # Interpret JSON values, not their whitespace or Unicode escape spelling.
            value = json.loads(prompt)
            content = value["question"] + "\n" + value["context"]
            text = "PIPELINE_TEST_DENY" if "답변검사" in content else "담당자: learner@example.com"
        elif "PIPELINE_TEST_MALFORMED" in prompt:
            text = "invalid-classifier-fixture"
        else:
            text = "Yes" if "PIPELINE_TEST_DENY" in prompt else "No"
        return {"output": {"message": {"role": "assistant", "content": [{"text": text}]}},
                "ResponseMetadata": {"RequestId": str(uuid4())}, "stopReason": "end_turn",
                "usage": {"inputTokens": 10, "outputTokens": 1, "totalTokens": 11}}


app = create_app(store=CapabilityStore("/state/gateway.sqlite3"), client=SDKFixture(),
                 control_token=os.environ["GUIDED_P12_GATEWAY_CONTROL_TOKEN"],
                 verifier_token=os.environ["GUIDED_P12_GATEWAY_VERIFIER_TOKEN"])
