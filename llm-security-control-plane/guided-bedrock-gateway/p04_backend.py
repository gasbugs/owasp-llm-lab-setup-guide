"""P04 Boto3 adapter. Caller supplies an already registered case and policy."""
import json

import boto3
from botocore.config import Config

from p04_contract import canonical, expected_arguments, validate_invocation


class ProviderError(RuntimeError):
    pass


class BedrockBackend:
    provider_mode = "aws"

    def __init__(self, body, guardrail, *, region="us-east-1", client_factory=None):
        if region != "us-east-1":
            raise ValueError("P04 uses the configured course region")
        self.body, self.guardrail = json.loads(canonical(body)), json.loads(canonical(guardrail))
        # Invalid-input cases must stop in the learner; they cannot create a provider.
        expected_arguments(self.body, self.guardrail)
        self.region = region
        self.client_factory = client_factory or boto3.client

    def __call__(self, operation, payload):
        try:
            arguments = validate_invocation(operation, payload, body=self.body, guardrail=self.guardrail)
            client = self.client_factory(
                "bedrock-runtime", region_name=self.region,
                config=Config(connect_timeout=3, read_timeout=20, retries={"total_max_attempts": 1}),
            )
            try:
                method = {"apply_guardrail": client.apply_guardrail, "converse": client.converse}[operation]
                response = method(**arguments)
            finally:
                client.close()
            if not isinstance(response, dict):
                raise ValueError("response object missing")
            metadata = response.get("ResponseMetadata")
            if (not isinstance(metadata, dict) or type(metadata.get("HTTPStatusCode")) is not int
                    or metadata["HTTPStatusCode"] != 200
                    or not isinstance(metadata.get("RequestId"), str)
                    or not metadata["RequestId"].isascii()
                    or not 1 <= len(metadata["RequestId"]) <= 256):
                raise ValueError("native response metadata missing")
            if len(canonical(response)) > 32768:
                raise ValueError("response limit")
            # No generated ID, repaired parameters, anonymization, or verdict here.
            return response
        except Exception:
            raise ProviderError("P04 Bedrock call failed") from None
