"""Publisher wiring for bounded live Bedrock checks; no mock or fallback client."""
import os
from p12_capabilities import CapabilityStore
from p12_gateway import BedrockClient, create_app

app = create_app(store=CapabilityStore("/state/gateway.sqlite3"), client=BedrockClient(),
    control_token=os.environ["GUIDED_P12_GATEWAY_CONTROL_TOKEN"],
    verifier_token=os.environ["GUIDED_P12_GATEWAY_VERIFIER_TOKEN"])
