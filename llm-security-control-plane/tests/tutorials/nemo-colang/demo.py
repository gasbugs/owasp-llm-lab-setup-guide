import asyncio
import os
import sys

from nemoguardrails import LLMRails, RailsConfig
from nemoguardrails.actions import action


@action(is_system_action=True)
async def get_security_contact() -> str:
    return "보안팀 연락처: security@example.com"


config = RailsConfig.from_path("/work/config")
config.models[0].parameters = {
    "base_url": os.environ["MODEL_GATEWAY_URL"] + "/v1",
    "api_key": os.environ["BEDROCK_GATEWAY_TOKEN"],
    "temperature": 0.0,
}
rails = LLMRails(config)
rails.register_action(get_security_contact, "get_security_contact")


def response_content(response) -> str:
    last = response[-1] if isinstance(response, list) else response
    return str(last.get("content", ""))


async def main() -> None:
    result = await rails.generate_async(
        messages=[{"role": "user", "content": sys.argv[1]}],
        options={"rails": ["dialog"]},
    )
    print(response_content(result.response))


asyncio.run(main())
