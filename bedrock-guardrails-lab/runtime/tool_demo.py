import json

import boto3


REGION = "us-east-1"
MODEL_ID = "us.amazon.nova-lite-v1:0"
TOOL_NAME = "get_security_contact"


client = boto3.client("bedrock-runtime", region_name=REGION)
response = client.converse(
    modelId=MODEL_ID,
    messages=[
        {
            "role": "user",
            "content": [{"text": "보안 사고 신고 연락처를 조회해 주세요."}],
        }
    ],
    toolConfig={
        "tools": [
            {
                "toolSpec": {
                    "name": TOOL_NAME,
                    "description": "읽기 전용 보안 신고 연락처를 조회한다.",
                    "inputSchema": {
                        "json": {
                            "type": "object",
                            "properties": {},
                            "required": [],
                        }
                    },
                }
            }
        ],
        "toolChoice": {"tool": {"name": TOOL_NAME}},
    },
    inferenceConfig={"maxTokens": 200, "temperature": 0, "topP": 0.9},
)

blocks = response.get("output", {}).get("message", {}).get("content", [])
tool_uses = [block["toolUse"] for block in blocks if "toolUse" in block]
selected = tool_uses[0] if tool_uses else {}
print(
    json.dumps(
        {
            "model": MODEL_ID,
            "stop_reason": response.get("stopReason"),
            "tool_name": selected.get("name"),
            "tool_input": selected.get("input"),
            "tool_executed": False,
            "usage": response.get("usage", {}),
        },
        ensure_ascii=False,
        indent=2,
    )
)
