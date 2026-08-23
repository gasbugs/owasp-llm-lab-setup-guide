import json

import boto3


# 실습에서 사용할 AWS 리전, 생성 모델, Tool 이름을 한곳에 고정한다.
REGION = "us-east-1"
MODEL_ID = "us.amazon.nova-lite-v1:0"
TOOL_NAME = "get_security_contact"


# Boto3의 Bedrock Runtime client가 실제 Converse API 요청을 전송한다.
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
                    # 모델이 제안할 수 있는 읽기 전용 Tool의 계약을 선언한다.
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
        # 이번 실습에서는 Nova Lite가 이 Tool을 선택하도록 명시한다.
        "toolChoice": {"tool": {"name": TOOL_NAME}},
    },
    # temperature=0으로 제안의 재현성을 높이고 출력 상한을 제한한다.
    inferenceConfig={"maxTokens": 200, "temperature": 0, "topP": 0.9},
)

# 응답 content에서 자연어가 아닌 toolUse 블록만 골라낸다.
blocks = response.get("output", {}).get("message", {}).get("content", [])
tool_uses = [block["toolUse"] for block in blocks if "toolUse" in block]
selected = tool_uses[0] if tool_uses else {}

# 모델의 제안만 출력한다. 연락처 함수는 아직 구현하거나 실행하지 않는다.
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
