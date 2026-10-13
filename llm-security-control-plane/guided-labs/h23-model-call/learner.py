"""질문을 Bedrock으로 전달하는 함수를 완성하세요."""
import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError


def forward_question(message):
    # TODO 1: 문자열이 아니거나 공백뿐인 질문은 ValueError로 거부하세요.
    if not isinstance(message, str) or not message.strip():
        raise ValueError("Invalid message")

    # 제공 코드: 연결된 AWS 설정에서 인증 정보를 자동으로 불러옵니다.
    # Access Key를 코드에 적지 않습니다.
    boto3.setup_default_session(region_name="us-east-1")
    config = Config(connect_timeout=5, read_timeout=90,
                    retries={"total_max_attempts": 1})
    # TODO 2, 3, 4: 클라이언트 생성, Converse 호출 및 예외 처리
    try:
        client = boto3.client("bedrock-runtime", region_name="us-east-1", config=config)
        response = client.converse(
            modelId="us.amazon.nova-lite-v1:0",
            messages=[{"role": "user", "content": [{"text": message}]}],
            inferenceConfig={"maxTokens": 64, "temperature": 0}
        )
        return response
    except (BotoCoreError, ClientError) as e:
        raise RuntimeError("model unavailable") from e
