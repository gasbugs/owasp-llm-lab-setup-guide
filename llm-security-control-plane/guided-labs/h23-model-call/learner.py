"""질문을 Bedrock으로 전달하는 함수를 완성하세요."""

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError


def forward_question(message):
    # 제공 흐름: 입력 오류는 SDK 오류와 구분해 호출 전에 거부합니다.
    if not isinstance(message, str) or not message.strip():
        raise ValueError("question required")

    # 제공 코드: 연결된 AWS 설정에서 인증 정보를 자동으로 불러옵니다.
    region_name = boto3.session.Session().region_name
    config = Config(connect_timeout=5, read_timeout=90, retries={"total_max_attempts": 1})

    try:
        # TODO 2: region_name과 config로 Bedrock Runtime 클라이언트를 만드세요.
        # TODO 3: client.converse()에 문제 화면의 modelId, messages,
        # inferenceConfig를 전달하고 응답 전체를 response에 받으세요.
        raise NotImplementedError("Implement forward_question")
    except (BotoCoreError, ClientError) as exc:
        # 제공 흐름: SDK 오류만 변환하고 입력 ValueError는 그대로 둡니다.
        raise RuntimeError("model unavailable") from exc
    return response
