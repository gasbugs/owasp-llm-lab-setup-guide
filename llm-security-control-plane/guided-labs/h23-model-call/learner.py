"""질문을 Bedrock으로 전달하는 함수를 완성하세요."""

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError


def forward_question(message):
    # TODO 1: 문자열이 아니거나 공백뿐인 질문은 ValueError로 거부하세요.

    # 제공 코드: 연결된 AWS 설정에서 인증 정보를 자동으로 불러옵니다.
    # Access Key를 코드에 적지 않습니다.
    region_name = boto3.session.Session().region_name
    config = Config(
        connect_timeout=5,
        read_timeout=90,
        retries={"total_max_attempts": 1},
    )

    # TODO 2: boto3.client()로 bedrock-runtime 클라이언트를 만드세요.
    # AWS 프로필에서 확인한 region_name과 기존 config를 전달하세요. Access Key를 직접 적지 마세요.

    # TODO 3: client.converse()로 질문을 한 번만 보내세요.
    # modelId, messages, inferenceConfig는 문제 화면의 값을 사용하세요.
    # 호출 결과를 변수에 받고, 그 응답 dict 전체를 return하세요.

    # TODO 4: 클라이언트 생성·Converse 호출에서 난 BotoCoreError/ClientError를 처리하세요.
    # try/except로 받아 RuntimeError("model unavailable")로 바꾸되 입력 ValueError는 그대로 두세요.
    raise NotImplementedError("Implement forward_question")
