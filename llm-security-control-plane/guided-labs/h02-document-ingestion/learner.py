"""입력을 검사하고 S3 원문 저장·Titan 임베딩을 직접 연결하세요."""

import json

from aws_auth import load_aws_session
from botocore.config import Config


async def prepare_document(body, document_id, aws):
    # TODO 1: AWS 호출 전에 title/body의 타입·길이·허용 필드를 검사하세요.
    # 잘못된 입력은 ValueError로 거부하세요.
    session, bucket = load_aws_session(aws)
    config = Config(
        connect_timeout=5,
        read_timeout=20,
        retries={"total_max_attempts": 1},
    )
    # TODO 2: S3에 제목과 본문을 정해진 key·형식으로 저장하세요.
    # TODO 3: 저장이 성공한 뒤 같은 본문으로 Titan 임베딩을 한 번 요청하세요.
    # TODO 4: source에는 S3 응답, embedding에는 stream을 JSON으로 변환한 dict를 담아 반환하세요.
    raise NotImplementedError("P02 document preparation is not implemented")
