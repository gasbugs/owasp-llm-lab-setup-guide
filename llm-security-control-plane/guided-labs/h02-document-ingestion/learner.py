"""입력을 검사하고 S3 원문 저장·Titan 임베딩을 직접 연결하세요."""

import json

from aws_auth import load_aws_session
from botocore.config import Config


async def prepare_document(body, document_id, aws):
    # TODO: 입력 검증 뒤 아래 제공 인증 골격을 사용해 구현하세요.
    session, bucket = load_aws_session(aws)
    config = Config(
        connect_timeout=5,
        read_timeout=20,
        retries={"total_max_attempts": 1},
    )
    raise NotImplementedError("P02 document preparation is not implemented")
