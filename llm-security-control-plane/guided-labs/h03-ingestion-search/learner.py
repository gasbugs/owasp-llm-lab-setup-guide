"""현재 ingestion 상태를 확인하고 완료된 문서만 검색하세요."""

from aws_auth import load_aws_session
from botocore.config import Config


async def search_current(current_job_id, aws):
    session, binding = load_aws_session(aws)
    config = Config(
        connect_timeout=5,
        read_timeout=20,
        retries={"total_max_attempts": 1},
    )
    # TODO: 현재 ingestion 확인과 검색을 구현하세요.
    raise NotImplementedError("P03 current-job retrieval is not implemented")
