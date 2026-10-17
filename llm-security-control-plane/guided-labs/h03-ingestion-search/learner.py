"""현재 ingestion 상태를 확인하고 완료된 문서만 검색하세요."""

from aws_auth import load_aws_session
from botocore.config import Config


async def search_current(current_job_id, aws):
    # 제공 코드: 서버가 발급한 인증과 현재 작업의 AWS 자원 ID를 불러옵니다.
    session, binding = load_aws_session(aws)
    config = Config(
        connect_timeout=5,
        read_timeout=20,
        retries={"total_max_attempts": 1},
    )

    # TODO 1: binding의 필수 ID 세 개를 AWS 호출 전에 검사하세요.
    # TODO 2: session의 region_name으로 조회·검색 클라이언트를 만드세요.
    # TODO 3: 이번 ingestionJobId의 상태를 한 번 조회하고 유효성을 검사하세요.
    # 진행 중이면 검색 없이 {"status":"waiting","result":None}을 반환하세요.
    # TODO 4: COMPLETE일 때만 한 번 검색하고 전체 SDK 응답을 result에 담으세요.
    # 실패 상태·잘못된 응답은 ValueError로 거부하고 SDK 오류는 숨기지 마세요.
    raise NotImplementedError("P03 current-job retrieval is not implemented")
