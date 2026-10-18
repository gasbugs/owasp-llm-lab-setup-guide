"""현재 ingestion 상태를 확인하고 완료된 문서만 검색하세요."""

from aws_auth import load_aws_session
from botocore.config import Config


async def search_current(current_job_id, aws):
    session, binding = load_aws_session(aws)
    config = Config(connect_timeout=5, read_timeout=20, retries={"total_max_attempts": 1})

    # 제공 흐름: 필요한 ID를 확인하기 전에는 AWS를 조회하지 않습니다.
    for name in ("knowledgeBaseId", "dataSourceId", "ingestionJobId"):
        if not isinstance(binding.get(name), str) or not binding[name]:
            raise ValueError(f"missing {name}")

    # TODO 2: session.region_name과 config로 agent·runtime 클라이언트를 만드세요.
    # TODO 3: agent.get_ingestion_job(**binding)을 한 번 호출하고
    # 응답의 ingestionJob에서 작업 ID와 status를 꺼내세요.
    raise NotImplementedError("P03 current-job retrieval is not implemented")

    # 제공 흐름: 현재 작업이 끝나기 전에는 검색을 호출하지 않습니다.
    if not isinstance(job_id, str) or job_id != binding["ingestionJobId"]:
        raise ValueError("ingestion job mismatch")
    if status in ("QUEUED", "STARTING", "IN_PROGRESS"):
        return {"status": "waiting", "result": None}
    if status != "COMPLETE":
        raise ValueError("ingestion job incomplete")

    # TODO 4: COMPLETE일 때만 runtime.retrieve()를 한 번 호출하고
    # 응답 전체를 result에 받으세요.
    raise NotImplementedError("P03 retrieval is not implemented")
    return {"status": "ready", "result": result}
