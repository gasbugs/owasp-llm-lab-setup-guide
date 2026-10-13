"""P01-03: create real Boto3 clients below the provided authentication skeleton."""
from aws_auth import load_aws_session
from botocore.config import Config


async def search_current(current_job_id, aws):
    # 제공 골격: 조회 전용 인증과 서버가 정한 KB·Data Source·작업 ID를 불러옵니다.
    session, binding = load_aws_session(aws)
    config = Config(connect_timeout=5, read_timeout=20, retries={'total_max_attempts': 1})

    # TODO 1: session.client로 bedrock-agent·bedrock-agent-runtime 객체를 만드세요.
    # region_name='us-east-1', config=config를 사용하세요.
    agent_client = session.client("bedrock-agent", region_name="us-east-1", config=config)
    runtime_client = session.client("bedrock-agent-runtime", region_name="us-east-1", config=config)

    # TODO 2: binding의 세 ID로 get_ingestion_job을 호출하고 ingestionJob을 확인하세요.
    if not binding or "knowledgeBaseId" not in binding or "dataSourceId" not in binding or "ingestionJobId" not in binding:
        raise ValueError("Invalid binding information")

    response = agent_client.get_ingestion_job(
        knowledgeBaseId=binding["knowledgeBaseId"],
        dataSourceId=binding["dataSourceId"],
        ingestionJobId=binding["ingestionJobId"]
    )

    ingestion_job = response.get("ingestionJob")
    if not ingestion_job or not isinstance(ingestion_job, dict):
        raise ValueError("Missing or invalid ingestionJob")

    job_id = ingestion_job.get("ingestionJobId")

    # TODO 3: 작업 ID 불일치·누락 및 잘못된 상태는 ValueError로 거부하세요.
    if not job_id or job_id != binding["ingestionJobId"]:
        raise ValueError("Ingestion job ID mismatch or missing")

    status = ingestion_job.get("status")
    if not status or not isinstance(status, str):
        raise ValueError("Missing or invalid ingestion job status")

    if status in ("QUEUED", "STARTING", "IN_PROGRESS"):
        return {"status": "waiting", "result": None}
    elif status in ("FAILED", "STOPPING", "STOPPED"):
        raise ValueError(f"Ingestion job failed with status: {status}")
    elif status != "COMPLETE":
        raise ValueError(f"Unknown ingestion job status: {status}")

    # TODO 4: COMPLETE일 때만 retrieve를 호출하세요. 검색문·결과 수는 문제 조건을 사용하세요.
    query_text = getattr(aws, "query", None)
    if not query_text:
        # aws 객체가 딕셔너리 형태일 경우 대비
        if isinstance(aws, dict):
            query_text = aws.get("query")

    retrieve_response = runtime_client.retrieve(
        knowledgeBaseId=binding["knowledgeBaseId"],
        retrievalQuery={"text": query_text},
        retrievalConfiguration={
            "vectorSearchConfiguration": {
                "numberOfResults": 3
            }
        }
    )

    # TODO 5: {'status': 'ready', 'result': 실제 retrieve 응답}을 반환하세요.
    # Boto3 호출에는 await를 붙이지 않고 SDK 오류를 그대로 전달하세요.
    return {
        "status": "ready",
        "result": retrieve_response
    }
