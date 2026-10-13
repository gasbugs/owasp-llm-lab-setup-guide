from aws_auth import load_aws_session
from botocore.config import Config


async def search_current(current_job_id, aws):
    # 제공된 조회 전용 인증과 이번 작업의 AWS ID를 불러온다.
    session, binding = load_aws_session(aws)
    config = Config(connect_timeout=5, read_timeout=20, retries={'total_max_attempts': 1})
    # 실제 Boto3 객체를 만들고 현재 동기화 작업 하나를 조회한다.
    agent = session.client('bedrock-agent', region_name='us-east-1', config=config)
    runtime = session.client('bedrock-agent-runtime', region_name='us-east-1', config=config)
    response = agent.get_ingestion_job(**binding)
    observed = response.get('ingestionJob', {})
    if observed.get('ingestionJobId') != binding['ingestionJobId']:
        raise ValueError('현재 작업 ID가 일치하지 않습니다')
    status = observed.get('status')
    # 진행 중에는 검색하지 않고 대기 결과만 반환한다.
    if status in ('QUEUED', 'STARTING', 'IN_PROGRESS'):
        return {'status': 'waiting', 'result': None}
    if status != 'COMPLETE':
        raise ValueError('검색할 수 없는 동기화 상태입니다')
    # 동기화 완료 후 실제 Knowledge Base 검색 응답을 반환한다.
    result = runtime.retrieve(knowledgeBaseId=binding['knowledgeBaseId'],
        retrievalQuery={'text': aws.query},
        retrievalConfiguration={'vectorSearchConfiguration': {'numberOfResults': 3}})
    return {'status': 'ready', 'result': result}
