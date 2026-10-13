import json
from aws_auth import load_aws_session
from botocore.config import Config


async def prepare_document(body, document_id, aws):
    # 허용 필드와 자료형·길이를 확인한 뒤 AWS에 연결한다.
    if not isinstance(body, dict) or set(body) != {"title", "body"}:
        raise ValueError("제목과 본문만 필요합니다")
    title, text = body["title"], body["body"]
    if (not isinstance(title, str) or not 1 <= len(title) <= 120
            or not title.strip() or "\n" in title or "\r" in title):
        raise ValueError("제목 형식이 잘못됐습니다")
    if not isinstance(text, str) or not 10 <= len(text) <= 4000 or not text.strip():
        raise ValueError("본문 형식이 잘못됐습니다")
    # 제공 골격: 이 문서에 사용할 임시 인증과 서버 소유 bucket을 불러온다.
    session, bucket = load_aws_session(aws)
    config = Config(connect_timeout=5, read_timeout=20, retries={"total_max_attempts": 1})
    # 실제 Boto3 객체를 직접 만들고 서버 발급 문서 ID로 저장한다.
    s3 = session.client("s3", region_name="us-east-1", config=config)
    runtime = session.client("bedrock-runtime", region_name="us-east-1", config=config)
    key = f"h02/knowledge/{document_id}.md"
    content = f"# {title}\n\n{text}\n"
    stored = s3.put_object(Bucket=bucket, Key=key, Body=content.encode("utf-8"),
        ContentType="text/markdown; charset=utf-8", Metadata={"course": "tenant-03", "activity": "h02"})
    # 저장 성공 후 원래 본문만 임베딩한다. SDK 호출에는 await를 붙이지 않는다.
    response = runtime.invoke_model(modelId="amazon.titan-embed-text-v2:0",
        contentType="application/json", accept="application/json",
        body=json.dumps({"inputText": text, "dimensions": 1024, "normalize": True}))
    # StreamingBody를 JSON 사전으로 변환한 뒤 닫는다.
    try:
        embedded = json.loads(response["body"].read())
    finally:
        response["body"].close()
    return {"source": stored, "embedding": embedded}
