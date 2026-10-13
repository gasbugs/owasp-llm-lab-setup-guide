"""입력을 검사하고 S3 원문 저장·Titan 임베딩을 직접 연결하세요."""
import json
from aws_auth import load_aws_session
from botocore.config import Config


async def prepare_document(body, document_id, aws):
    # TODO 1: title·body 필드, 문자열 자료형·길이·공백을 검사하세요.
    # 잘못된 입력은 AWS 인증을 불러오기 전에 ValueError로 거부하세요.
    if not isinstance(body, dict):
        raise ValueError("Invalid body type")

    # 추가 필드가 있는지 확인 (오직 title과 body만 허용)
    if set(body.keys()) != {"title", "body"}:
        raise ValueError("Invalid fields in body")

    title = body.get("title")
    content = body.get("body")

    # title 검사: 문자열, 1~120자, 줄바꿈 금지, 공백뿐인 값 금지
    if not isinstance(title, str) or not title.strip() or len(title) < 1 or len(title) > 120:
        raise ValueError("Invalid title")
    if "\n" in title or "\r" in title:
        raise ValueError("Title cannot contain line breaks")

    # body 검사: 문자열, 10~4,000자, 공백뿐인 값 금지
    if not isinstance(content, str) or not content.strip() or len(content) < 10 or len(content) > 4000:
        raise ValueError("Invalid body content")

    # 제공 골격: 문서 한 건에 제한된 15분 임시 AWS 인증을 불러옵니다.
    session, bucket = load_aws_session(aws)
    config = Config(connect_timeout=5, read_timeout=20,
                    retries={"total_max_attempts": 1})

    # TODO 2: session.client로 s3·bedrock-runtime 객체를 직접 만드세요.
    # 두 객체에 region_name="us-east-1", config=config를 전달하세요.
    s3_client = session.client("s3", region_name="us-east-1", config=config)
    bedrock_client = session.client("bedrock-runtime", region_name="us-east-1", config=config)

    # TODO 3: 서버 발급 document_id로 Markdown 원문을 S3에 한 번 저장하세요.
    storage_key = f"h02/knowledge/{document_id}.md"
    markdown_content = f"# {title}\n\n{content}\n"

    source = s3_client.put_object(
        Bucket=bucket,
        Key=storage_key,
        Body=markdown_content.encode("utf-8"),
        ContentType="text/markdown; charset=utf-8",
        Metadata={"course": "tenant-03", "activity": "h02"}
    )

    # TODO 4: 저장 성공 후 원래 본문을 Titan v2에 한 번 보내세요.
    # dimensions=1024, normalize=True를 사용하세요.
    payload = {
        "inputText": content,
        "dimensions": 1024,
        "normalize": True
    }

    response = bedrock_client.invoke_model(
        modelId="amazon.titan-embed-text-v2:0",
        contentType="application/json",
        accept="application/json",
        body=json.dumps(payload)
    )

    # TODO 5: 응답 body를 JSON으로 변환하고 스트림을 닫으세요.
    # source에는 put_object 응답, embedding에는 파싱한 Titan 응답을 반환하세요.
    response_body = response["body"]
    try:
        embedding = json.loads(response_body.read().decode("utf-8"))
    finally:
        response_body.close()

    return {
        "source": source,
        "embedding": embedding
    }
