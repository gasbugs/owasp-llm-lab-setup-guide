"""입력을 검사하고 S3 원문 저장·Titan 임베딩을 직접 연결하세요."""

import json
from aws_auth import load_aws_session
from botocore.config import Config


async def prepare_document(body, document_id, aws):
    # 제공 흐름: 허용 필드와 값의 타입·길이를 AWS 호출 전에 검사합니다.
    if not isinstance(body, dict) or set(body) != {"title", "body"}:
        raise ValueError("title and body required")
    title, text = body["title"], body["body"]
    if not isinstance(title, str) or not title.strip() or "\n" in title or "\r" in title or len(title) > 120:
        raise ValueError("invalid title")
    if not isinstance(text, str) or not text.strip() or not 10 <= len(text) <= 4000:
        raise ValueError("invalid body")

    session, bucket = load_aws_session(aws)
    config = Config(connect_timeout=5, read_timeout=20, retries={"total_max_attempts": 1})
    key = f"h02/knowledge/{document_id}.md"
    source_text = f"# {title}\n\n{text}\n"

    # TODO 2: S3 클라이언트를 만들고 key·source_text를 put_object()로 저장하세요.
    # 결과 전체를 source에 받으세요. 성공하기 전에는 임베딩을 호출하지 않습니다.
    # TODO 3: 같은 text로 Titan을 invoke_model() 한 번 호출하세요.
    # 결과 전체를 embedding_response에 받으세요.
    raise NotImplementedError("P02 document preparation is not implemented")

    # 제공 흐름: SDK stream을 JSON으로 변환하되 응답 필드는 그대로 유지합니다.
    embedding = json.loads(embedding_response["body"].read())
    return {"source": source, "embedding": embedding}
