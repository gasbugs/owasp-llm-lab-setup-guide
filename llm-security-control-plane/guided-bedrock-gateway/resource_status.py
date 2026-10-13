"""Live, read-only inventory of server-owned mission resources."""
from datetime import datetime, timezone
from urllib.parse import quote
from botocore.exceptions import ClientError
from resource_cleanup import clients

MISSING = {"404", "NoSuchBucket", "NoSuchEntity", "ResourceNotFoundException", "NotFoundException"}


def inventory(problem, *, provider_mode, p02_template, client_factory=clients):
    result = {"practice_id": problem, "read_only": True,
              "checked_at": datetime.now(timezone.utc).isoformat(), "resources": []}
    if provider_mode != "aws":
        return {**result, "state": "unavailable", "detail": "AWS 연결 모드가 아니므로 실제 자원은 조회하지 않았습니다."}
    sdk = client_factory("us-east-1")
    rows = result["resources"]
    def probe(label, name, call):
        try:
            value = call()
            rows.append({"type": label, "name": name, "state": "present"})
            return value
        except ClientError as error:
            code = error.response.get("Error", {}).get("Code", "Unknown")
            rows.append({"type": label, "name": name,
                         "state": "absent" if code in MISSING else "unknown", "detail": code})
            return None
    def enrich(row, call, transform):
        try:
            row["facts"] = transform(call())
        except Exception as error:
            row["inspection_error"] = (error.response.get("Error", {}).get("Code", "조회 실패")
                                       if isinstance(error, ClientError) else "상세 조회 실패")
    def listing(call, key, name):
        matches = []
        token = None
        for _ in range(100):
            page = call(**({"nextToken": token} if token else {}), maxResults=100)
            matches.extend(item for item in page.get(key, []) if item.get("name") == name)
            token = page.get("nextToken")
            if not token:
                return matches
        raise RuntimeError("resource listing exceeds its bound")
    try:
        account = sdk["sts"].get_caller_identity()["Account"]
        if problem == "P04":
            from p04_resource_contract import template
            t = template(account)
            matches = listing(sdk["bedrock"].list_guardrails, "guardrails", t["name"])
            if not matches:
                rows.append({"type": "AWS Guardrail", "name": t["name"], "state": "absent"})
            for item in matches:
                detail = probe("AWS Guardrail", item["id"], lambda: sdk["bedrock"].get_guardrail(
                    guardrailIdentifier=item["id"], guardrailVersion="DRAFT"))
                if detail:
                    rows[-1]["aws_status"] = detail.get("status")
                    rows[-1]["facts"] = {"버전": detail.get("version"), "정책 이름": detail.get("name"),
                                          "최근 수정": str(detail.get("updatedAt", ""))}
                    rows[-1]["console_url"] = f"https://us-east-1.console.aws.amazon.com/bedrock/home?region=us-east-1#/guardrails/{item['id']}"
        else:
            if problem == "P02":
                t = p02_template(account)
            else:
                from p03_resource_contract import template
                t = template(account)
            probe("S3 source bucket", t["source_bucket"], lambda: sdk["s3"].head_bucket(
                Bucket=t["source_bucket"], ExpectedBucketOwner=account))
            if rows[-1]["state"] == "present":
                prefix = t.get("source_prefix", "h02/knowledge/")
                rows[-1]["console_url"] = f"https://us-east-1.console.aws.amazon.com/s3/buckets/{t['source_bucket']}?region=us-east-1"
                def document_facts(page):
                    objects = page.get("Contents", [])
                    return {"문서 수" : str(len(objects)) + ("개 이상" if page.get("IsTruncated") else "개"),
                            "원문 크기": str(sum(item.get("Size", 0) for item in objects)) + (" Byte 이상" if page.get("IsTruncated") else " Byte"),
                            "조회 경로": prefix,
                            "최근 저장": str(max((item["LastModified"] for item in objects), default="아직 문서 없음"))}
                enrich(rows[-1], lambda: sdk["s3"].list_objects_v2(Bucket=t["source_bucket"],
                       ExpectedBucketOwner=account, Prefix=prefix, MaxKeys=1000), document_facts)
            probe("S3 vector bucket", t["vector_bucket"], lambda: sdk["vectors"].get_vector_bucket(vectorBucketName=t["vector_bucket"]))
            if rows[-1]["state"] == "present":
                rows[-1]["console_url"] = f"https://us-east-1.console.aws.amazon.com/s3/vector-buckets/{quote(t['vector_bucket'], safe='')}?region=us-east-1"
            probe("Vector index", t["index_arn"], lambda: sdk["vectors"].get_index(indexArn=t["index_arn"]))
            if rows[-1]["state"] == "present":
                index_name = t["index_arn"].rsplit("/", 1)[-1]
                rows[-1]["console_url"] = f"https://us-east-1.console.aws.amazon.com/s3/vector-buckets/{quote(t['vector_bucket'], safe='')}/indexes/{quote(index_name, safe='')}?region=us-east-1"
                enrich(rows[-1], lambda: sdk["vectors"].get_index(indexArn=t["index_arn"]),
                       lambda response: {"벡터 차원": response["index"].get("dimension"),
                                         "거리 계산": response["index"].get("distanceMetric"), "데이터 형식": response["index"].get("dataType")})
            probe("IAM role", t["role_name"], lambda: sdk["iam"].get_role(RoleName=t["role_name"]))
            if rows[-1]["state"] == "present":
                rows[-1]["console_url"] = f"https://us-east-1.console.aws.amazon.com/iam/home#/roles/details/{quote(t['role_name'], safe='')}?section=permissions"
            matches = listing(sdk["agent"].list_knowledge_bases, "knowledgeBaseSummaries", t["knowledge_base_name"])
            if not matches:
                rows.extend({"type": label, "name": t[key], "state": "absent"}
                            for label, key in (("Knowledge Base", "knowledge_base_name"), ("Data source", "data_source_name")))
            for item in matches:
                kb_id = item["knowledgeBaseId"]
                detail = probe("Knowledge Base", kb_id, lambda: sdk["agent"].get_knowledge_base(knowledgeBaseId=kb_id))
                if detail:
                    kb = detail["knowledgeBase"]
                    rows[-1]["aws_status"] = kb.get("status")
                    storage = kb.get("storageConfiguration", {})
                    rows[-1]["facts"] = {"이름": kb.get("name"), "검색 저장소": storage.get("type"),
                        "연결 인덱스": storage.get("s3VectorsConfiguration", {}).get("indexArn"),
                        "임베딩 모델": kb.get("knowledgeBaseConfiguration", {}).get("vectorKnowledgeBaseConfiguration", {}).get("embeddingModelArn"),
                        "IAM 역할": kb.get("roleArn")}
                    rows[-1]["console_url"] = f"https://us-east-1.console.aws.amazon.com/bedrock/home?region=us-east-1#/knowledge-bases/{kb_id}"
                sources = listing(lambda **args: sdk["agent"].list_data_sources(knowledgeBaseId=kb_id, **args), "dataSourceSummaries", t["data_source_name"])
                rows.extend({"type": "Data source", "name": source["dataSourceId"], "state": "present", "aws_status": source.get("status")} for source in sources)
                for source in sources:
                    row = next(row for row in rows if row["type"] == "Data source" and row["name"] == source["dataSourceId"])
                    ds_id = source["dataSourceId"]
                    row["console_url"] = f"https://us-east-1.console.aws.amazon.com/bedrock/home?region=us-east-1#/knowledge-bases/{kb_id}"
                    row["console_hint"] = "Knowledge Base 화면의 Data source에서 이 ID를 선택하세요."
                    def source_facts(response):
                        ds = response["dataSource"]
                        config = ds.get("dataSourceConfiguration", {}).get("s3Configuration", {})
                        return {"이름": ds.get("name"), "연결 버킷": config.get("bucketArn"),
                                "문서 경로": ", ".join(config.get("inclusionPrefixes", []))}
                    enrich(row, lambda: sdk["agent"].get_data_source(knowledgeBaseId=kb_id, dataSourceId=ds_id), source_facts)
                    try:
                        jobs = sdk["agent"].list_ingestion_jobs(knowledgeBaseId=kb_id, dataSourceId=ds_id, maxResults=10,
                                sortBy={"attribute": "STARTED_AT", "order": "DESCENDING"}).get("ingestionJobSummaries", [])
                        row.setdefault("facts", {})["최근 동기화"] = jobs[0]["status"] if jobs else "아직 실행하지 않음"
                        if jobs:
                            row["facts"]["동기화 시작"] = str(jobs[0].get("startedAt", ""))
                            row["facts"]["동기화 통계"] = str(jobs[0].get("statistics", {}))
                    except Exception:
                        row["inspection_error"] = "동기화 이력 조회 실패"
                if not sources:
                    rows.append({"type": "Data source", "name": t["data_source_name"], "state": "absent"})
        states = {row["state"] for row in rows}
        result["state"] = "unknown" if "unknown" in states else "absent" if states == {"absent"} else "present" if states == {"present"} else "partial"
        return result
    finally:
        for client in sdk.values():
            client.close()
