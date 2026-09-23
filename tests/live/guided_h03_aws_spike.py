#!/usr/bin/env python3
"""Measure the non-atomic H03 retrieval transition in an isolated AWS namespace."""

from __future__ import annotations

import argparse
import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

import boto3
from botocore.exceptions import ClientError


EMBEDDING_MODEL_ID = "amazon.titan-embed-text-v2:0"
INDEX_NAME = "course-knowledge"
SOURCE_PREFIX = "h03/knowledge/"
OLD_KEY = f"{SOURCE_PREFIX}revoked-policy.md"
CURRENT_KEY = f"{SOURCE_PREFIX}current-policy.md"
QUERY = "GUIDED-H03-ORION access procedure"
OLD_MARKER = "GUIDED-H03-ORION-REVOKED"
CURRENT_MARKER = "GUIDED-H03-ORION-CURRENT"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", default="default")
    parser.add_argument("--region", default="us-east-1")
    return parser.parse_args()


def request_id(response: dict[str, Any]) -> str:
    value = response.get("ResponseMetadata", {}).get("RequestId")
    if not value:
        raise RuntimeError("AWS response did not include a request ID")
    return value


def wait_for(
    fetch: Callable[[], dict[str, Any]],
    expected: str,
    *,
    failed: set[str],
    attempts: int = 100,
    delay: float = 3.0,
) -> dict[str, Any]:
    last: dict[str, Any] = {}
    for _ in range(attempts):
        last = fetch()
        status = str(last.get("status", ""))
        if status == expected:
            return last
        if status in failed:
            raise RuntimeError(f"AWS resource entered {status}: {last}")
        time.sleep(delay)
    raise TimeoutError(f"AWS resource did not reach {expected}: {last}")


def find_one(items: list[dict[str, Any]], name: str) -> dict[str, Any] | None:
    matches = [item for item in items if item.get("name") == name]
    if len(matches) > 1:
        raise RuntimeError(f"duplicate AWS resources named {name}")
    return matches[0] if matches else None


def ensure_resources(session: boto3.Session, region: str) -> dict[str, str]:
    sts = session.client("sts", region_name=region)
    account_id = sts.get_caller_identity()["Account"]
    prefix = f"owasp-llm-03-h03-{account_id}"
    source_bucket = f"{prefix}-source"
    vector_bucket = f"{prefix}-vectors"
    vector_bucket_arn = (
        f"arn:aws:s3vectors:{region}:{account_id}:bucket/{vector_bucket}"
    )
    index_arn = f"{vector_bucket_arn}/index/{INDEX_NAME}"
    role_name = f"{prefix}-knowledge-base-role"
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    knowledge_base_name = f"{prefix}-knowledge-base"
    data_source_name = f"{prefix}-source"

    s3 = session.client("s3", region_name=region)
    vectors = session.client("s3vectors", region_name=region)
    iam = session.client("iam", region_name=region)
    agent = session.client("bedrock-agent", region_name=region)

    try:
        s3.head_bucket(Bucket=source_bucket)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in {"404", "NoSuchBucket"}:
            raise
        s3.create_bucket(Bucket=source_bucket)
    s3.put_public_access_block(
        Bucket=source_bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_tagging(
        Bucket=source_bucket,
        Tagging={
            "TagSet": [
                {"Key": "Course", "Value": "tenant-03"},
                {"Key": "Activity", "Value": "H03"},
                {"Key": "ManagedBy", "Value": "guided-control-center"},
            ]
        },
    )

    try:
        vector = vectors.get_vector_bucket(vectorBucketName=vector_bucket)[
            "vectorBucket"
        ]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise
        vectors.create_vector_bucket(vectorBucketName=vector_bucket)
        vector = vectors.get_vector_bucket(vectorBucketName=vector_bucket)[
            "vectorBucket"
        ]
    if vector.get("vectorBucketArn") != vector_bucket_arn:
        raise RuntimeError("H03 vector bucket ARN does not match the fixed namespace")

    try:
        index = vectors.get_index(
            vectorBucketName=vector_bucket, indexName=INDEX_NAME
        )["index"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise
        vectors.create_index(
            vectorBucketName=vector_bucket,
            indexName=INDEX_NAME,
            dataType="float32",
            dimension=1024,
            distanceMetric="cosine",
        )
        index = vectors.get_index(
            vectorBucketName=vector_bucket, indexName=INDEX_NAME
        )["index"]
    if any(
        (
            index.get("indexArn") != index_arn,
            index.get("dimension") != 1024,
            index.get("dataType") != "float32",
            index.get("distanceMetric") != "cosine",
        )
    ):
        raise RuntimeError("H03 vector index does not match the fixed configuration")

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bedrock.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {
                        "aws:SourceArn": (
                            f"arn:aws:bedrock:{region}:{account_id}:knowledge-base/*"
                        )
                    },
                },
            }
        ],
    }
    runtime_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "InvokeTitanEmbedding",
                "Effect": "Allow",
                "Action": "bedrock:InvokeModel",
                "Resource": (
                    f"arn:aws:bedrock:{region}::foundation-model/"
                    f"{EMBEDDING_MODEL_ID}"
                ),
            },
            {
                "Sid": "ReadH03Source",
                "Effect": "Allow",
                "Action": ["s3:ListBucket", "s3:GetObject"],
                "Resource": [
                    f"arn:aws:s3:::{source_bucket}",
                    f"arn:aws:s3:::{source_bucket}/{SOURCE_PREFIX}*",
                ],
            },
            {
                "Sid": "UseH03VectorIndex",
                "Effect": "Allow",
                "Action": [
                    "s3vectors:DeleteVectors",
                    "s3vectors:GetIndex",
                    "s3vectors:GetVectors",
                    "s3vectors:PutVectors",
                    "s3vectors:QueryVectors",
                ],
                "Resource": [vector_bucket_arn, index_arn],
            },
        ],
    }
    try:
        role = iam.get_role(RoleName=role_name)["Role"]
        iam.update_assume_role_policy(
            RoleName=role_name, PolicyDocument=json.dumps(trust_policy)
        )
    except iam.exceptions.NoSuchEntityException:
        role = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Tags=[
                {"Key": "Course", "Value": "tenant-03"},
                {"Key": "Activity", "Value": "H03"},
                {"Key": "ManagedBy", "Value": "guided-control-center"},
            ],
        )["Role"]
    if role.get("Arn") != role_arn:
        raise RuntimeError("H03 IAM role does not match the fixed account")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=f"{prefix}-runtime",
        PolicyDocument=json.dumps(runtime_policy),
    )

    knowledge_base = find_one(
        agent.list_knowledge_bases(maxResults=100).get(
            "knowledgeBaseSummaries", []
        ),
        knowledge_base_name,
    )
    if knowledge_base:
        knowledge_base_id = knowledge_base["knowledgeBaseId"]
    else:
        create_args = {
            "clientToken": f"h03{uuid.uuid4().hex}",
            "name": knowledge_base_name,
            "description": "Tenant 03 H03 stale retrieval boundary",
            "roleArn": role_arn,
            "knowledgeBaseConfiguration": {
                "type": "VECTOR",
                "vectorKnowledgeBaseConfiguration": {
                    "embeddingModelArn": (
                        f"arn:aws:bedrock:{region}::foundation-model/"
                        f"{EMBEDDING_MODEL_ID}"
                    ),
                    "embeddingModelConfiguration": {
                        "bedrockEmbeddingModelConfiguration": {
                            "dimensions": 1024,
                            "embeddingDataType": "FLOAT32",
                        }
                    },
                },
            },
            "storageConfiguration": {
                "type": "S3_VECTORS",
                "s3VectorsConfiguration": {"indexArn": index_arn},
            },
            "tags": {
                "Course": "tenant-03",
                "Activity": "H03",
                "ManagedBy": "guided-control-center",
            },
        }
        last_error: ClientError | None = None
        for _ in range(6):
            try:
                created = agent.create_knowledge_base(**create_args)
                knowledge_base_id = created["knowledgeBase"]["knowledgeBaseId"]
                break
            except ClientError as exc:
                last_error = exc
                if exc.response.get("Error", {}).get("Code") != "ValidationException":
                    raise
                time.sleep(5)
        else:
            raise last_error or RuntimeError("H03 Knowledge Base creation failed")

    knowledge_base_detail = wait_for(
        lambda: agent.get_knowledge_base(knowledgeBaseId=knowledge_base_id)[
            "knowledgeBase"
        ],
        "ACTIVE",
        failed={"FAILED", "DELETE_UNSUCCESSFUL"},
    )
    if any(
        (
            knowledge_base_detail.get("name") != knowledge_base_name,
            knowledge_base_detail.get("roleArn") != role_arn,
            knowledge_base_detail.get("storageConfiguration", {})
            .get("s3VectorsConfiguration", {})
            .get("indexArn")
            != index_arn,
        )
    ):
        raise RuntimeError("H03 Knowledge Base configuration is foreign")

    data_source = find_one(
        agent.list_data_sources(
            knowledgeBaseId=knowledge_base_id, maxResults=100
        ).get("dataSourceSummaries", []),
        data_source_name,
    )
    if data_source:
        data_source_id = data_source["dataSourceId"]
    else:
        created = agent.create_data_source(
            clientToken=f"h03{uuid.uuid4().hex}",
            knowledgeBaseId=knowledge_base_id,
            name=data_source_name,
            description="Tenant 03 H03 fixed S3 source",
            dataDeletionPolicy="DELETE",
            dataSourceConfiguration={
                "type": "S3",
                "s3Configuration": {
                    "bucketArn": f"arn:aws:s3:::{source_bucket}",
                    "bucketOwnerAccountId": account_id,
                    "inclusionPrefixes": [SOURCE_PREFIX],
                },
            },
            vectorIngestionConfiguration={
                "chunkingConfiguration": {
                    "chunkingStrategy": "FIXED_SIZE",
                    "fixedSizeChunkingConfiguration": {
                        "maxTokens": 200,
                        "overlapPercentage": 20,
                    },
                }
            },
        )
        data_source_id = created["dataSource"]["dataSourceId"]
    data_source_detail = wait_for(
        lambda: agent.get_data_source(
            knowledgeBaseId=knowledge_base_id, dataSourceId=data_source_id
        )["dataSource"],
        "AVAILABLE",
        failed={"DELETE_UNSUCCESSFUL"},
    )
    source = data_source_detail.get("dataSourceConfiguration", {}).get(
        "s3Configuration", {}
    )
    if source.get("inclusionPrefixes") != [SOURCE_PREFIX]:
        raise RuntimeError("H03 data source prefix is foreign")

    return {
        "account_id": account_id,
        "source_bucket": source_bucket,
        "vector_bucket": vector_bucket,
        "knowledge_base_id": knowledge_base_id,
        "data_source_id": data_source_id,
    }


def wait_for_other_ingestion(agent: Any, resources: dict[str, str]) -> None:
    summaries = agent.list_ingestion_jobs(
        knowledgeBaseId=resources["knowledge_base_id"],
        dataSourceId=resources["data_source_id"],
        maxResults=10,
        sortBy={"attribute": "STARTED_AT", "order": "DESCENDING"},
    ).get("ingestionJobSummaries", [])
    active = next(
        (
            item
            for item in summaries
            if item.get("status") in {"STARTING", "IN_PROGRESS", "STOPPING"}
        ),
        None,
    )
    if active:
        wait_for(
            lambda: agent.get_ingestion_job(
                knowledgeBaseId=resources["knowledge_base_id"],
                dataSourceId=resources["data_source_id"],
                ingestionJobId=active["ingestionJobId"],
            )["ingestionJob"],
            "COMPLETE",
            failed={"FAILED", "STOPPED"},
        )


def start_and_wait(agent: Any, resources: dict[str, str]) -> tuple[str, float]:
    wait_for_other_ingestion(agent, resources)
    started = time.monotonic()
    job = agent.start_ingestion_job(
        knowledgeBaseId=resources["knowledge_base_id"],
        dataSourceId=resources["data_source_id"],
        description="Tenant 03 H03 live transition proof",
        clientToken=f"h03{uuid.uuid4().hex}",
    )["ingestionJob"]
    job_id = job["ingestionJobId"]
    wait_for(
        lambda: agent.get_ingestion_job(
            knowledgeBaseId=resources["knowledge_base_id"],
            dataSourceId=resources["data_source_id"],
            ingestionJobId=job_id,
        )["ingestionJob"],
        "COMPLETE",
        failed={"FAILED", "STOPPED"},
    )
    return job_id, round(time.monotonic() - started, 3)


def retrieve(runtime: Any, knowledge_base_id: str) -> dict[str, Any]:
    response = runtime.retrieve(
        knowledgeBaseId=knowledge_base_id,
        retrievalQuery={"text": QUERY},
        retrievalConfiguration={
            "vectorSearchConfiguration": {"numberOfResults": 3}
        },
    )
    results = []
    for item in response.get("retrievalResults", []):
        location = item.get("location", {})
        uri = location.get("s3Location", {}).get("uri")
        results.append(
            {
                "text": item.get("content", {}).get("text", ""),
                "source_uri": uri,
                "score": item.get("score"),
                "metadata": item.get("metadata", {}),
            }
        )
    return {"request_id": request_id(response), "results": results}


def has_marker(result: dict[str, Any], marker: str, key: str) -> bool:
    expected_suffix = f"/{key}"
    return any(
        marker in item.get("text", "")
        and str(item.get("source_uri", "")).endswith(expected_suffix)
        for item in result["results"]
    )


def wait_for_marker(
    runtime: Any,
    knowledge_base_id: str,
    marker: str,
    key: str,
    *,
    attempts: int = 30,
) -> dict[str, Any]:
    last: dict[str, Any] = {}
    for _ in range(attempts):
        last = retrieve(runtime, knowledge_base_id)
        if has_marker(last, marker, key):
            return last
        time.sleep(2)
    raise TimeoutError(f"retrieval did not return {marker}: {last}")


def main() -> None:
    args = parse_args()
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    resources = ensure_resources(session, args.region)
    s3 = session.client("s3", region_name=args.region)
    agent = session.client("bedrock-agent", region_name=args.region)
    runtime = session.client("bedrock-agent-runtime", region_name=args.region)

    old_body = (
        f"# 폐기된 접근 절차\n\n{OLD_MARKER}\n\n"
        "ORION 시스템은 공유 관리자 계정으로 접속한다는 폐기된 지침입니다."
    )
    current_body = (
        f"# 현재 접근 절차\n\n{CURRENT_MARKER}\n\n"
        "ORION 시스템은 개인 계정과 승인된 역할로만 접속한다는 현재 지침입니다."
    )
    s3.put_object(
        Bucket=resources["source_bucket"],
        Key=OLD_KEY,
        Body=old_body.encode(),
        ContentType="text/markdown; charset=utf-8",
        Metadata={"course": "tenant-03", "activity": "h03", "state": "revoked"},
    )
    s3.delete_object(Bucket=resources["source_bucket"], Key=CURRENT_KEY)
    seed_job_id, seed_seconds = start_and_wait(agent, resources)
    old_ready = wait_for_marker(
        runtime, resources["knowledge_base_id"], OLD_MARKER, OLD_KEY
    )

    s3.delete_object(Bucket=resources["source_bucket"], Key=OLD_KEY)
    s3.put_object(
        Bucket=resources["source_bucket"],
        Key=CURRENT_KEY,
        Body=current_body.encode(),
        ContentType="text/markdown; charset=utf-8",
        Metadata={"course": "tenant-03", "activity": "h03", "state": "current"},
    )

    before = [retrieve(runtime, resources["knowledge_base_id"]) for _ in range(3)]
    if not all(has_marker(item, OLD_MARKER, OLD_KEY) for item in before):
        raise AssertionError("the revoked document was not a deterministic stale hit")

    started = time.monotonic()
    current_job = agent.start_ingestion_job(
        knowledgeBaseId=resources["knowledge_base_id"],
        dataSourceId=resources["data_source_id"],
        description="Tenant 03 H03 current document transition",
        clientToken=f"h03{uuid.uuid4().hex}",
    )["ingestionJob"]
    current_job_id = current_job["ingestionJobId"]
    during = []
    for _ in range(3):
        job_state = agent.get_ingestion_job(
            knowledgeBaseId=resources["knowledge_base_id"],
            dataSourceId=resources["data_source_id"],
            ingestionJobId=current_job_id,
        )["ingestionJob"]["status"]
        result = retrieve(runtime, resources["knowledge_base_id"])
        during.append({"job_status": job_state, **result})
    wait_for(
        lambda: agent.get_ingestion_job(
            knowledgeBaseId=resources["knowledge_base_id"],
            dataSourceId=resources["data_source_id"],
            ingestionJobId=current_job_id,
        )["ingestionJob"],
        "COMPLETE",
        failed={"FAILED", "STOPPED"},
    )
    current_seconds = round(time.monotonic() - started, 3)
    wait_for_marker(
        runtime, resources["knowledge_base_id"], CURRENT_MARKER, CURRENT_KEY
    )
    after = [retrieve(runtime, resources["knowledge_base_id"]) for _ in range(3)]
    if not all(
        has_marker(item, CURRENT_MARKER, CURRENT_KEY)
        and not has_marker(item, OLD_MARKER, OLD_KEY)
        for item in after
    ):
        raise AssertionError("the completed job did not replace the revoked retrieval hit")

    print(
        json.dumps(
            {
                "course_verdict": "PASS",
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "account_id": resources["account_id"],
                "region": args.region,
                "knowledge_base_id": resources["knowledge_base_id"],
                "data_source_id": resources["data_source_id"],
                "seed_job_id": seed_job_id,
                "seed_job_seconds": seed_seconds,
                "current_job_id": current_job_id,
                "current_job_seconds": current_seconds,
                "old_ready_request_id": old_ready["request_id"],
                "before_request_ids": [item["request_id"] for item in before],
                "during": [
                    {
                        "job_status": item["job_status"],
                        "request_id": item["request_id"],
                        "old_hit": has_marker(item, OLD_MARKER, OLD_KEY),
                        "current_hit": has_marker(item, CURRENT_MARKER, CURRENT_KEY),
                    }
                    for item in during
                ],
                "during_old_hits": sum(
                    has_marker(item, OLD_MARKER, OLD_KEY) for item in during
                ),
                "during_current_hits": sum(
                    has_marker(item, CURRENT_MARKER, CURRENT_KEY) for item in during
                ),
                "after_request_ids": [item["request_id"] for item in after],
                "before_old_hits": 3,
                "after_current_hits": 3,
                "after_old_hits": 0,
                "old_source_uri": (
                    f"s3://{resources['source_bucket']}/{OLD_KEY}"
                ),
                "current_source_uri": (
                    f"s3://{resources['source_bucket']}/{CURRENT_KEY}"
                ),
                "metadata_keys": sorted(
                    {
                        key
                        for result in after
                        for item in result["results"]
                        for key in item.get("metadata", {})
                    }
                ),
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
