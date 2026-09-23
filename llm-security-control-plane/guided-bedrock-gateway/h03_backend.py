"""H03 fixed AWS namespace, ingestion jobs, and immutable retrieval evidence."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Literal

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field


AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
PROVIDER_MODE = os.getenv("GUIDED_PROVIDER_MODE", "aws")
DATABASE_PATH = os.getenv("GUIDED_GATEWAY_DATABASE", "/state/evidence.sqlite3")
RUNTIME_TOKEN = os.environ["GUIDED_H03_GATEWAY_TOKEN"]
PROVISION_TOKEN = os.environ["GUIDED_LAB03_PROVISION_TOKEN"]
VERIFIER_TOKEN = os.environ["GUIDED_VERIFIER_GATEWAY_TOKEN"]
EMBEDDING_MODEL_ID = "amazon.titan-embed-text-v2:0"
INDEX_NAME = "course-knowledge"
SOURCE_PREFIX = "h03/knowledge/"
OLD_KEY = f"{SOURCE_PREFIX}revoked-policy.md"
CURRENT_KEY = f"{SOURCE_PREFIX}current-policy.md"
QUERY = "GUIDED-H03-ORION access procedure"
OLD_MARKER = "GUIDED-H03-ORION-REVOKED"
CURRENT_MARKER = "GUIDED-H03-ORION-CURRENT"
LOCK = threading.Lock()
AWS_QUEUE_SECONDS = 5


def connect() -> sqlite3.Connection:
    database = sqlite3.connect(DATABASE_PATH, timeout=10)
    database.row_factory = sqlite3.Row
    return database


with connect() as database:
    database.execute(
        "CREATE TABLE IF NOT EXISTS h03_retrieval_evidence "
        "(execution_id TEXT NOT NULL, phase TEXT NOT NULL, provider_request_id TEXT NOT NULL UNIQUE, "
        "receipt_json TEXT NOT NULL, PRIMARY KEY(execution_id, phase))"
    )


class ProvisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    execution_id: str = Field(pattern=r"^[0-9a-f-]{36}$")


class IngestionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    execution_id: str = Field(pattern=r"^[0-9a-f-]{36}$")


class RetrievalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    execution_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    phase: Literal["early", "final"]
    ingestion_job_id: str = Field(min_length=1, max_length=40)


def bearer(expected: str, authorization: str | None) -> None:
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="invalid service credential")


def require_runtime(authorization: str | None = Header(default=None)) -> None:
    bearer(RUNTIME_TOKEN, authorization)


def require_provision(authorization: str | None = Header(default=None)) -> None:
    bearer(PROVISION_TOKEN, authorization)


def require_verifier(authorization: str | None = Header(default=None)) -> None:
    bearer(VERIFIER_TOKEN, authorization)


def load_state() -> dict[str, Any] | None:
    with connect() as database:
        row = database.execute(
            "SELECT state_json FROM resource_state WHERE logical_name='h03'"
        ).fetchone()
    return json.loads(row["state_json"]) if row else None


def save_state(state: dict[str, Any]) -> None:
    with connect() as database:
        database.execute(
            "INSERT OR REPLACE INTO resource_state VALUES('h03',?)",
            (json.dumps(state, ensure_ascii=False),),
        )


def fixed_names(account_id: str) -> dict[str, str]:
    prefix = f"owasp-llm-03-h03-{account_id}"
    vector_bucket = f"{prefix}-vectors"
    vector_bucket_arn = (
        f"arn:aws:s3vectors:{AWS_REGION}:{account_id}:bucket/{vector_bucket}"
    )
    return {
        "prefix": prefix,
        "source_bucket": f"{prefix}-source",
        "vector_bucket": vector_bucket,
        "vector_bucket_arn": vector_bucket_arn,
        "index_arn": f"{vector_bucket_arn}/index/{INDEX_NAME}",
        "role_name": f"{prefix}-knowledge-base-role",
        "role_arn": f"arn:aws:iam::{account_id}:role/{prefix}-knowledge-base-role",
        "knowledge_base_name": f"{prefix}-knowledge-base",
        "data_source_name": f"{prefix}-source",
    }


def template_digest(names: dict[str, str]) -> str:
    payload = {
        "region": AWS_REGION,
        "source_bucket": names["source_bucket"],
        "source_prefix": SOURCE_PREFIX,
        "vector_bucket": names["vector_bucket"],
        "index_name": INDEX_NAME,
        "embedding_model": EMBEDDING_MODEL_ID,
        "dimensions": 1024,
        "distance_metric": "cosine",
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def wait_for(fetch, expected: str, failed: set[str], attempts: int = 100) -> dict:
    last: dict[str, Any] = {}
    for _ in range(attempts):
        last = fetch()
        status = str(last.get("status", ""))
        if status == expected:
            return last
        if status in failed:
            raise HTTPException(status_code=502, detail=f"AWS resource entered {status}")
        time.sleep(3)
    raise HTTPException(status_code=504, detail=f"AWS resource did not reach {expected}")


def one_named(items: list[dict], name: str) -> dict | None:
    matches = [item for item in items if item.get("name") == name]
    if len(matches) > 1:
        raise HTTPException(status_code=409, detail=f"duplicate AWS resource named {name}")
    return matches[0] if matches else None


def ensure_aws_resources() -> dict[str, Any]:
    sts = boto3.client("sts", region_name=AWS_REGION)
    account_id = sts.get_caller_identity()["Account"]
    names = fixed_names(account_id)
    s3 = boto3.client("s3", region_name=AWS_REGION)
    vectors = boto3.client("s3vectors", region_name=AWS_REGION)
    iam = boto3.client("iam", region_name=AWS_REGION)
    agent = boto3.client("bedrock-agent", region_name=AWS_REGION)
    request_ids: list[str] = []

    try:
        s3.head_bucket(Bucket=names["source_bucket"])
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in {"404", "NoSuchBucket"}:
            raise
        response = s3.create_bucket(Bucket=names["source_bucket"])
        request_ids.append(response["ResponseMetadata"]["RequestId"])
    s3.put_public_access_block(
        Bucket=names["source_bucket"],
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_tagging(
        Bucket=names["source_bucket"],
        Tagging={
            "TagSet": [
                {"Key": "Course", "Value": "tenant-03"},
                {"Key": "Activity", "Value": "H03"},
                {"Key": "ManagedBy", "Value": "guided-control-center"},
            ]
        },
    )

    try:
        vector = vectors.get_vector_bucket(
            vectorBucketName=names["vector_bucket"]
        )["vectorBucket"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise
        response = vectors.create_vector_bucket(
            vectorBucketName=names["vector_bucket"]
        )
        request_ids.append(response["ResponseMetadata"]["RequestId"])
        vector = vectors.get_vector_bucket(
            vectorBucketName=names["vector_bucket"]
        )["vectorBucket"]
    if vector.get("vectorBucketArn") != names["vector_bucket_arn"]:
        raise HTTPException(status_code=409, detail="foreign H03 vector bucket")

    try:
        index = vectors.get_index(
            vectorBucketName=names["vector_bucket"], indexName=INDEX_NAME
        )["index"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise
        response = vectors.create_index(
            vectorBucketName=names["vector_bucket"],
            indexName=INDEX_NAME,
            dataType="float32",
            dimension=1024,
            distanceMetric="cosine",
        )
        request_ids.append(response["ResponseMetadata"]["RequestId"])
        index = vectors.get_index(
            vectorBucketName=names["vector_bucket"], indexName=INDEX_NAME
        )["index"]
    if any(
        (
            index.get("indexArn") != names["index_arn"],
            index.get("dimension") != 1024,
            index.get("dataType") != "float32",
            index.get("distanceMetric") != "cosine",
        )
    ):
        raise HTTPException(status_code=409, detail="foreign H03 vector index")

    trust = {
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
                            f"arn:aws:bedrock:{AWS_REGION}:{account_id}:knowledge-base/*"
                        )
                    },
                },
            }
        ],
    }
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "bedrock:InvokeModel",
                "Resource": (
                    f"arn:aws:bedrock:{AWS_REGION}::foundation-model/{EMBEDDING_MODEL_ID}"
                ),
            },
            {
                "Effect": "Allow",
                "Action": ["s3:ListBucket", "s3:GetObject"],
                "Resource": [
                    f"arn:aws:s3:::{names['source_bucket']}",
                    f"arn:aws:s3:::{names['source_bucket']}/{SOURCE_PREFIX}*",
                ],
            },
            {
                "Effect": "Allow",
                "Action": [
                    "s3vectors:DeleteVectors",
                    "s3vectors:GetIndex",
                    "s3vectors:GetVectors",
                    "s3vectors:PutVectors",
                    "s3vectors:QueryVectors",
                ],
                "Resource": [names["vector_bucket_arn"], names["index_arn"]],
            },
        ],
    }
    try:
        role = iam.get_role(RoleName=names["role_name"])["Role"]
        iam.update_assume_role_policy(
            RoleName=names["role_name"], PolicyDocument=json.dumps(trust)
        )
    except iam.exceptions.NoSuchEntityException:
        response = iam.create_role(
            RoleName=names["role_name"],
            AssumeRolePolicyDocument=json.dumps(trust),
            Tags=[
                {"Key": "Course", "Value": "tenant-03"},
                {"Key": "Activity", "Value": "H03"},
                {"Key": "ManagedBy", "Value": "guided-control-center"},
            ],
        )
        request_ids.append(response["ResponseMetadata"]["RequestId"])
        role = response["Role"]
    if role.get("Arn") != names["role_arn"]:
        raise HTTPException(status_code=409, detail="foreign H03 IAM role")
    response = iam.put_role_policy(
        RoleName=names["role_name"],
        PolicyName=f"{names['prefix']}-runtime",
        PolicyDocument=json.dumps(policy),
    )
    request_ids.append(response["ResponseMetadata"]["RequestId"])

    summary = one_named(
        agent.list_knowledge_bases(maxResults=100).get("knowledgeBaseSummaries", []),
        names["knowledge_base_name"],
    )
    if summary:
        knowledge_base_id = summary["knowledgeBaseId"]
    else:
        args = {
            "clientToken": f"h03{uuid.uuid4().hex}",
            "name": names["knowledge_base_name"],
            "description": "Tenant 03 H03 stale retrieval boundary",
            "roleArn": names["role_arn"],
            "knowledgeBaseConfiguration": {
                "type": "VECTOR",
                "vectorKnowledgeBaseConfiguration": {
                    "embeddingModelArn": (
                        f"arn:aws:bedrock:{AWS_REGION}::foundation-model/"
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
                "s3VectorsConfiguration": {"indexArn": names["index_arn"]},
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
                response = agent.create_knowledge_base(**args)
                request_ids.append(response["ResponseMetadata"]["RequestId"])
                knowledge_base_id = response["knowledgeBase"]["knowledgeBaseId"]
                break
            except ClientError as exc:
                last_error = exc
                if exc.response.get("Error", {}).get("Code") != "ValidationException":
                    raise
                time.sleep(5)
        else:
            raise last_error or RuntimeError("H03 Knowledge Base creation failed")

    detail = wait_for(
        lambda: agent.get_knowledge_base(knowledgeBaseId=knowledge_base_id)[
            "knowledgeBase"
        ],
        "ACTIVE",
        {"FAILED", "DELETE_UNSUCCESSFUL"},
    )
    if detail.get("roleArn") != names["role_arn"]:
        raise HTTPException(status_code=409, detail="foreign H03 Knowledge Base")

    summary = one_named(
        agent.list_data_sources(
            knowledgeBaseId=knowledge_base_id, maxResults=100
        ).get("dataSourceSummaries", []),
        names["data_source_name"],
    )
    if summary:
        data_source_id = summary["dataSourceId"]
    else:
        response = agent.create_data_source(
            clientToken=f"h03{uuid.uuid4().hex}",
            knowledgeBaseId=knowledge_base_id,
            name=names["data_source_name"],
            description="Tenant 03 H03 fixed S3 source",
            dataDeletionPolicy="DELETE",
            dataSourceConfiguration={
                "type": "S3",
                "s3Configuration": {
                    "bucketArn": f"arn:aws:s3:::{names['source_bucket']}",
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
        request_ids.append(response["ResponseMetadata"]["RequestId"])
        data_source_id = response["dataSource"]["dataSourceId"]
    source = wait_for(
        lambda: agent.get_data_source(
            knowledgeBaseId=knowledge_base_id, dataSourceId=data_source_id
        )["dataSource"],
        "AVAILABLE",
        {"DELETE_UNSUCCESSFUL"},
    )
    prefixes = (
        source.get("dataSourceConfiguration", {})
        .get("s3Configuration", {})
        .get("inclusionPrefixes")
    )
    if prefixes != [SOURCE_PREFIX]:
        raise HTTPException(status_code=409, detail="foreign H03 data source")
    return {
        **names,
        "account_id": account_id,
        "knowledge_base_id": knowledge_base_id,
        "data_source_id": data_source_id,
        "template_digest": template_digest(names),
        "aws_request_ids": request_ids,
    }


def get_job_aws(resources: dict, job_id: str) -> dict:
    job = boto3.client("bedrock-agent", region_name=AWS_REGION).get_ingestion_job(
        knowledgeBaseId=resources["knowledge_base_id"],
        dataSourceId=resources["data_source_id"],
        ingestionJobId=job_id,
    )["ingestionJob"]
    return {
        "ingestion_job_id": job_id,
        "status": job["status"],
        "started_at": job.get("startedAt").isoformat() if job.get("startedAt") else None,
        "updated_at": job.get("updatedAt").isoformat() if job.get("updatedAt") else None,
        "statistics": job.get("statistics", {}),
    }


def start_job_aws(resources: dict, description: str) -> dict:
    response = boto3.client("bedrock-agent", region_name=AWS_REGION).start_ingestion_job(
        knowledgeBaseId=resources["knowledge_base_id"],
        dataSourceId=resources["data_source_id"],
        description=description,
        clientToken=f"h03{uuid.uuid4().hex}",
    )
    job = response["ingestionJob"]
    return {
        "ingestion_job_id": job["ingestionJobId"],
        "status": job["status"],
        "provider_request_id": response["ResponseMetadata"]["RequestId"],
    }


def wait_job(resources: dict, job_id: str) -> dict:
    return wait_for(
        lambda: {"status": get_job_aws(resources, job_id)["status"]},
        "COMPLETE",
        {"FAILED", "STOPPED"},
    )


def wait_for_active_job(resources: dict) -> None:
    agent = boto3.client("bedrock-agent", region_name=AWS_REGION)
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
        wait_job(resources, active["ingestionJobId"])


def retrieve_aws(resources: dict) -> dict:
    response = boto3.client("bedrock-agent-runtime", region_name=AWS_REGION).retrieve(
        knowledgeBaseId=resources["knowledge_base_id"],
        retrievalQuery={"text": QUERY},
        retrievalConfiguration={"vectorSearchConfiguration": {"numberOfResults": 3}},
    )
    results = []
    for item in response.get("retrievalResults", []):
        metadata = item.get("metadata", {})
        uri = item.get("location", {}).get("s3Location", {}).get("uri")
        document_id = metadata.get("x-amz-bedrock-kb-chunk-id")
        results.append(
            {
                "document_id": document_id,
                "source_uri": uri,
                "score": item.get("score"),
                "text": item.get("content", {}).get("text", ""),
                "metadata": metadata,
            }
        )
    return {
        "provider_request_id": response["ResponseMetadata"]["RequestId"],
        "results": results,
    }


def reset_contract(execution_id: str) -> dict:
    names = fixed_names("000000000000")
    state = {
        "status": "READY_FOR_SYNC",
        "provider_mode": "contract",
        "execution_id": execution_id,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "account_id": "000000000000",
        "region": AWS_REGION,
        "source_bucket": names["source_bucket"],
        "source_prefix": SOURCE_PREFIX,
        "vector_bucket": names["vector_bucket"],
        "index_arn": names["index_arn"],
        "knowledge_base_id": "CONTRACTH03KB",
        "data_source_id": "CONTRACTH03DS",
        "template_digest": template_digest(names),
        "seed_job_id": f"contract-seed-{execution_id[:8]}",
        "old_source_uri": f"s3://{names['source_bucket']}/{OLD_KEY}",
        "current_source_uri": f"s3://{names['source_bucket']}/{CURRENT_KEY}",
        "old_source_exists": False,
        "current_source_exists": True,
        "current_job": None,
        "aws_request_ids": [f"contract-reset-{execution_id[:12]}"],
    }
    save_state(state)
    return state


def reset_aws(execution_id: str) -> dict:
    resources = ensure_aws_resources()
    wait_for_active_job(resources)
    s3 = boto3.client("s3", region_name=AWS_REGION)
    s3.put_object(
        Bucket=resources["source_bucket"],
        Key=OLD_KEY,
        Body=(
            f"# 폐기된 접근 절차\n\n{OLD_MARKER}\n\n"
            "ORION 시스템은 공유 관리자 계정으로 접속한다는 폐기된 지침입니다."
        ).encode(),
        ContentType="text/markdown; charset=utf-8",
        Metadata={"course": "tenant-03", "activity": "h03", "state": "revoked"},
    )
    s3.delete_object(Bucket=resources["source_bucket"], Key=CURRENT_KEY)
    seed = start_job_aws(resources, "Tenant 03 H03 seed revoked document")
    wait_job(resources, seed["ingestion_job_id"])
    old = retrieve_aws(resources)
    if not any(
        OLD_MARKER in item["text"] and str(item["source_uri"]).endswith(OLD_KEY)
        for item in old["results"]
    ):
        raise HTTPException(status_code=502, detail="H03 revoked baseline was not indexed")
    s3.delete_object(Bucket=resources["source_bucket"], Key=OLD_KEY)
    s3.put_object(
        Bucket=resources["source_bucket"],
        Key=CURRENT_KEY,
        Body=(
            f"# 현재 접근 절차\n\n{CURRENT_MARKER}\n\n"
            "ORION 시스템은 개인 계정과 승인된 역할로만 접속한다는 현재 지침입니다."
        ).encode(),
        ContentType="text/markdown; charset=utf-8",
        Metadata={"course": "tenant-03", "activity": "h03", "state": "current"},
    )
    state = {
        "status": "READY_FOR_SYNC",
        "provider_mode": "aws",
        "execution_id": execution_id,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "account_id": resources["account_id"],
        "region": AWS_REGION,
        "source_bucket": resources["source_bucket"],
        "source_prefix": SOURCE_PREFIX,
        "vector_bucket": resources["vector_bucket"],
        "index_arn": resources["index_arn"],
        "knowledge_base_id": resources["knowledge_base_id"],
        "data_source_id": resources["data_source_id"],
        "template_digest": resources["template_digest"],
        "seed_job_id": seed["ingestion_job_id"],
        "old_source_uri": f"s3://{resources['source_bucket']}/{OLD_KEY}",
        "current_source_uri": f"s3://{resources['source_bucket']}/{CURRENT_KEY}",
        "old_source_exists": False,
        "current_source_exists": True,
        "current_job": None,
        "aws_request_ids": resources["aws_request_ids"] + [seed["provider_request_id"]],
    }
    save_state(state)
    return state


def reset(execution_id: str) -> dict:
    if not LOCK.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="H03 reset is already running")
    try:
        return reset_contract(execution_id) if PROVIDER_MODE == "contract" else reset_aws(execution_id)
    except (BotoCoreError, ClientError) as exc:
        raise HTTPException(status_code=502, detail=f"H03 AWS reset failed: {type(exc).__name__}") from exc
    finally:
        LOCK.release()


def start_current_ingestion(execution_id: str) -> dict:
    state = load_state()
    if not state or state.get("status") != "READY_FOR_SYNC":
        raise HTTPException(status_code=409, detail="H03 baseline is not ready for sync")
    if PROVIDER_MODE == "contract":
        job = {
            "ingestion_job_id": f"contract-current-{execution_id[:8]}",
            "status": "STARTING",
            "provider_request_id": f"contract-start-{execution_id[:12]}",
            "polls": 0,
        }
    else:
        # AWS may publish new vectors before the job status becomes COMPLETE.  A
        # short server-owned queue makes the unsafe pre-completion search window
        # deterministic without fabricating the retrieval result.
        job = {
            "ingestion_job_id": f"h03-{uuid.uuid4().hex}",
            "status": "QUEUED",
            "provider_ingestion_job_id": None,
            "provider_request_id": None,
            "start_after_epoch": time.time() + AWS_QUEUE_SECONDS,
        }
    state["status"] = "SYNCING"
    state["current_job"] = job
    state["observed_at"] = datetime.now(timezone.utc).isoformat()
    save_state(state)
    return job


def current_job(job_id: str, *, advance_contract: bool) -> dict:
    state = load_state()
    job = (state or {}).get("current_job")
    if not state or not job or job.get("ingestion_job_id") != job_id:
        raise HTTPException(status_code=404, detail="H03 current job not found")
    if PROVIDER_MODE == "contract":
        if advance_contract:
            job["polls"] = int(job.get("polls", 0)) + 1
            job["status"] = "IN_PROGRESS" if job["polls"] == 1 else "COMPLETE"
            if job["status"] == "COMPLETE":
                state["status"] = "CURRENT"
            state["current_job"] = job
            save_state(state)
        return {
            "ingestion_job_id": job_id,
            "status": job["status"],
            "provider_ingestion_job_id": job_id,
            "statistics": {"numberOfNewDocumentsIndexed": 1} if job["status"] == "COMPLETE" else {},
        }
    provider_job_id = job.get("provider_ingestion_job_id")
    if provider_job_id is None:
        if not advance_contract or time.time() < float(job["start_after_epoch"]):
            return {
                "ingestion_job_id": job_id,
                "status": "QUEUED",
                "provider_ingestion_job_id": None,
                "statistics": {},
            }
        started = start_job_aws(state, "Tenant 03 H03 current document transition")
        provider_job_id = started["ingestion_job_id"]
        job.update(
            {
                "status": started["status"],
                "provider_ingestion_job_id": provider_job_id,
                "provider_request_id": started["provider_request_id"],
            }
        )
        state["current_job"] = job
        save_state(state)
    receipt = get_job_aws(state, provider_job_id)
    receipt["provider_ingestion_job_id"] = provider_job_id
    receipt["ingestion_job_id"] = job_id
    state["current_job"] = {**job, **receipt}
    if receipt["status"] == "COMPLETE":
        state["status"] = "CURRENT"
    save_state(state)
    return receipt


def retrieve_current(request: RetrievalRequest) -> dict:
    state = load_state()
    job = (state or {}).get("current_job")
    if not state or not job or job.get("ingestion_job_id") != request.ingestion_job_id:
        raise HTTPException(status_code=409, detail="retrieval is not bound to the current H03 job")
    job_receipt = current_job(request.ingestion_job_id, advance_contract=False)
    if PROVIDER_MODE == "contract":
        current = job_receipt["status"] == "COMPLETE"
        marker = CURRENT_MARKER if current else OLD_MARKER
        key = CURRENT_KEY if current else OLD_KEY
        provider = {
            "provider_request_id": f"contract-retrieve-{request.phase}-{request.execution_id[:8]}",
            "results": [
                {
                    "document_id": f"contract-{marker.lower()}",
                    "source_uri": f"s3://{state['source_bucket']}/{key}",
                    "score": 0.99,
                    "text": marker,
                    "metadata": {"x-amz-bedrock-kb-chunk-id": f"contract-{key}"},
                }
            ],
        }
    else:
        provider = retrieve_aws(state)
    observed_at = datetime.now(timezone.utc).isoformat()
    receipt = {
        "execution_id": request.execution_id,
        "phase": request.phase,
        "provider_mode": PROVIDER_MODE,
        "provider_request_id": provider["provider_request_id"],
        "observed_at": observed_at,
        "ingestion_job_id": request.ingestion_job_id,
        "job_status_at_retrieval": job_receipt["status"],
        "knowledge_base_id": state["knowledge_base_id"],
        "data_source_id": state["data_source_id"],
        "template_digest": state["template_digest"],
        "results": provider["results"],
        "source_uris": [item["source_uri"] for item in provider["results"] if item.get("source_uri")],
        "document_ids": [item["document_id"] for item in provider["results"] if item.get("document_id")],
    }
    try:
        with connect() as database:
            database.execute(
                "INSERT INTO h03_retrieval_evidence VALUES(?,?,?,?)",
                (
                    request.execution_id,
                    request.phase,
                    provider["provider_request_id"],
                    json.dumps(receipt, ensure_ascii=False),
                ),
            )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="H03 retrieval evidence already exists") from exc
    return receipt


def verification_state() -> dict:
    state = load_state()
    if not state:
        return {"status": "MISSING", "region": AWS_REGION}
    result = dict(state)
    if PROVIDER_MODE == "aws":
        s3 = boto3.client("s3", region_name=AWS_REGION)
        for label, key in (("old_source_exists", OLD_KEY), ("current_source_exists", CURRENT_KEY)):
            try:
                s3.head_object(Bucket=state["source_bucket"], Key=key)
                result[label] = True
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") in {"404", "NoSuchKey"}:
                    result[label] = False
                else:
                    raise
        documents = boto3.client("bedrock-agent", region_name=AWS_REGION).list_knowledge_base_documents(
            knowledgeBaseId=state["knowledge_base_id"],
            dataSourceId=state["data_source_id"],
            maxResults=100,
        ).get("documentDetails", [])
        result["indexed_documents"] = [
            {
                "status": item.get("status"),
                "source_uri": item.get("identifier", {}).get("s3", {}).get("uri"),
                "updated_at": item.get("updatedAt").isoformat() if item.get("updatedAt") else None,
            }
            for item in documents
        ]
    else:
        current = state.get("status") == "CURRENT"
        result["indexed_documents"] = [
            {
                "status": "INDEXED",
                "source_uri": state["current_source_uri"] if current else state["old_source_uri"],
                "updated_at": state["observed_at"],
            }
        ]
    return result


router = APIRouter()


@router.post("/v1/h03/provision")
def provision(request: ProvisionRequest, _authorized: None = Depends(require_provision)) -> dict:
    return reset(request.execution_id)


@router.post("/v1/h03/ingestions")
def start_ingestion(request: IngestionRequest, _authorized: None = Depends(require_runtime)) -> dict:
    return start_current_ingestion(request.execution_id)


@router.get("/v1/h03/ingestions/{job_id}")
def ingestion(job_id: str, _authorized: None = Depends(require_runtime)) -> dict:
    return current_job(job_id, advance_contract=True)


@router.post("/v1/h03/retrievals")
def retrieval(request: RetrievalRequest, _authorized: None = Depends(require_runtime)) -> dict:
    return retrieve_current(request)


@router.get("/v1/h03/resources")
def resources(_authorized: None = Depends(require_verifier)) -> dict:
    return verification_state()


@router.get("/v1/h03/jobs/{job_id}")
def job_evidence(job_id: str, _authorized: None = Depends(require_verifier)) -> dict:
    return current_job(job_id, advance_contract=False)


@router.get("/v1/h03/retrievals/{execution_id}/{phase}")
def retrieval_evidence(
    execution_id: str,
    phase: Literal["early", "final"],
    _authorized: None = Depends(require_verifier),
) -> dict:
    with connect() as database:
        row = database.execute(
            "SELECT receipt_json FROM h03_retrieval_evidence WHERE execution_id=? AND phase=?",
            (execution_id, phase),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="H03 retrieval evidence not found")
    return json.loads(row["receipt_json"])
