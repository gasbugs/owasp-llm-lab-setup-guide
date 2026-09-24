"""Credential boundary and immutable evidence ledger for tenant 03."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import threading
import time
import uuid
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from h03_backend import router as h03_router
from h04_backend import router as h04_router
from h07_backend import router as h07_router
from h08_backend import router as h08_router


MODEL_ID = "us.amazon.nova-lite-v1:0"
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
PROVIDER_MODE = os.getenv("GUIDED_PROVIDER_MODE", "aws")
DATABASE_PATH = os.getenv("GUIDED_GATEWAY_DATABASE", "/state/evidence.sqlite3")
LAB01_TOKEN = os.environ["GUIDED_LAB01_GATEWAY_TOKEN"]
NEMO_TOKEN = os.environ["GUIDED_NEMO_GATEWAY_TOKEN"]
VERIFIER_TOKEN = os.environ["GUIDED_VERIFIER_GATEWAY_TOKEN"]
H02_RUNTIME_TOKEN = os.environ["GUIDED_H02_GATEWAY_TOKEN"]
H02_PROVISION_TOKEN = os.environ["GUIDED_LAB02_PROVISION_TOKEN"]
H10_RUNTIME_TOKEN = os.environ["GUIDED_H10_GATEWAY_TOKEN"]
H10_VERIFIER_TOKEN = os.environ["GUIDED_H10_GATEWAY_VERIFIER_TOKEN"]
H11_RUNTIME_TOKEN = os.environ["GUIDED_H11_GATEWAY_TOKEN"]
H11_VERIFIER_TOKEN = os.environ["GUIDED_H11_GATEWAY_VERIFIER_TOKEN"]
EMBEDDING_MODEL_ID = "amazon.titan-embed-text-v2:0"
H02_PREFIX = "owasp-llm-03"
H02_INDEX_NAME = "course-knowledge"
H02_SOURCE_PREFIX = "h02/knowledge/"
H02_PROVISION_LOCK = threading.Lock()

Path(DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)


def connect() -> sqlite3.Connection:
    database = sqlite3.connect(DATABASE_PATH, timeout=10)
    database.row_factory = sqlite3.Row
    return database


with connect() as database:
    database.execute(
        """CREATE TABLE IF NOT EXISTS evidence (
        execution_id TEXT PRIMARY KEY,
        provider_request_id TEXT NOT NULL UNIQUE,
        observed_at TEXT NOT NULL,
        receipt_json TEXT NOT NULL
        )"""
    )
    database.execute(
        "CREATE TABLE IF NOT EXISTS resource_state "
        "(logical_name TEXT PRIMARY KEY, state_json TEXT NOT NULL)"
    )
    database.execute(
        """CREATE TABLE IF NOT EXISTS h10_calls (
        call_id INTEGER PRIMARY KEY AUTOINCREMENT,
        suite_id TEXT NOT NULL,
        execution_id TEXT NOT NULL,
        case_id TEXT NOT NULL,
        role TEXT NOT NULL,
        provider_request_id TEXT NOT NULL UNIQUE,
        request_digest TEXT NOT NULL,
        response_digest TEXT NOT NULL,
        output_text TEXT NOT NULL,
        observed_at TEXT NOT NULL,
        provider_mode TEXT NOT NULL,
        UNIQUE(suite_id, execution_id, role)
        )"""
    )
    database.execute(
        """CREATE TABLE IF NOT EXISTS h11_embeddings (
        call_id INTEGER PRIMARY KEY AUTOINCREMENT,
        suite_id TEXT NOT NULL,
        execution_id TEXT NOT NULL,
        item_id TEXT NOT NULL,
        provider_request_id TEXT NOT NULL UNIQUE,
        input_digest TEXT NOT NULL,
        vector_digest TEXT NOT NULL,
        dimensions INTEGER NOT NULL,
        observed_at TEXT NOT NULL,
        provider_mode TEXT NOT NULL,
        UNIQUE(suite_id, item_id)
        )"""
    )


class InvokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    execution_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    prompt: str = Field(min_length=1, max_length=4000)
    max_output_tokens: int = Field(ge=1, le=512)
    temperature: float = Field(default=0.0, ge=0.0, le=1.0)


class ChatMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: Literal["system", "user", "assistant"]
    content: str = Field(min_length=1, max_length=4000)


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")
    model: str
    messages: list[ChatMessage] = Field(min_length=1, max_length=20)
    max_tokens: int = Field(default=180, ge=1, le=512)
    temperature: float = Field(default=0.0, ge=0.0, le=1.0)
    stream: bool = False


class H02DocumentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    execution_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    started_at: str
    title: str = Field(min_length=1, max_length=120)
    body: str = Field(min_length=10, max_length=4000)
    object_key: str = Field(
        pattern=r"^h02/(knowledge|untrusted)/[0-9a-f-]{36}\.md$"
    )
    scenario: Literal["normal", "risk"]


class H02ProvisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    execution_id: str = Field(pattern=r"^[0-9a-f-]{36}$")


class H11EmbedRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suite_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    execution_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    item_id: str = Field(pattern=r"^(doc-(public|draft|foreign)|query-[a-z0-9-]+)$")
    text: str = Field(min_length=10, max_length=4000)


def bearer(expected: str, authorization: str | None) -> None:
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="invalid service credential")


def require_lab01(authorization: str | None = Header(default=None)) -> None:
    bearer(LAB01_TOKEN, authorization)


def require_nemo(authorization: str | None = Header(default=None)) -> None:
    bearer(NEMO_TOKEN, authorization)


def require_verifier(authorization: str | None = Header(default=None)) -> None:
    bearer(VERIFIER_TOKEN, authorization)


def require_h02_runtime(authorization: str | None = Header(default=None)) -> None:
    bearer(H02_RUNTIME_TOKEN, authorization)


def require_h02_provision(authorization: str | None = Header(default=None)) -> None:
    bearer(H02_PROVISION_TOKEN, authorization)


def require_h10_runtime(authorization: str | None = Header(default=None)) -> None:
    bearer(H10_RUNTIME_TOKEN, authorization)


def require_h10_verifier(authorization: str | None = Header(default=None)) -> None:
    bearer(H10_VERIFIER_TOKEN, authorization)


def require_h11_runtime(authorization: str | None = Header(default=None)) -> None:
    bearer(H11_RUNTIME_TOKEN, authorization)


def require_h11_verifier(authorization: str | None = Header(default=None)) -> None:
    bearer(H11_VERIFIER_TOKEN, authorization)


def h02_template(account_id: str) -> dict:
    prefix = f"{H02_PREFIX}-{account_id}"
    source_bucket = f"{prefix}-source"
    vector_bucket = f"{prefix}-vectors"
    vector_bucket_arn = (
        f"arn:aws:s3vectors:{AWS_REGION}:{account_id}:bucket/{vector_bucket}"
    )
    index_arn = f"{vector_bucket_arn}/index/{H02_INDEX_NAME}"
    role_name = f"{prefix}-knowledge-base-role"
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
                            f"arn:aws:bedrock:{AWS_REGION}:{account_id}:knowledge-base/*"
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
                    f"arn:aws:bedrock:{AWS_REGION}::foundation-model/{EMBEDDING_MODEL_ID}"
                ),
            },
            {
                "Sid": "ReadKnowledgeSource",
                "Effect": "Allow",
                "Action": ["s3:ListBucket", "s3:GetObject"],
                "Resource": [
                    f"arn:aws:s3:::{source_bucket}",
                    f"arn:aws:s3:::{source_bucket}/{H02_SOURCE_PREFIX}*",
                ],
            },
            {
                "Sid": "UseS3VectorIndex",
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
    public_template = {
        "region": AWS_REGION,
        "embedding_model_id": EMBEDDING_MODEL_ID,
        "dimensions": 1024,
        "source_bucket": source_bucket,
        "source_prefix": H02_SOURCE_PREFIX,
        "vector_bucket": vector_bucket,
        "vector_index": H02_INDEX_NAME,
        "knowledge_base_name": f"{prefix}-knowledge-base",
        "data_source_name": f"{prefix}-source",
        "role_name": role_name,
        "allowed_actions": [
            "S3 PutObject into the fixed H02 bucket",
            "Titan Text Embeddings V2 InvokeModel",
            "fixed Knowledge Base and Data Source provisioning",
        ],
    }
    digest = hashlib.sha256(
        json.dumps(
            {"template": public_template, "trust": trust_policy, "runtime": runtime_policy},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    return {
        **public_template,
        "account_id": account_id,
        "vector_bucket_arn": vector_bucket_arn,
        "index_arn": index_arn,
        "role_arn": f"arn:aws:iam::{account_id}:role/{role_name}",
        "trust_policy": trust_policy,
        "runtime_policy": runtime_policy,
        "template_digest": digest,
    }


def load_h02_state() -> dict | None:
    with connect() as database:
        row = database.execute(
            "SELECT state_json FROM resource_state WHERE logical_name='h02'"
        ).fetchone()
    return json.loads(row["state_json"]) if row else None


def save_h02_state(state: dict) -> None:
    with connect() as database:
        database.execute(
            "INSERT OR REPLACE INTO resource_state VALUES('h02',?)",
            (json.dumps(state, ensure_ascii=False),),
        )


def contract_h02_state(execution_id: str) -> dict:
    template = h02_template("000000000000")
    state = {
        "status": "READY",
        "execution_id": execution_id,
        "provider_mode": "contract",
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "account_id": template["account_id"],
        "region": AWS_REGION,
        "template_digest": template["template_digest"],
        "source_bucket": template["source_bucket"],
        "source_prefix": H02_SOURCE_PREFIX,
        "vector_bucket": template["vector_bucket"],
        "index_arn": template["index_arn"],
        "knowledge_base_id": "CONTRACTKB",
        "data_source_id": "CONTRACTDS",
        "embedding_model_id": EMBEDDING_MODEL_ID,
        "dimensions": 1024,
        "aws_request_ids": [f"contract-provision-{execution_id[:12]}"],
    }
    save_h02_state(state)
    return state


def wait_for_status(fetch, ready: str, *, attempts: int = 60) -> dict:
    current = {}
    for _ in range(attempts):
        current = fetch()
        if current.get("status") == ready:
            return current
        if current.get("status") == "FAILED":
            raise HTTPException(status_code=502, detail="AWS resource creation failed")
        time.sleep(3)
    raise HTTPException(status_code=504, detail="AWS resource creation timed out")


def provision_h02_aws(execution_id: str) -> dict:
    sts = boto3.client("sts", region_name=AWS_REGION)
    account_id = sts.get_caller_identity()["Account"]
    template = h02_template(account_id)
    request_ids: list[str] = []
    s3 = boto3.client("s3", region_name=AWS_REGION)
    s3vectors = boto3.client("s3vectors", region_name=AWS_REGION)
    iam = boto3.client("iam", region_name=AWS_REGION)
    agent = boto3.client("bedrock-agent", region_name=AWS_REGION)

    try:
        s3.head_bucket(Bucket=template["source_bucket"])
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in {"404", "NoSuchBucket"}:
            raise
        created = s3.create_bucket(Bucket=template["source_bucket"])
        request_ids.append(created["ResponseMetadata"]["RequestId"])
    s3.put_public_access_block(
        Bucket=template["source_bucket"],
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_tagging(
        Bucket=template["source_bucket"],
        Tagging={
            "TagSet": [
                {"Key": "Course", "Value": "tenant-03"},
                {"Key": "Activity", "Value": "H02"},
                {"Key": "ManagedBy", "Value": "guided-control-center"},
            ]
        },
    )

    try:
        vector = s3vectors.get_vector_bucket(
            vectorBucketName=template["vector_bucket"]
        )["vectorBucket"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise
        created = s3vectors.create_vector_bucket(
            vectorBucketName=template["vector_bucket"]
        )
        request_ids.append(created["ResponseMetadata"]["RequestId"])
        vector = s3vectors.get_vector_bucket(
            vectorBucketName=template["vector_bucket"]
        )["vectorBucket"]
    if vector["vectorBucketArn"] != template["vector_bucket_arn"]:
        raise HTTPException(status_code=409, detail="foreign vector bucket")

    try:
        index = s3vectors.get_index(
            vectorBucketName=template["vector_bucket"], indexName=H02_INDEX_NAME
        )["index"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise
        created = s3vectors.create_index(
            vectorBucketName=template["vector_bucket"],
            indexName=H02_INDEX_NAME,
            dataType="float32",
            dimension=1024,
            distanceMetric="cosine",
        )
        request_ids.append(created["ResponseMetadata"]["RequestId"])
        index = s3vectors.get_index(
            vectorBucketName=template["vector_bucket"], indexName=H02_INDEX_NAME
        )["index"]
    if any(
        (
            index.get("indexArn") != template["index_arn"],
            index.get("dimension") != 1024,
            index.get("dataType") != "float32",
            index.get("distanceMetric") != "cosine",
        )
    ):
        raise HTTPException(status_code=409, detail="foreign vector index configuration")

    try:
        role = iam.get_role(RoleName=template["role_name"])["Role"]
        iam.update_assume_role_policy(
            RoleName=template["role_name"],
            PolicyDocument=json.dumps(template["trust_policy"]),
        )
    except iam.exceptions.NoSuchEntityException:
        created = iam.create_role(
            RoleName=template["role_name"],
            AssumeRolePolicyDocument=json.dumps(template["trust_policy"]),
            Tags=[
                {"Key": "Course", "Value": "tenant-03"},
                {"Key": "Activity", "Value": "H02"},
                {"Key": "ManagedBy", "Value": "guided-control-center"},
            ],
        )
        request_ids.append(created["ResponseMetadata"]["RequestId"])
        role = created["Role"]
    if role["Arn"] != template["role_arn"]:
        raise HTTPException(status_code=409, detail="foreign IAM role")
    policy = iam.put_role_policy(
        RoleName=template["role_name"],
        PolicyName=f"{H02_PREFIX}-knowledge-base-runtime",
        PolicyDocument=json.dumps(template["runtime_policy"]),
    )
    request_ids.append(policy["ResponseMetadata"]["RequestId"])

    summaries = agent.list_knowledge_bases(maxResults=100).get(
        "knowledgeBaseSummaries", []
    )
    matches = [
        item
        for item in summaries
        if item.get("name") == template["knowledge_base_name"]
    ]
    if len(matches) > 1:
        raise HTTPException(status_code=409, detail="duplicate Knowledge Bases")
    if matches:
        knowledge_base_id = matches[0]["knowledgeBaseId"]
    else:
        create_args = {
            "clientToken": f"h02{uuid.uuid4().hex}",
            "name": template["knowledge_base_name"],
            "description": "Tenant 03 H02 Knowledge Base",
            "roleArn": template["role_arn"],
            "knowledgeBaseConfiguration": {
                "type": "VECTOR",
                "vectorKnowledgeBaseConfiguration": {
                    "embeddingModelArn": (
                        f"arn:aws:bedrock:{AWS_REGION}::foundation-model/{EMBEDDING_MODEL_ID}"
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
                "s3VectorsConfiguration": {"indexArn": template["index_arn"]},
            },
            "tags": {
                "Course": "tenant-03",
                "Activity": "H02",
                "ManagedBy": "guided-control-center",
            },
        }
        last_error: ClientError | None = None
        for _ in range(6):
            try:
                created = agent.create_knowledge_base(**create_args)
                request_ids.append(created["ResponseMetadata"]["RequestId"])
                knowledge_base_id = created["knowledgeBase"]["knowledgeBaseId"]
                break
            except ClientError as exc:
                last_error = exc
                if exc.response.get("Error", {}).get("Code") != "ValidationException":
                    raise
                time.sleep(5)
        else:
            raise last_error or RuntimeError("Knowledge Base creation failed")

    knowledge_base = wait_for_status(
        lambda: agent.get_knowledge_base(knowledgeBaseId=knowledge_base_id)[
            "knowledgeBase"
        ],
        "ACTIVE",
    )
    if any(
        (
            knowledge_base.get("name") != template["knowledge_base_name"],
            knowledge_base.get("roleArn") != template["role_arn"],
            knowledge_base.get("storageConfiguration", {})
            .get("s3VectorsConfiguration", {})
            .get("indexArn")
            != template["index_arn"],
        )
    ):
        raise HTTPException(status_code=409, detail="foreign Knowledge Base configuration")

    summaries = agent.list_data_sources(
        knowledgeBaseId=knowledge_base_id, maxResults=100
    ).get("dataSourceSummaries", [])
    matches = [
        item for item in summaries if item.get("name") == template["data_source_name"]
    ]
    if len(matches) > 1:
        raise HTTPException(status_code=409, detail="duplicate data sources")
    if matches:
        data_source_id = matches[0]["dataSourceId"]
    else:
        created = agent.create_data_source(
            clientToken=f"h02{uuid.uuid4().hex}",
            knowledgeBaseId=knowledge_base_id,
            name=template["data_source_name"],
            description="Tenant 03 H02 fixed S3 source",
            dataDeletionPolicy="DELETE",
            dataSourceConfiguration={
                "type": "S3",
                "s3Configuration": {
                    "bucketArn": f"arn:aws:s3:::{template['source_bucket']}",
                    "bucketOwnerAccountId": account_id,
                    "inclusionPrefixes": [H02_SOURCE_PREFIX],
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
        request_ids.append(created["ResponseMetadata"]["RequestId"])
        data_source_id = created["dataSource"]["dataSourceId"]
    data_source = wait_for_status(
        lambda: agent.get_data_source(
            knowledgeBaseId=knowledge_base_id, dataSourceId=data_source_id
        )["dataSource"],
        "AVAILABLE",
    )
    source_config = data_source.get("dataSourceConfiguration", {}).get(
        "s3Configuration", {}
    )
    if any(
        (
            source_config.get("bucketArn")
            != f"arn:aws:s3:::{template['source_bucket']}",
            source_config.get("bucketOwnerAccountId") != account_id,
            source_config.get("inclusionPrefixes") != [H02_SOURCE_PREFIX],
        )
    ):
        raise HTTPException(status_code=409, detail="foreign data source configuration")

    state = {
        "status": "READY",
        "execution_id": execution_id,
        "provider_mode": "aws",
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "account_id": account_id,
        "region": AWS_REGION,
        "template_digest": template["template_digest"],
        "source_bucket": template["source_bucket"],
        "source_prefix": H02_SOURCE_PREFIX,
        "vector_bucket": template["vector_bucket"],
        "index_arn": template["index_arn"],
        "knowledge_base_id": knowledge_base_id,
        "data_source_id": data_source_id,
        "embedding_model_id": EMBEDDING_MODEL_ID,
        "dimensions": 1024,
        "aws_request_ids": request_ids,
    }
    save_h02_state(state)
    return state


def provision_h02(execution_id: str) -> dict:
    if not H02_PROVISION_LOCK.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="H02 provisioning is already running")
    try:
        if PROVIDER_MODE == "contract":
            return contract_h02_state(execution_id)
        return provision_h02_aws(execution_id)
    except (BotoCoreError, ClientError) as exc:
        raise HTTPException(
            status_code=502, detail=f"H02 AWS provisioning failed: {type(exc).__name__}"
        ) from exc
    finally:
        H02_PROVISION_LOCK.release()


def call_titan_and_store(request: H02DocumentRequest, state: dict) -> dict:
    if PROVIDER_MODE == "contract":
        digest = hashlib.sha256(
            f"{request.execution_id}:{request.body}".encode()
        ).hexdigest()
        return {
            "provider_request_id": f"contract-titan-{digest[:16]}",
            "s3_request_id": f"contract-s3-{digest[16:32]}",
            "input_token_count": max(1, len(request.body.split())),
            "embedding_dimension": 1024,
            "embedding_norm": 1.0,
            "object_exists": True,
        }

    runtime = boto3.client("bedrock-runtime", region_name=AWS_REGION)
    result = runtime.invoke_model(
        modelId=EMBEDDING_MODEL_ID,
        contentType="application/json",
        accept="application/json",
        body=json.dumps(
            {"inputText": request.body, "dimensions": 1024, "normalize": True}
        ),
    )
    provider_id = result.get("ResponseMetadata", {}).get("RequestId")
    payload = json.loads(result["body"].read())
    embedding = payload.get("embedding")
    if not provider_id or not isinstance(embedding, list) or len(embedding) != 1024:
        raise HTTPException(status_code=502, detail="Titan embedding evidence is invalid")
    norm = sum(float(value) ** 2 for value in embedding) ** 0.5
    stored = boto3.client("s3", region_name=AWS_REGION).put_object(
        Bucket=state["source_bucket"],
        Key=request.object_key,
        Body=(f"# {request.title}\n\n{request.body}\n").encode(),
        ContentType="text/markdown; charset=utf-8",
        Metadata={"course": "tenant-03", "activity": "h02"},
    )
    return {
        "provider_request_id": provider_id,
        "s3_request_id": stored["ResponseMetadata"]["RequestId"],
        "input_token_count": payload.get("inputTextTokenCount"),
        "embedding_dimension": len(embedding),
        "embedding_norm": round(norm, 6),
        "object_exists": True,
    }


def config_digest(max_output_tokens: int, temperature: float) -> str:
    payload = {
        "model_id": MODEL_ID,
        "inference_config": {
            "maxTokens": max_output_tokens,
            "temperature": temperature,
        },
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def call_provider(
    prompt: str, max_output_tokens: int, temperature: float, request_identity: str
) -> dict:
    if PROVIDER_MODE == "contract":
        request_id = hashlib.sha256(
            f"{request_identity}:{prompt}:{max_output_tokens}:{temperature}".encode()
        ).hexdigest()[:24]
        if "XSS-REGRESSION" in prompt:
            text = '<img src=x onerror="window.__guided_xss=true"><script>window.__guided_xss=true</script>'
        else:
            text = "계약 테스트 응답입니다. " + ("안전한 출력 상한을 확인했습니다. " * 8)
        # The fixed risk probe must consume the forwarded allowance so an
        # unbounded starter is deterministically distinguishable from a fix.
        output_tokens = (
            max_output_tokens
            if "GUIDED-H01-RISK" in prompt
            else min(max_output_tokens, 48)
        )
        return {
            "request_id": f"contract-{request_id}",
            "text": text,
            "stop_reason": "max_tokens" if output_tokens == max_output_tokens else "end_turn",
            "usage": {
                "inputTokens": 18,
                "outputTokens": output_tokens,
                "totalTokens": 18 + output_tokens,
            },
            "provider_mode": "contract",
        }

    try:
        result = boto3.client("bedrock-runtime", region_name=AWS_REGION).converse(
            modelId=MODEL_ID,
            messages=[{"role": "user", "content": [{"text": prompt}]}],
            inferenceConfig={
                "maxTokens": max_output_tokens,
                "temperature": temperature,
            },
        )
    except (BotoCoreError, ClientError) as exc:
        raise HTTPException(
            status_code=502, detail=f"Bedrock Converse failed: {type(exc).__name__}"
        ) from exc

    request_id = result.get("ResponseMetadata", {}).get("RequestId")
    if not request_id:
        raise HTTPException(status_code=502, detail="provider request ID is missing")
    usage = result.get("usage")
    if not isinstance(usage, dict) or any(
        type(usage.get(field)) is not int
        for field in ("inputTokens", "outputTokens", "totalTokens")
    ):
        raise HTTPException(status_code=502, detail="provider usage is missing")
    text = "".join(
        part.get("text", "")
        for part in result.get("output", {}).get("message", {}).get("content", [])
    )
    return {
        "request_id": request_id,
        "text": text,
        "stop_reason": result.get("stopReason", "unknown"),
        "usage": usage,
        "provider_mode": "aws",
    }


def invoke_once(request: InvokeRequest) -> dict:
    with connect() as database:
        if database.execute(
            "SELECT 1 FROM evidence WHERE execution_id=?", (request.execution_id,)
        ).fetchone():
            raise HTTPException(status_code=409, detail="execution ID already exists")

    provider = call_provider(
        request.prompt,
        request.max_output_tokens,
        request.temperature,
        request.execution_id,
    )
    observed_at = datetime.now(timezone.utc).isoformat()
    digest = config_digest(request.max_output_tokens, request.temperature)
    receipt = {
        "execution_id": request.execution_id,
        "provider_request_id": provider["request_id"],
        "provider_mode": provider["provider_mode"],
        "observed_at": observed_at,
        "model_id": MODEL_ID,
        "region": AWS_REGION,
        "forwarded_parameters": {
            "maxTokens": request.max_output_tokens,
            "temperature": request.temperature,
        },
        "usage": provider["usage"],
        "stop_reason": provider["stop_reason"],
        "output_text": provider["text"],
        "config_digest": digest,
    }
    try:
        with connect() as database:
            database.execute(
                "INSERT INTO evidence VALUES(?,?,?,?)",
                (
                    request.execution_id,
                    provider["request_id"],
                    observed_at,
                    json.dumps(receipt, ensure_ascii=False),
                ),
            )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="provider evidence already used") from exc
    return receipt


app = FastAPI(title="Tenant 03 Bedrock Gateway", docs_url=None, redoc_url=None)
app.include_router(h03_router)
app.include_router(h04_router)
app.include_router(h07_router)
app.include_router(h08_router)


@app.get("/livez")
def livez() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/readyz")
def readyz() -> dict[str, str]:
    with connect() as database:
        database.execute("SELECT 1").fetchone()
    return {"status": "ready", "provider_check": "not-run"}


@app.post("/v1/nova/invoke")
def invoke(request: InvokeRequest, _authorized: None = Depends(require_lab01)) -> dict:
    return invoke_once(request)


@app.post("/v1/provider-preflight")
def provider_preflight(
    request: InvokeRequest, _authorized: None = Depends(require_lab01)
) -> dict:
    if request.max_output_tokens > 2:
        raise HTTPException(status_code=422, detail="preflight max output is 2")
    return invoke_once(request)


@app.get("/v1/h02/template")
def h02_public_template(
    _authorized: None = Depends(require_h02_provision),
) -> dict:
    account_id = (
        "000000000000"
        if PROVIDER_MODE == "contract"
        else boto3.client("sts", region_name=AWS_REGION).get_caller_identity()["Account"]
    )
    template = h02_template(account_id)
    return {
        key: value
        for key, value in template.items()
        if key not in {"trust_policy", "runtime_policy"}
    } | {
        "trust_policy": template["trust_policy"],
        "runtime_policy": template["runtime_policy"],
    }


@app.post("/v1/h02/provision")
def h02_provision(
    request: H02ProvisionRequest,
    _authorized: None = Depends(require_h02_provision),
) -> dict:
    return provision_h02(request.execution_id)


@app.post("/v1/h02/documents")
def h02_documents(
    request: H02DocumentRequest,
    _authorized: None = Depends(require_h02_runtime),
) -> dict:
    with connect() as database:
        if database.execute(
            "SELECT 1 FROM evidence WHERE execution_id=?", (request.execution_id,)
        ).fetchone():
            raise HTTPException(status_code=409, detail="execution ID already exists")
    state = load_h02_state()
    if not state or state.get("status") != "READY":
        raise HTTPException(status_code=409, detail="H02 resources are not ready")
    try:
        provider = call_titan_and_store(request, state)
    except (BotoCoreError, ClientError) as exc:
        raise HTTPException(
            status_code=502, detail=f"H02 document call failed: {type(exc).__name__}"
        ) from exc
    observed_at = datetime.now(timezone.utc).isoformat()
    receipt = {
        "execution_id": request.execution_id,
        "started_at": request.started_at,
        "observed_at": observed_at,
        "scenario": request.scenario,
        "provider_mode": PROVIDER_MODE,
        "provider_request_id": provider["provider_request_id"],
        "s3_request_id": provider["s3_request_id"],
        "model_id": EMBEDDING_MODEL_ID,
        "region": AWS_REGION,
        "object_key": request.object_key,
        "object_uri": f"s3://{state['source_bucket']}/{request.object_key}",
        "object_exists": provider["object_exists"],
        "embedding_dimension": provider["embedding_dimension"],
        "embedding_norm": provider["embedding_norm"],
        "input_token_count": provider["input_token_count"],
        "knowledge_base_id": state["knowledge_base_id"],
        "data_source_id": state["data_source_id"],
        "template_digest": state["template_digest"],
        "upstream_called": True,
    }
    try:
        with connect() as database:
            database.execute(
                "INSERT INTO evidence VALUES(?,?,?,?)",
                (
                    request.execution_id,
                    provider["provider_request_id"],
                    observed_at,
                    json.dumps(receipt, ensure_ascii=False),
                ),
            )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="provider evidence already used") from exc
    return receipt


@app.get("/v1/h02/resources")
def h02_resources(_authorized: None = Depends(require_verifier)) -> dict:
    state = load_h02_state()
    if not state:
        return {"status": "MISSING", "region": AWS_REGION}
    return state


@app.get("/v1/h02/evidence/{execution_id}")
def h02_evidence(
    execution_id: str, _authorized: None = Depends(require_verifier)
) -> dict:
    with connect() as database:
        row = database.execute(
            "SELECT receipt_json FROM evidence WHERE execution_id=?", (execution_id,)
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="evidence not found")
    receipt = json.loads(row["receipt_json"])
    if receipt.get("model_id") != EMBEDDING_MODEL_ID:
        raise HTTPException(status_code=404, detail="H02 evidence not found")
    if PROVIDER_MODE == "aws":
        try:
            boto3.client("s3", region_name=AWS_REGION).head_object(
                Bucket=receipt["object_uri"].split("/", 3)[2],
                Key=receipt["object_key"],
            )
        except (BotoCoreError, ClientError):
            receipt["object_exists"] = False
    return receipt


@app.get("/v1/evidence/{execution_id}")
def evidence(
    execution_id: str, _authorized: None = Depends(require_verifier)
) -> dict:
    with connect() as database:
        row = database.execute(
            "SELECT receipt_json FROM evidence WHERE execution_id=?", (execution_id,)
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="evidence not found")
    return json.loads(row["receipt_json"])


@app.post("/v1/h11/embeddings")
def h11_embedding(
    request: H11EmbedRequest,
    _authorized: None = Depends(require_h11_runtime),
) -> dict:
    """Return an H11-only Titan vector and retain immutable provider evidence."""
    input_digest = hashlib.sha256(request.text.encode()).hexdigest()
    if PROVIDER_MODE == "contract":
        generator = random.Random(int(input_digest, 16))
        vector = [generator.uniform(-1.0, 1.0) for _ in range(1024)]
        norm = sum(value * value for value in vector) ** 0.5
        vector = [value / norm for value in vector]
        provider_request_id = f"contract-h11-{hashlib.sha256((request.execution_id + request.item_id).encode()).hexdigest()[:24]}"
    else:
        try:
            result = boto3.client("bedrock-runtime", region_name=AWS_REGION).invoke_model(
                modelId=EMBEDDING_MODEL_ID,
                contentType="application/json",
                accept="application/json",
                body=json.dumps(
                    {"inputText": request.text, "dimensions": 1024, "normalize": True}
                ),
            )
        except (BotoCoreError, ClientError) as exc:
            raise HTTPException(status_code=502, detail=f"H11 Titan call failed: {type(exc).__name__}") from exc
        provider_request_id = result.get("ResponseMetadata", {}).get("RequestId")
        payload = json.loads(result["body"].read())
        vector = payload.get("embedding")
        if not provider_request_id or not isinstance(vector, list) or len(vector) != 1024:
            raise HTTPException(status_code=502, detail="H11 Titan evidence is invalid")
    vector_digest = hashlib.sha256(
        json.dumps(vector, separators=(",", ":")).encode()
    ).hexdigest()
    observed_at = datetime.now(timezone.utc).isoformat()
    try:
        with connect() as database:
            database.execute(
                "INSERT INTO h11_embeddings "
                "(suite_id,execution_id,item_id,provider_request_id,input_digest,vector_digest,dimensions,observed_at,provider_mode) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    request.suite_id,
                    request.execution_id,
                    request.item_id,
                    provider_request_id,
                    input_digest,
                    vector_digest,
                    1024,
                    observed_at,
                    PROVIDER_MODE,
                ),
            )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="H11 embedding evidence already exists") from exc
    return {
        "model_id": EMBEDDING_MODEL_ID,
        "dimensions": 1024,
        "provider_request_id": provider_request_id,
        "vector": vector,
        "vector_digest": vector_digest,
    }


@app.get("/v1/h11/suites/{suite_id}/ledger")
def h11_ledger(
    suite_id: str, _authorized: None = Depends(require_h11_verifier)
) -> dict:
    with connect() as database:
        rows = database.execute(
            "SELECT * FROM h11_embeddings WHERE suite_id=? ORDER BY call_id", (suite_id,)
        ).fetchall()
    return {"suite_id": suite_id, "calls": [dict(row) for row in rows]}


@app.post("/v1/h10/chat/completions")
def h10_chat(
    request: ChatRequest,
    x_guided_suite_id: str = Header(alias="X-Guided-Suite-Id"),
    x_guided_execution_id: str = Header(alias="X-Guided-Execution-Id"),
    x_guided_case_id: str = Header(alias="X-Guided-Case-Id"),
    x_guided_role: Literal["main", "self_check_output"] = Header(
        alias="X-Guided-Role"
    ),
    _authorized: None = Depends(require_h10_runtime),
) -> dict:
    """Call Nova Lite for H10 and keep independently readable role evidence."""
    if request.stream:
        raise HTTPException(status_code=422, detail="streaming is not enabled")
    if x_guided_case_id not in {
        "normal-reset-guide",
        "normal-report-secret",
        "risk-recovery-code",
        "risk-internal-note",
    }:
        raise HTTPException(status_code=422, detail="unknown H10 case")
    expected_model = f"{MODEL_ID}#h10-{x_guided_role.replace('_', '-')}"
    if request.model != expected_model:
        raise HTTPException(status_code=403, detail="H10 model role mismatch")
    prompt = "\n".join(message.content for message in request.messages)
    identity = f"{x_guided_suite_id}:{x_guided_execution_id}:{x_guided_role}"
    if PROVIDER_MODE == "contract":
        if x_guided_role == "self_check_output":
            text = (
                "Yes"
                if "Block synthetic recovery codes and internal-only notes used by this application." in prompt
                and x_guided_case_id in {"risk-recovery-code", "risk-internal-note"}
                else "No"
            )
        elif x_guided_case_id == "risk-recovery-code":
            text = "H10-RECOVERY-CODE-4821"
        elif x_guided_case_id == "risk-internal-note":
            text = "H10-INTERNAL-NOTE"
        else:
            text = "본인 확인 뒤 계정 복구 절차를 진행하세요."
        provider = {
            "request_id": "contract-h10-" + hashlib.sha256(identity.encode()).hexdigest()[:24],
            "text": text,
            "stop_reason": "end_turn",
            "usage": {"inputTokens": 20, "outputTokens": 8, "totalTokens": 28},
            "provider_mode": "contract",
        }
    else:
        provider = call_provider(prompt, request.max_tokens, request.temperature, identity)
    observed_at = datetime.now(timezone.utc).isoformat()
    receipt = {
        "suite_id": x_guided_suite_id,
        "execution_id": x_guided_execution_id,
        "case_id": x_guided_case_id,
        "role": x_guided_role,
        "provider_request_id": provider["request_id"],
        "request_digest": hashlib.sha256(prompt.encode()).hexdigest(),
        "response_digest": hashlib.sha256(provider["text"].encode()).hexdigest(),
        "output_text": provider["text"],
        "observed_at": observed_at,
        "provider_mode": provider["provider_mode"],
        "usage": provider["usage"],
        "stop_reason": provider["stop_reason"],
    }
    try:
        with connect() as database:
            database.execute(
                "INSERT INTO h10_calls "
                "(suite_id,execution_id,case_id,role,provider_request_id,request_digest,response_digest,output_text,observed_at,provider_mode) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    x_guided_suite_id,
                    x_guided_execution_id,
                    x_guided_case_id,
                    x_guided_role,
                    provider["request_id"],
                    receipt["request_digest"],
                    receipt["response_digest"],
                    provider["text"],
                    observed_at,
                    provider["provider_mode"],
                ),
            )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="H10 role call already exists") from exc
    return {
        "id": provider["request_id"],
        "object": "chat.completion",
        "model": MODEL_ID,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": provider["text"]}, "finish_reason": "stop"}],
        "usage": {
            "prompt_tokens": provider["usage"]["inputTokens"],
            "completion_tokens": provider["usage"]["outputTokens"],
            "total_tokens": provider["usage"]["totalTokens"],
        },
    }


@app.get("/v1/h10/suites/{suite_id}/ledger")
def h10_ledger(
    suite_id: str, _authorized: None = Depends(require_h10_verifier)
) -> dict:
    with connect() as database:
        rows = database.execute(
            "SELECT * FROM h10_calls WHERE suite_id=? ORDER BY call_id", (suite_id,)
        ).fetchall()
    return {"suite_id": suite_id, "calls": [dict(row) for row in rows]}


@app.post("/v1/chat/completions")
def chat(request: ChatRequest, _authorized: None = Depends(require_nemo)) -> dict:
    if request.stream:
        raise HTTPException(status_code=422, detail="streaming is not enabled")
    prompt = "\n".join(message.content for message in request.messages)
    provider = call_provider(prompt, request.max_tokens, request.temperature, str(uuid.uuid4()))
    return {
        "id": provider["request_id"],
        "object": "chat.completion",
        "model": MODEL_ID,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": provider["text"]},
                "finish_reason": "length"
                if provider["stop_reason"] == "max_tokens"
                else "stop",
            }
        ],
        "usage": {
            "prompt_tokens": provider["usage"]["inputTokens"],
            "completion_tokens": provider["usage"]["outputTokens"],
            "total_tokens": provider["usage"]["totalTokens"],
        },
    }
