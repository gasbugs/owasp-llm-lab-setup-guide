"""Server-owned P03 AWS specification and read-only reuse audit.

This module never creates, repairs, deletes, uploads, or starts ingestion.
An absent set is distinct from a partially prepared or foreign set.
"""
from copy import deepcopy
import hashlib
import json
import re

from botocore.exceptions import ClientError

from p03_ledger import LedgerError

TAGS = {"Course": "tenant-03", "Activity": "P03", "ManagedBy": "guided-control-center"}
PUBLIC_BLOCK = dict.fromkeys(("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"), True)
MODEL = "amazon.titan-embed-text-v2:0"
PREFIX = "h03/knowledge/"


def template(account_id, region="us-east-1"):
    if not isinstance(account_id, str) or not re.fullmatch(r"[0-9]{12}", account_id) or region != "us-east-1":
        raise ValueError("P03 requires an AWS account and the configured course region")
    stem = "owasp-guided-p03-" + account_id
    bucket, vectors, role = stem + "-source", stem + "-vectors", stem + "-kb-role"
    vector_arn = f"arn:aws:s3vectors:{region}:{account_id}:bucket/{vectors}"
    index_arn = vector_arn + "/index/knowledge"
    model_arn = f"arn:aws:bedrock:{region}::foundation-model/{MODEL}"
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "bedrock.amazonaws.com"},
        "Action": "sts:AssumeRole", "Condition": {"StringEquals": {"aws:SourceAccount": account_id},
        "ArnLike": {"aws:SourceArn": f"arn:aws:bedrock:{region}:{account_id}:knowledge-base/*"}}}]}
    runtime = {"Version": "2012-10-17", "Statement": [
        {"Sid": "EmbedSource", "Effect": "Allow", "Action": "bedrock:InvokeModel", "Resource": model_arn},
        {"Sid": "ListSource", "Effect": "Allow", "Action": "s3:ListBucket", "Resource": f"arn:aws:s3:::{bucket}",
         "Condition": {"StringLike": {"s3:prefix": [PREFIX + "*"]}}},
        {"Sid": "ReadSource", "Effect": "Allow", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bucket}/{PREFIX}*"},
        {"Sid": "UseVectorIndex", "Effect": "Allow", "Action": ["s3vectors:DeleteVectors", "s3vectors:GetIndex",
         "s3vectors:GetVectors", "s3vectors:PutVectors", "s3vectors:QueryVectors"], "Resource": index_arn},
    ]}
    result = {"account_id": account_id, "region": region, "source_bucket": bucket, "source_prefix": PREFIX,
        "vector_bucket": vectors, "vector_bucket_arn": vector_arn, "vector_index": "knowledge", "index_arn": index_arn,
        "role_name": role, "role_arn": f"arn:aws:iam::{account_id}:role/{role}", "policy_name": "guided-p03-kb-runtime",
        "knowledge_base_name": stem + "-knowledge-base", "data_source_name": stem + "-source",
        "trust_policy": trust, "runtime_policy": runtime, "tags": deepcopy(TAGS),
        "public_access_block": deepcopy(PUBLIC_BLOCK),
        "knowledge_base_configuration": {"type": "VECTOR", "vectorKnowledgeBaseConfiguration": {
            "embeddingModelArn": model_arn, "embeddingModelConfiguration": {
                "bedrockEmbeddingModelConfiguration": {"dimensions": 1024, "embeddingDataType": "FLOAT32"}}}},
        "storage_configuration": {"type": "S3_VECTORS", "s3VectorsConfiguration": {"indexArn": index_arn}},
        "data_source_configuration": {"type": "S3", "s3Configuration": {
            "bucketArn": f"arn:aws:s3:::{bucket}", "bucketOwnerAccountId": account_id, "inclusionPrefixes": [PREFIX]}},
        "ingestion_configuration": {"chunkingConfiguration": {"chunkingStrategy": "FIXED_SIZE",
            "fixedSizeChunkingConfiguration": {"maxTokens": 200, "overlapPercentage": 20}}},
    }
    result["template_digest"] = hashlib.sha256(json.dumps(result, sort_keys=True).encode()).hexdigest()
    return result


def require(condition):
    if not condition:
        raise LedgerError(409)


def inspect_existing(specification, *, s3, vectors, iam, agent):
    """Return verified connection metadata or None only if all fixed names are absent."""
    try:
        t = deepcopy(specification)
        require(t == template(t["account_id"], t["region"]))
        request_ids = []

        def call(method, *, absent=(), **kwargs):
            try:
                result = method(**kwargs)
            except ClientError as error:
                if error.response.get("Error", {}).get("Code") in absent:
                    return None
                raise
            metadata = result["ResponseMetadata"]
            request_id = metadata["RequestId"]
            require(metadata["HTTPStatusCode"] == 200 and isinstance(request_id, str) and request_id
                    and request_id not in request_ids)
            request_ids.append(request_id)
            return result

        def pages(method, field, **kwargs):
            rows, seen = [], set()
            for _ in range(100):
                result = call(method, **kwargs)
                require(isinstance(result[field], list))
                rows.extend(result[field])
                if "nextToken" not in result:
                    return rows
                token = result["nextToken"]
                require(isinstance(token, str) and token and token not in seen)
                seen.add(token)
                kwargs["nextToken"] = token
            raise LedgerError(409)

        source_args = {"Bucket": t["source_bucket"], "ExpectedBucketOwner": t["account_id"]}
        source = call(s3.head_bucket, absent=("404", "NoSuchBucket"), **source_args)
        vector = call(vectors.get_vector_bucket, absent=("NotFoundException",), vectorBucketName=t["vector_bucket"])
        role = call(iam.get_role, absent=("NoSuchEntity",), RoleName=t["role_name"])
        matches = [row for row in pages(agent.list_knowledge_bases, "knowledgeBaseSummaries", maxResults=100)
                   if row.get("name") == t["knowledge_base_name"]]
        present = (source is not None, vector is not None, role is not None, bool(matches))
        if not any(present):
            return None
        require(all(present) and len(matches) == 1)
        tags = call(s3.get_bucket_tagging, **source_args)["TagSet"]
        require({item["Key"]: item["Value"] for item in tags} == t["tags"])
        require(call(s3.get_public_access_block, **source_args)["PublicAccessBlockConfiguration"] == t["public_access_block"])
        require(vector["vectorBucket"]["vectorBucketArn"] == t["vector_bucket_arn"])
        index = call(vectors.get_index, indexArn=t["index_arn"])["index"]
        require(all(index[key] == value for key, value in {"indexArn": t["index_arn"], "dimension": 1024,
                    "dataType": "float32", "distanceMetric": "cosine"}.items()))
        current_role = role["Role"]
        require(current_role["Arn"] == t["role_arn"] and current_role["AssumeRolePolicyDocument"] == t["trust_policy"]
                and "PermissionsBoundary" not in current_role
                and {item["Key"]: item["Value"] for item in current_role["Tags"]} == t["tags"])
        role_args = {"RoleName": t["role_name"]}
        policies = call(iam.list_role_policies, **role_args)
        require(not policies.get("IsTruncated") and policies["PolicyNames"] == [t["policy_name"]])
        attached = call(iam.list_attached_role_policies, **role_args)
        require(not attached.get("IsTruncated") and attached["AttachedPolicies"] == [])
        require(call(iam.get_role_policy, **role_args, PolicyName=t["policy_name"])["PolicyDocument"] == t["runtime_policy"])
        kb_id = matches[0]["knowledgeBaseId"]
        kb = call(agent.get_knowledge_base, knowledgeBaseId=kb_id)["knowledgeBase"]
        kb_arn = f"arn:aws:bedrock:{t['region']}:{t['account_id']}:knowledge-base/{kb_id}"
        require(kb["knowledgeBaseId"] == kb_id and kb["knowledgeBaseArn"] == kb_arn and kb["status"] == "ACTIVE"
                and kb["name"] == t["knowledge_base_name"] and kb["roleArn"] == t["role_arn"]
                and kb["knowledgeBaseConfiguration"] == t["knowledge_base_configuration"]
                and kb["storageConfiguration"] == t["storage_configuration"])
        require(call(agent.list_tags_for_resource, resourceArn=kb_arn)["tags"] == t["tags"])
        sources = pages(agent.list_data_sources, "dataSourceSummaries", knowledgeBaseId=kb_id, maxResults=100)
        require(len(sources) == 1 and sources[0]["name"] == t["data_source_name"])
        ds_id = sources[0]["dataSourceId"]
        ds = call(agent.get_data_source, knowledgeBaseId=kb_id, dataSourceId=ds_id)["dataSource"]
        require(ds["knowledgeBaseId"] == kb_id and ds["dataSourceId"] == ds_id and ds["status"] == "AVAILABLE"
                and ds["name"] == t["data_source_name"] and ds["dataDeletionPolicy"] == "DELETE"
                and ds["dataSourceConfiguration"] == t["data_source_configuration"]
                and ds["vectorIngestionConfiguration"] == t["ingestion_configuration"])
        return {"account_id": t["account_id"], "region": t["region"], "template_digest": t["template_digest"],
                "knowledge_base_id": kb_id, "data_source_id": ds_id, "resource_request_ids": request_ids}
    except LedgerError:
        raise
    except Exception:
        raise LedgerError(502) from None
