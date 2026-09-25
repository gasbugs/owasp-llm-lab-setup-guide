"""Explicit P03-only AWS resource creation; no ingestion, deletion, or repair."""
from copy import deepcopy
import json
import re
import time
from uuid import UUID

from botocore.exceptions import ClientError

from p03_ledger import LedgerError
from p03_resource_contract import inspect_existing, require, template


def prepare_resources(specification, operation_id, *, sts, s3, vectors, iam, agent,
                      sleep=time.sleep, monotonic=time.monotonic):
    """Audit before writes and after creation. Caller owns durable preparation lock.

    The SDK clients must use bounded timeouts and a single attempt. A partial
    creation remains visible for operator inspection; it is never auto-deleted.
    """
    try:
        t = deepcopy(specification)
        require(t == template(t["account_id"], t["region"]))
        operation = UUID(operation_id)
        require(str(operation) == operation_id)
        request_ids = []
        deadline = monotonic() + 240

        def call(method, **kwargs):
            require(monotonic() < deadline)
            result = method(**kwargs)
            metadata = result["ResponseMetadata"]
            rid = metadata["RequestId"]
            require(type(metadata["HTTPStatusCode"]) is int and 200 <= metadata["HTTPStatusCode"] < 300
                    and isinstance(rid, str) and rid and rid not in request_ids)
            request_ids.append(rid)
            return result

        identity = call(sts.get_caller_identity)
        require(identity["Account"] == t["account_id"])
        clients = dict(s3=s3, vectors=vectors, iam=iam, agent=agent)
        existing = inspect_existing(t, **clients)
        if existing is not None:
            return {**existing, "resource_action": "reused", "preparation_request_ids": request_ids}

        source = {"Bucket": t["source_bucket"], "ExpectedBucketOwner": t["account_id"]}
        tags = [{"Key": key, "Value": value} for key, value in t["tags"].items()]
        call(s3.create_bucket, Bucket=t["source_bucket"])
        call(s3.put_public_access_block, **source, PublicAccessBlockConfiguration=t["public_access_block"])
        call(s3.put_bucket_tagging, **source, Tagging={"TagSet": tags})
        vector = call(vectors.create_vector_bucket, vectorBucketName=t["vector_bucket"])
        require(vector["vectorBucketArn"] == t["vector_bucket_arn"])
        index = call(vectors.create_index, vectorBucketName=t["vector_bucket"], indexName=t["vector_index"],
                     dataType="float32", dimension=1024, distanceMetric="cosine")
        require(index["indexArn"] == t["index_arn"])
        role = call(iam.create_role, RoleName=t["role_name"], Tags=tags,
                    AssumeRolePolicyDocument=json.dumps(t["trust_policy"]))["Role"]
        require(role["Arn"] == t["role_arn"])
        call(iam.put_role_policy, RoleName=t["role_name"], PolicyName=t["policy_name"],
             PolicyDocument=json.dumps(t["runtime_policy"]))
        # Only this observed role-propagation response is retried, with one token.
        sleep(5)
        for attempt in range(6):
            try:
                kb = call(agent.create_knowledge_base, clientToken="p03-kb-" + operation.hex,
                          name=t["knowledge_base_name"], description="Tenant 03 P03 current document search",
                          roleArn=t["role_arn"], tags=t["tags"],
                          knowledgeBaseConfiguration=t["knowledge_base_configuration"],
                          storageConfiguration=t["storage_configuration"])["knowledgeBase"]
                break
            except ClientError as error:
                detail = error.response.get("Error", {})
                if (attempt == 5 or detail.get("Code") != "ValidationException"
                        or detail.get("Message") != "Bedrock Knowledge Base was unable to assume the given role. "
                        "Provide the proper permissions and retry the request."):
                    raise
                sleep(5)
        kb_id = kb["knowledgeBaseId"]
        require(isinstance(kb_id, str) and re.fullmatch(r"[A-Za-z0-9]{10}", kb_id))

        def wait(method, field, ready, pending, identity, **kwargs):
            for attempt in range(60):
                value = call(method, **kwargs)[field]
                require(all(value.get(key) == expected for key, expected in identity.items()))
                if value.get("status") == ready:
                    return value
                require(value.get("status") in pending)
                if attempt < 59:
                    sleep(2)
            raise LedgerError(409)

        wait(agent.get_knowledge_base, "knowledgeBase", "ACTIVE", {"CREATING"},
             {"knowledgeBaseId": kb_id, "name": t["knowledge_base_name"], "roleArn": t["role_arn"]},
             knowledgeBaseId=kb_id)
        ds = call(agent.create_data_source, clientToken="p03-ds-" + operation.hex,
                  knowledgeBaseId=kb_id, name=t["data_source_name"], dataDeletionPolicy="DELETE",
                  description="Tenant 03 P03 fixed S3 document prefix",
                  dataSourceConfiguration=t["data_source_configuration"],
                  vectorIngestionConfiguration=t["ingestion_configuration"])["dataSource"]
        ds_id = ds["dataSourceId"]
        require(isinstance(ds_id, str) and re.fullmatch(r"[A-Za-z0-9]{10}", ds_id))
        wait(agent.get_data_source, "dataSource", "AVAILABLE", set(),
             {"knowledgeBaseId": kb_id, "dataSourceId": ds_id, "name": t["data_source_name"]},
             knowledgeBaseId=kb_id, dataSourceId=ds_id)
        audited = inspect_existing(t, **clients)
        require(audited is not None and audited["knowledge_base_id"] == kb_id
                and audited["data_source_id"] == ds_id)
        return {**audited, "resource_action": "created", "preparation_request_ids": request_ids}
    except LedgerError:
        raise
    except Exception:
        raise LedgerError(502) from None
