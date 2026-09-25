"""Publisher-only guard/cleanup, executed inside the credential-owning Gateway.

Refuse existing resources before provisioning. Cleanup requires that preflight,
the exact successful provisioning receipt and the complete executed case IDs.
Failed/partial provisioning is deliberately left for explicit diagnosis.
"""
import json
import sys
import time

import boto3
from botocore.exceptions import ClientError
from botocore.config import Config
import server


READ_OPERATIONS = frozenset({
    "GetCallerIdentity", "HeadBucket", "GetBucketTagging", "GetPublicAccessBlock",
    "GetVectorBucket", "GetIndex", "GetRole", "ListRolePolicies",
    "ListAttachedRolePolicies", "GetRolePolicy", "ListKnowledgeBases",
    "GetKnowledgeBase", "ListTagsForResource", "ListDataSources", "GetDataSource",
})


def read_only_reuse(previous, config):
    """Run the shipped provisioner with SDK writes rejected before transmission."""
    from uuid import uuid4
    original = boto3.client
    calls = []
    def before_call(model, **kwargs):
        calls.append(model.name)
        if model.name not in READ_OPERATIONS:
            raise AssertionError("provisioning reuse attempted an AWS write: " + model.name)
    def guarded_client(name, **kwargs):
        client = original(name, **{**kwargs, "config": config})
        client.meta.events.register("before-call.*.*", before_call)
        return client
    try:
        boto3.client = guarded_client
        current = server.provision_h02_aws(str(uuid4()))
    finally:
        boto3.client = original
    volatile = {"execution_id", "observed_at", "aws_request_ids"}
    assert {key: value for key, value in previous.items() if key not in volatile} == {
        key: value for key, value in current.items() if key not in volatile}
    assert current["execution_id"] != previous["execution_id"]
    assert current == server.load_h02_state()
    assert set(calls) == READ_OPERATIONS
    return {"verified": True, "scope": "shipped provisioner with read-only SDK event guard",
            "aws_operations": calls, "state": current}


def absent(call, codes):
    try:
        call()
    except ClientError as error:
        if error.response["Error"]["Code"] in codes:
            return True
        raise
    return False


def run(action, payload):
    region = "us-east-1"
    config = Config(connect_timeout=5, read_timeout=20, retries={"total_max_attempts": 1})
    def client(name):
        return boto3.client(name, region_name=region, config=config)
    account = client("sts").get_caller_identity()["Account"]
    if account != payload["account_id"]:
        raise ValueError("unexpected AWS account")
    template = server.h02_template(account)
    s3, vectors, iam, agent = (client(name) for name in ("s3", "s3vectors", "iam", "bedrock-agent"))
    def matching_kbs():
        return [item for page in agent.get_paginator("list_knowledge_bases").paginate()
                for item in page.get("knowledgeBaseSummaries", [])
                if item["name"] == template["knowledge_base_name"]]
    if action == "preflight":
        checks = {
            "source_absent": absent(lambda: s3.head_bucket(Bucket=template["source_bucket"]), {"404", "NoSuchBucket"}),
            "vector_absent": absent(lambda: vectors.get_vector_bucket(vectorBucketName=template["vector_bucket"]), {"NotFoundException"}),
            "role_absent": absent(lambda: iam.get_role(RoleName=template["role_name"]), {"NoSuchEntity"}),
            "kb_absent": not matching_kbs(),
        }
        if not all(checks.values()):
            raise ValueError("existing P02 resources: no provisioning or cleanup authorized")
        return {"account_id": account, "region": region, "checks": checks,
                "template_digest": template["template_digest"], "observed_at": time.time()}
    if action not in {"cleanup", "reuse"}:
        raise ValueError("unknown publisher action")
    before, state = payload["preflight"], payload["state"]
    assert before["account_id"] == account and all(before["checks"].values())
    assert set(before["checks"]) == {"source_absent", "vector_absent", "role_absent", "kb_absent"}
    assert 0 <= time.time() - before["observed_at"] < 3600
    assert before["template_digest"] == state["template_digest"] == template["template_digest"]
    assert state == server.load_h02_state() and state["provider_mode"] == "aws"
    assert state["source_bucket"] == template["source_bucket"] and state["index_arn"] == template["index_arn"]
    if action == "reuse":
        return read_only_reuse(state, config)
    tags = {tag["Key"]: tag["Value"] for tag in s3.get_bucket_tagging(Bucket=template["source_bucket"])["TagSet"]}
    assert tags == {"Course": "tenant-03", "Activity": "H02", "ManagedBy": "guided-control-center"}
    assert s3.get_bucket_versioning(Bucket=template["source_bucket"]).get("Status") is None
    from uuid import UUID
    ids = payload["execution_ids"]
    assert len(ids) == 22 and len(set(ids)) == 22 and all(str(UUID(value)) == value for value in ids)
    allowed = {f"h02/knowledge/{value}.md" for value in ids}
    objects = [item["Key"] for page in s3.get_paginator("list_objects_v2").paginate(Bucket=template["source_bucket"])
               for item in page.get("Contents", [])]
    assert set(objects) <= allowed
    roles = iam.get_role(RoleName=template["role_name"])["Role"]
    assert roles["Arn"] == template["role_arn"]
    assert {tag["Key"]: tag["Value"] for tag in roles["Tags"]} == tags
    policies = iam.list_role_policies(RoleName=template["role_name"])["PolicyNames"]
    assert policies == [f"{server.H02_PREFIX}-knowledge-base-runtime"]
    assert iam.list_attached_role_policies(RoleName=template["role_name"])["AttachedPolicies"] == []
    matches = matching_kbs()
    assert len(matches) == 1 and matches[0]["knowledgeBaseId"] == state["knowledge_base_id"]
    sources = agent.list_data_sources(knowledgeBaseId=state["knowledge_base_id"])["dataSourceSummaries"]
    assert len(sources) == 1 and sources[0]["dataSourceId"] == state["data_source_id"]
    assert agent.list_ingestion_jobs(knowledgeBaseId=state["knowledge_base_id"], dataSourceId=state["data_source_id"])["ingestionJobSummaries"] == []
    assert vectors.list_vectors(indexArn=state["index_arn"], maxResults=1)["vectors"] == []
    agent.delete_data_source(knowledgeBaseId=state["knowledge_base_id"], dataSourceId=state["data_source_id"])
    deadline = time.monotonic() + 60
    while not absent(lambda: agent.get_data_source(knowledgeBaseId=state["knowledge_base_id"], dataSourceId=state["data_source_id"]), {"ResourceNotFoundException"}):
        if time.monotonic() >= deadline:
            raise TimeoutError("Data Source deletion")
        time.sleep(1)
    agent.delete_knowledge_base(knowledgeBaseId=state["knowledge_base_id"])
    deadline = time.monotonic() + 60
    while not absent(lambda: agent.get_knowledge_base(knowledgeBaseId=state["knowledge_base_id"]), {"ResourceNotFoundException"}):
        if time.monotonic() >= deadline:
            raise TimeoutError("Knowledge Base deletion")
        time.sleep(1)
    for key in objects:
        s3.delete_object(Bucket=template["source_bucket"], Key=key)
    s3.delete_bucket(Bucket=template["source_bucket"])
    vectors.delete_index(indexArn=state["index_arn"])
    vectors.delete_vector_bucket(vectorBucketName=template["vector_bucket"])
    iam.delete_role_policy(RoleName=template["role_name"], PolicyName=policies[0])
    iam.delete_role(RoleName=template["role_name"])
    after = run("preflight", {"account_id": account})
    return {"removed_source_objects": len(objects), "resources_absent": after["checks"]}


if __name__ == "__main__":
    print(json.dumps(run(sys.argv[1], json.loads(sys.argv[2]))))
