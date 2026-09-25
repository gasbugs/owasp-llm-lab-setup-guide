"""Publisher-only cleanup of one successful, newly created P03 test namespace.

Never repairs or deletes a partial preparation. Preflight absence, the unchanged
local journal, exact AWS configuration, source bytes and the single completed
ingestion job must all match before the first deletion. Not an external lock:
administrators must not modify this test namespace concurrently.
"""
import time
from uuid import UUID

from botocore.exceptions import ClientError

from p03_aws_preparation import clients
from p03_preparation import PreparationStore
from p03_resource_contract import inspect_existing, require, template
from p03_seed_document import DOCUMENT, DOCUMENT_SHA
from p03_aws_scope import preflight


def validate_records(account_id, before, prepared, *, now):
    t = template(account_id)
    require(before["account_id"] == prepared["account_id"] == account_id)
    require(before["region"] == t["region"] and before["resources_absent"] is True)
    require(before["template_digest"] == prepared["template_digest"] == t["template_digest"])
    require(before["names"] == {key: t[key] for key in
            ("source_bucket", "vector_bucket", "role_name", "knowledge_base_name")})
    require(str(UUID(before["preflight_id"])) == before["preflight_id"])
    operation = UUID(prepared["operation_id"])
    require(str(operation) == prepared["operation_id"])
    require(prepared["practice_id"] == "P03" and prepared["state"] == "ready")
    require(0 <= now - before["started_at"] < 3600)
    require(before["started_at"] <= before["finished_at"] <= prepared["started_at"]
            <= prepared["finished_at"] <= now)
    connection, document = prepared["evidence"]["connection"], prepared["evidence"]["document"]
    require(connection["resource_action"] == "created" and document["source_action"] == "created")
    require(all(connection[key] == t[key] for key in ("account_id", "region", "template_digest")))
    require(document["source_sha256"] == DOCUMENT_SHA and document["status"] == "COMPLETE"
            and type(document["number_of_documents_failed"]) is int and document["number_of_documents_failed"] == 0)
    snapshot = prepared["resources"]
    binding = snapshot["binding"]
    require(snapshot["provider_mode"] == "aws" and binding["region"] == t["region"])
    require(binding["current_job_id"] == "p03-" + operation.hex)
    require(binding["knowledge_base_id"] == connection["knowledge_base_id"]
            and binding["data_source_id"] == connection["data_source_id"]
            and binding["provider_ingestion_job_id"] == document["provider_ingestion_job_id"])
    prefix = "s3://" + t["source_bucket"] + "/" + t["source_prefix"]
    require(binding["source_uri_prefix"] == prefix and snapshot["source_uris"] == [prefix + "current-policy.md"])
    return t, connection, binding


def cleanup_created(account_id, before, prepared, database, *, client_factory=clients,
                    now=time.time, sleep=time.sleep, monotonic=time.monotonic):
    t, connection, binding = validate_records(account_id, before, prepared, now=now())
    store = PreparationStore(database)
    require(store.read(prepared["operation_id"]) == prepared and store.resources() == prepared["resources"])
    sdk = client_factory(t["region"])
    require(sdk["sts"].get_caller_identity()["Account"] == account_id)
    audited = inspect_existing(t, **{key: sdk[key] for key in ("s3", "vectors", "iam", "agent")})
    require(audited is not None and all(audited[key] == connection[key] for key in
            ("account_id", "region", "template_digest", "knowledge_base_id", "data_source_id")))
    s3, vectors, iam, agent = (sdk[key] for key in ("s3", "vectors", "iam", "agent"))
    source = {"Bucket": t["source_bucket"], "ExpectedBucketOwner": account_id}
    require(s3.get_bucket_versioning(**source).get("Status") is None)
    objects = s3.list_objects_v2(**source, MaxKeys=2)
    key = t["source_prefix"] + "current-policy.md"
    require(objects.get("IsTruncated") is False and "NextContinuationToken" not in objects)
    require([row["Key"] for row in objects.get("Contents", [])] == [key])
    response = s3.get_object(**source, Key=key)
    try:
        require(response["ContentLength"] == len(DOCUMENT) and response["Body"].read(len(DOCUMENT) + 1) == DOCUMENT)
    finally:
        response["Body"].close()
    ids = {"knowledgeBaseId": binding["knowledge_base_id"], "dataSourceId": binding["data_source_id"]}
    jobs = agent.list_ingestion_jobs(**ids, maxResults=100)
    require("nextToken" not in jobs)
    summaries = jobs["ingestionJobSummaries"]
    require(len(summaries) == 1 and summaries[0]["ingestionJobId"] == binding["provider_ingestion_job_id"]
            and summaries[0]["status"] == "COMPLETE")
    job = agent.get_ingestion_job(**ids, ingestionJobId=binding["provider_ingestion_job_id"])["ingestionJob"]
    require(all(job[k] == v for k, v in ids.items()) and job["status"] == "COMPLETE"
            and job["ingestionJobId"] == binding["provider_ingestion_job_id"])
    require(type(job["statistics"]["numberOfDocumentsFailed"]) is int
            and job["statistics"]["numberOfDocumentsFailed"] == 0)
    # Recheck the local operation immediately before destructive calls.
    require(store.read(prepared["operation_id"]) == prepared and store.resources() == prepared["resources"])

    def gone(method, **kwargs):
        deadline = monotonic() + 60
        for _ in range(60):
            try:
                method(**kwargs)
            except ClientError as error:
                if error.response["Error"]["Code"] == "ResourceNotFoundException":
                    return
                raise
            if monotonic() >= deadline:
                break
            sleep(1)
        raise TimeoutError("P03 test resource deletion not confirmed")

    agent.delete_data_source(**ids)
    gone(agent.get_data_source, **ids)
    agent.delete_knowledge_base(knowledgeBaseId=ids["knowledgeBaseId"])
    gone(agent.get_knowledge_base, knowledgeBaseId=ids["knowledgeBaseId"])
    s3.delete_object(**source, Key=key)
    s3.delete_bucket(**source)
    vectors.delete_index(indexArn=t["index_arn"])
    vectors.delete_vector_bucket(vectorBucketName=t["vector_bucket"])
    iam.delete_role_policy(RoleName=t["role_name"], PolicyName=t["policy_name"])
    iam.delete_role(RoleName=t["role_name"])
    after = preflight(account_id, client_factory=client_factory)
    return {"removed_source_objects": 1, "operation_id": prepared["operation_id"],
            "resources_absent": after["resources_absent"], "after": after}
