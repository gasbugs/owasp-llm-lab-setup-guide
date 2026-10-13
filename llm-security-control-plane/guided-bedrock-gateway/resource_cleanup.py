"""Explicit mission-owned AWS deletion. Never invoked by bootstrap or preparation."""
import json
from resource_progress import tracked, step
import re
import sqlite3
import time
from uuid import UUID

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from fastapi import HTTPException


def require(value, reason):
    if not value:
        raise HTTPException(409, reason)


def clients(region):
    config = Config(connect_timeout=5, read_timeout=20, retries={"total_max_attempts": 1})
    return {key: boto3.client(service, region_name=region, config=config)
            for key, service in (("sts", "sts"), ("s3", "s3"), ("vectors", "s3vectors"),
                                 ("iam", "iam"), ("agent", "bedrock-agent"), ("bedrock", "bedrock"))}


def assert_idle(database, problem):
    with sqlite3.connect(database) as db:
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        execution = problem.lower() + "_executions"
        if execution in tables:
            require(db.execute(f"SELECT COUNT(*) FROM {execution} WHERE closed_at IS NULL").fetchone()[0] == 0,
                    "finish the running mission before deleting its AWS resources")
        preparation = problem.lower() + "_preparations"
        if preparation in tables:
            require(db.execute(f"SELECT COUNT(*) FROM {preparation} WHERE state='preparing'").fetchone()[0] == 0,
                    "AWS preparation is still running")


def wait_absent(fetch, *, sleep=time.sleep, attempts=60):
    for _ in range(attempts):
        try:
            fetch()
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") in {"ResourceNotFoundException", "NotFoundException", "404", "NoSuchBucket", "NoSuchEntity"}:
                return
            raise
        sleep(1)
    raise HTTPException(502, "AWS resource deletion is not yet confirmed")


def cleanup_storage(specification, audit, sdk, *, problem, sleep=time.sleep):
    """Audit the whole namespace before the first destructive API call."""
    t = specification
    state = audit()
    if state is None:
        return []
    require(not state.get("missing"), "partial resources require inspection before deletion")
    s3, vectors, iam, agent = (sdk[key] for key in ("s3", "vectors", "iam", "agent"))
    source = {"Bucket": t["source_bucket"], "ExpectedBucketOwner": t["account_id"]}
    versioning = s3.get_bucket_versioning(**source)
    require(versioning.get("Status") is None, "versioned source bucket is outside this deletion action")
    indices = vectors.list_indexes(vectorBucketName=t["vector_bucket"], maxResults=100)
    require(not indices.get("nextToken") and [row["indexName"] for row in indices["indexes"]] == [t["vector_index"]],
            "vector bucket has additional indexes")
    objects = []
    for page in s3.get_paginator("list_objects_v2").paginate(**source):
        objects.extend(row["Key"] for row in page.get("Contents", []))
        require(len(objects) <= 10000, "source listing exceeds the deletion bound")
    if problem == "P02":
        require(all(re.fullmatch(r"h02/knowledge/[0-9a-f-]{36}\.md", key) and
                    str(UUID(key.split('/')[-1][:-3])) == key.split('/')[-1][:-3] for key in objects),
                "source bucket contains files outside the mission")
    else:
        require(set(objects) <= {t["source_prefix"] + "current-policy.md"},
                "source bucket contains files outside the mission")
    ids = {"knowledgeBaseId": state["knowledge_base_id"], "dataSourceId": state["data_source_id"]}
    jobs = agent.list_ingestion_jobs(**ids, maxResults=100)
    require(not jobs.get("nextToken") and all(row["status"] in {"COMPLETE", "FAILED", "STOPPED"}
            for row in jobs["ingestionJobSummaries"]), "finish the AWS ingestion job before deletion")
    # Ownership/configuration is revalidated immediately before deletion.
    require(audit() == state, "resource configuration changed during the deletion audit")
    step(2)
    agent.delete_data_source(**ids)
    wait_absent(lambda: agent.get_data_source(**ids), sleep=sleep)
    step(3)
    agent.delete_knowledge_base(knowledgeBaseId=ids["knowledgeBaseId"])
    wait_absent(lambda: agent.get_knowledge_base(knowledgeBaseId=ids["knowledgeBaseId"]), sleep=sleep)
    step(4)
    for key in objects:
        s3.delete_object(**source, Key=key)
    s3.delete_bucket(**source)
    wait_absent(lambda: s3.head_bucket(**source), sleep=sleep)
    step(5)
    vectors.delete_index(indexArn=t["index_arn"])
    wait_absent(lambda: vectors.get_index(indexArn=t["index_arn"]), sleep=sleep)
    step(6)
    vectors.delete_vector_bucket(vectorBucketName=t["vector_bucket"])
    wait_absent(lambda: vectors.get_vector_bucket(vectorBucketName=t["vector_bucket"]), sleep=sleep)
    step(7)
    iam.delete_role_policy(RoleName=t["role_name"], PolicyName=t["policy_name"])
    iam.delete_role(RoleName=t["role_name"])
    wait_absent(lambda: iam.get_role(RoleName=t["role_name"]), sleep=sleep)
    step(8)
    require(audit() is None, "AWS resource absence could not be verified")
    return [t[key] for key in ("source_bucket", "vector_bucket", "role_name", "knowledge_base_name")]


@tracked(None, action="delete")
def delete_resources(problem, operation_id, database, *, p02_template, p02_state,
                     provider_mode, client_factory=clients):
    require(problem in {"P02", "P03", "P04"}, "unsupported mission")
    require(str(UUID(operation_id)) == operation_id, "invalid deletion operation")
    require(provider_mode == "aws", "deletion requires the AWS provider")
    step(1)
    assert_idle(database, problem)
    sdk = client_factory("us-east-1")
    try:
        account = sdk["sts"].get_caller_identity()["Account"]
        if problem == "P02":
            from p02_reuse import preflight
            t = p02_template(account)
            t["policy_name"] = t["knowledge_base_name"].removesuffix("-" + account + "-knowledge-base") + "-knowledge-base-runtime"
            previous = p02_state()
            if previous:
                require(previous.get("template_digest") == t["template_digest"], "P02 resource journal differs")
            def audit():
                result = preflight(t, **{key: sdk[key] for key in ("s3", "vectors", "iam", "agent")}, policy_name=t["policy_name"])
                if result:
                    result.pop("aws_request_ids", None)
                return result
            removed = cleanup_storage(t, audit, sdk, problem=problem)
        elif problem == "P03":
            from p03_resource_contract import template, inspect_existing
            t = template(account)
            def audit():
                result = inspect_existing(t, **{key: sdk[key] for key in ("s3", "vectors", "iam", "agent")})
                if result:
                    result.pop("resource_request_ids", None)
                return result
            removed = cleanup_storage(t, audit, sdk, problem=problem)
        else:
            from p04_resource_contract import template, inspect_existing
            from p04_preparation import PreparationStore
            current = inspect_existing(template(account), client=sdk["bedrock"])
            removed = []
            if current["state"] != "absent":
                snapshot = PreparationStore(database).resources()
                require(current["state"] == "ready" and current["resources"] == snapshot,
                        "P04 policy ownership or journal differs")
                identifier = snapshot["guardrail"]["guardrailIdentifier"]
                step(2)
                sdk["bedrock"].delete_guardrail(guardrailIdentifier=identifier, guardrailVersion="DRAFT")
                wait_absent(lambda: sdk["bedrock"].get_guardrail(guardrailIdentifier=identifier, guardrailVersion="DRAFT"))
                removed = [identifier]
        step(3 if problem == "P04" else 8)
        with sqlite3.connect(database) as db:
            if problem == "P02":
                db.execute("DELETE FROM resource_state WHERE logical_name='h02'")
            elif problem == "P03":
                db.execute("DELETE FROM resource_state WHERE logical_name='p03'")
                db.execute("UPDATE p03_preparations SET state='deleted' WHERE state='ready'")
            else:
                db.execute("UPDATE p04_preparations SET state='deleted' WHERE state='ready'")
            db.execute("CREATE TABLE IF NOT EXISTS resource_deletions (operation_id TEXT PRIMARY KEY, practice_id TEXT NOT NULL, result_json TEXT NOT NULL)")
            result = {"practice_id": problem, "operation_id": operation_id, "state": "deleted", "removed_resources": removed}
            db.execute("INSERT INTO resource_deletions VALUES(?,?,?)", (operation_id, problem, json.dumps(result)))
        return result
    finally:
        for client in sdk.values():
            client.close()
