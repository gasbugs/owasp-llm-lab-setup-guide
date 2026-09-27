"""AWS recovery rehearsal in an initially absent P03 namespace, never an existing lab.

Explicit account required. Audits before each deletion; failures leave resources
and the journal for inspection. The learner's solution/grading is tested separately.
"""
import argparse
import json
from pathlib import Path
import sys
import time
from uuid import uuid4

from botocore.exceptions import ClientError

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "llm-security-control-plane/guided-bedrock-gateway"))
from p03_aws_scope import preflight
from p03_aws_preparation import clients, prepare_aws
from p03_preparation import PreparationStore
from p03_resource_contract import inspect_existing, template
from p03_seed_document import DOCUMENT
import boto3


def gone(method, **kwargs):
    for _ in range(60):
        try:
            method(**kwargs)
        except ClientError as error:
            if error.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(1)
    raise TimeoutError("test resource deletion not confirmed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(exist_ok=False)
    database = args.output / "journal.sqlite3"
    proof = {"before": preflight(args.account_id), "cases": []}
    t = template(args.account_id)
    sdk = clients(t["region"])
    s3, vectors, iam, agent = (sdk[key] for key in ("s3", "vectors", "iam", "agent"))
    runtime = boto3.client("bedrock-agent-runtime", region_name=t["region"])
    source = {"Bucket": t["source_bucket"], "ExpectedBucketOwner": args.account_id}
    key = t["source_prefix"] + "current-policy.md"
    prepared = None

    def save():
        (args.output / "result.json").write_text(json.dumps(proof, indent=2, default=str))

    def audit():
        assert time.time() - proof["before"]["started_at"] < 3600
        assert sdk["sts"].get_caller_identity()["Account"] == args.account_id
        current = inspect_existing(t, **{key: sdk[key] for key in ("s3", "vectors", "iam", "agent")})
        previous = prepared["evidence"]["connection"]
        assert all(current[key] == previous[key] for key in ("knowledge_base_id", "data_source_id"))
        assert PreparationStore(database).resources() == prepared["resources"]
        assert s3.get_bucket_versioning(**source).get("Status") is None
        objects = s3.list_objects_v2(**source, MaxKeys=2)
        assert objects.get("IsTruncated") is False
        assert [row["Key"] for row in objects.get("Contents", [])] == [key]
        document = s3.get_object(**source, Key=key)
        try:
            assert document["Body"].read() == DOCUMENT
        finally:
            document["Body"].close()
        ids = {"knowledgeBaseId": current["knowledge_base_id"], "dataSourceId": current["data_source_id"]}
        jobs = agent.list_ingestion_jobs(**ids, maxResults=100)
        assert not jobs.get("nextToken")
        known = {row["prepared"]["resources"]["binding"]["provider_ingestion_job_id"] for row in proof["cases"]}
        assert all(job["ingestionJobId"] in known and job["status"] == "COMPLETE"
                   for job in jobs["ingestionJobSummaries"])
        return ids

    try:
        for scenario in ("all_absent", "reuse", "index_missing", "source_missing", "kb_missing"):
            if prepared is not None:
                ids = audit()
                if scenario == "index_missing":
                    vectors.delete_index(indexArn=t["index_arn"])
                elif scenario == "source_missing":
                    s3.delete_object(**source, Key=key)
                    s3.delete_bucket(**source)
                elif scenario == "kb_missing":
                    agent.delete_data_source(**ids)
                    gone(agent.get_data_source, **ids)
                    agent.delete_knowledge_base(knowledgeBaseId=ids["knowledgeBaseId"])
                    gone(agent.get_knowledge_base, knowledgeBaseId=ids["knowledgeBaseId"])
            prepared = prepare_aws(database, str(uuid4()), args.account_id)
            case = {"scenario": scenario, "prepared": prepared}
            proof["cases"].append(case)
            save()
            result = runtime.retrieve(knowledgeBaseId=prepared["resources"]["binding"]["knowledge_base_id"],
                                      retrievalQuery={"text": "How do I request access to ORION?"},
                                      retrievalConfiguration={"vectorSearchConfiguration": {"numberOfResults": 3}})
            case["retrieval"] = result
            assert any(row.get("location", {}).get("s3Location", {}).get("uri") ==
                       "s3://" + t["source_bucket"] + "/" + key for row in result["retrievalResults"])
            case["verified"] = True
            save()
            print(scenario + ": verified", flush=True)
        ids = audit()
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
        proof["after"] = preflight(args.account_id)
        print("test namespace absent", flush=True)
    finally:
        save()


if __name__ == "__main__":
    main()
