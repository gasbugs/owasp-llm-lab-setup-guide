"""Publisher diagnostic of a fixed, already-audited P03 source.

Only reads and one StartIngestionJob are permitted by default. An explicit
flag allows conditional creation of the fixed source, never overwrite. Optional
search uses the shipped adapter. No resource creation, policy update, deletion,
learner grading or model chat.
"""
import argparse
import json
from pathlib import Path
import sys
from uuid import uuid4

import boto3
from botocore.config import Config

from p03_aws_preparation import clients, prepare_aws
from p03_backend import Binding, BedrockSearchBackend
from p03_preparation import PreparationStore
from p03_resource_contract import inspect_existing, require, template
from p03_seed_document import prepare_document
from p03_aws_scope import READ_OPERATIONS


def guard_operation(name, *, create_source=False, retrieve=False):
    allowed = READ_OPERATIONS | {"ListObjectsV2", "GetObject", "StartIngestionJob", "GetIngestionJob"}
    if create_source:
        allowed = allowed | {"PutObject"}
    if retrieve:
        allowed = allowed | {"Retrieve"}
    require(name in allowed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--knowledge-base-id", required=True)
    parser.add_argument("--data-source-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expect-source-create", action="store_true",
                        help="allow the shipped conditional PutObject into an absent fixed source key")
    parser.add_argument("--coordinator", action="store_true")
    parser.add_argument("--retrieve", action="store_true",
                        help="verify actual search after successful coordinator preparation")
    args = parser.parse_args()
    if args.retrieve and not args.coordinator:
        parser.error("--retrieve requires --coordinator")
    if args.output.exists():
        parser.error("preserve existing evidence")
    proof = {"operation_id": str(uuid4()), "calls": [], "exceptions": [], "checked": False}
    sdk = clients("us-east-1")

    def guard(model, **kwargs):
        guard_operation(model.name, create_source=args.expect_source_create, retrieve=args.retrieve)

    def observe(model, parsed, **kwargs):
        row = {"operation": model.name, "metadata": {key: parsed.get("ResponseMetadata", {}).get(key)
                                                    for key in ("HTTPStatusCode", "RequestId")}}
        if "ingestionJob" in parsed:
            row["job"] = {key: parsed["ingestionJob"][key] for key in
                ("knowledgeBaseId", "dataSourceId", "ingestionJobId", "status", "statistics")
                if key in parsed["ingestionJob"]}
        proof["calls"].append(row)

    def trace(frame, event, arg):
        if event == "exception" and frame.f_code.co_filename.startswith("/app/p03_"):
            proof["exceptions"].append({"file": Path(frame.f_code.co_filename).name,
                                        "line": frame.f_lineno, "type": arg[0].__name__})
        return trace

    for client in sdk.values():
        client.meta.events.register("before-call.*.*", guard)
        client.meta.events.register("after-call.*.*", observe)
    try:
        require(sdk["sts"].get_caller_identity()["Account"] == args.account_id)
        t = template(args.account_id)
        connection = inspect_existing(t, **{key: sdk[key] for key in ("s3", "vectors", "iam", "agent")})
        require(connection is not None and connection["knowledge_base_id"] == args.knowledge_base_id
                and connection["data_source_id"] == args.data_source_id)
        proof["connection"] = connection
        sys.settrace(trace)
        if args.coordinator:
            database = args.output.with_suffix(".sqlite3")
            require(not database.exists())
            proof["prepared"] = prepare_aws(database, proof["operation_id"], args.account_id,
                                            client_factory=lambda region: sdk)
            require(proof["prepared"]["evidence"]["document"]["source_action"] ==
                    ("created" if args.expect_source_create else "reused"))
            if args.retrieve:
                binding = Binding(**proof["prepared"]["resources"]["binding"])
                runtime = boto3.client("bedrock-agent-runtime", region_name=binding.region,
                    config=Config(connect_timeout=5, read_timeout=20,
                                  retries={"total_max_attempts": 1}))
                runtime.meta.events.register("before-call.*.*", guard)
                runtime.meta.events.register("after-call.*.*", observe)
                backend = BedrockSearchBackend(binding,
                    lambda: Binding(**PreparationStore(database).resources()["binding"]),
                    sdk["agent"], runtime)
                proof["retrieval"] = backend.retrieve(binding.current_job_id)
                results = proof["retrieval"]["results"]
                require(bool(results) and all(item["location"]["s3Location"]["uri"] in
                    proof["prepared"]["resources"]["source_uris"] for item in results))
        else:
            proof["document"] = prepare_document(t, connection, proof["operation_id"], s3=sdk["s3"], agent=sdk["agent"])
            require(proof["document"]["evidence"]["source_action"] == ("created" if args.expect_source_create else "reused"))
        proof["checked"] = True
    finally:
        sys.settrace(None)
        with args.output.open("x") as stream:
            json.dump(proof, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    print(json.dumps({"checked": proof["checked"], "output": str(args.output)}))


if __name__ == "__main__":
    main()
