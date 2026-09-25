"""Publisher-only, read-only P03 AWS preflight; never installed in learner images.

Run in a credential-owning Gateway image. A successful receipt proves absence
at the observed time, not ownership of later resources or permission to delete.
Partial/existing resources and permission errors stop the publisher run.
"""
import argparse
import json
from pathlib import Path
import time
from uuid import uuid4

from p03_aws_preparation import clients
from p03_resource_contract import inspect_existing, require, template


READ_OPERATIONS = frozenset({
    "GetCallerIdentity", "HeadBucket", "GetVectorBucket", "GetRole",
    "ListKnowledgeBases", "GetBucketTagging", "GetPublicAccessBlock", "GetIndex",
    "ListRolePolicies", "ListAttachedRolePolicies", "GetRolePolicy",
    "GetKnowledgeBase", "ListTagsForResource", "ListDataSources", "GetDataSource",
})


class ReadOnlyCalls:
    def __init__(self):
        self.attempted = []
        self.responses = []

    def before(self, model, **kwargs):
        if model.name not in READ_OPERATIONS:
            raise ValueError("publisher preflight cannot write AWS resources")
        self.attempted.append(model.name)

    def after(self, model, parsed, **kwargs):
        metadata = parsed.get("ResponseMetadata", {})
        self.responses.append({"operation": model.name,
            "status": metadata.get("HTTPStatusCode"), "request_id": metadata.get("RequestId"),
            "error_code": parsed.get("Error", {}).get("Code")})

    def attach(self, sdk):
        for client in sdk.values():
            client.meta.events.register("before-call.*.*", self.before)
            client.meta.events.register("after-call.*.*", self.after)


def preflight(account_id, *, client_factory=clients, now=time.time):
    specification = template(account_id)
    started = now()
    sdk = client_factory(specification["region"])
    guard = ReadOnlyCalls()
    guard.attach(sdk)
    identity = sdk["sts"].get_caller_identity()
    metadata = identity.get("ResponseMetadata", {})
    require(identity.get("Account") == account_id and metadata.get("HTTPStatusCode") == 200
            and isinstance(metadata.get("RequestId"), str) and bool(metadata["RequestId"]))
    connection = inspect_existing(specification, **{key: sdk[key] for key in ("s3", "vectors", "iam", "agent")})
    if connection is not None:
        raise ValueError("existing P03 resources are not publisher-owned test resources")
    finished = now()
    require(0 <= finished - started < 300)
    return {"scope": "read-only P03 absence preflight; no creation or cleanup authorization",
            "preflight_id": str(uuid4()), "account_id": account_id, "region": specification["region"],
            "template_digest": specification["template_digest"], "started_at": started,
            "finished_at": finished, "resources_absent": True,
            "names": {key: specification[key] for key in
                      ("source_bucket", "vector_bucket", "role_name", "knowledge_base_name")},
            "attempted_operations": guard.attempted, "responses": guard.responses}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("preserve existing evidence; choose a new output")
    result = preflight(args.account_id)
    with args.output.open("x") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({"resources_absent": True, "read_calls": len(result["responses"]),
                      "output": str(args.output)}))


if __name__ == "__main__":
    main()
