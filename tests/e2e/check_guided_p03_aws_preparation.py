"""Publisher-only live preparation/search/cleanup using shipped Gateway modules.

Not a learner suite, Browser, or API E2E. Mount only in a temporary Gateway
container. Successful newly created resources are cleaned even if search fails;
partial preparation is preserved with diagnostic evidence, never auto-deleted.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
from uuid import uuid4

import boto3
from botocore.config import Config

from p03_aws_preparation import clients, prepare_aws
from p03_backend import Binding, BedrockSearchBackend
from p03_preparation import PreparationStore
from p03_aws_scope import preflight, ReadOnlyCalls
from p03_aws_cleanup import cleanup_created


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(exist_ok=False)
    operation = str(uuid4())
    database = args.output_dir / "preparation.sqlite3"
    proof = {"scope": "shipped preparation and read-only search adapter; not Practice completion",
             "operation_id": operation, "checked": False}
    observer = ReadOnlyCalls()
    provider_errors = []
    proof["exceptions"] = []

    def trace(frame, event, arg):
        if event == "exception" and frame.f_code.co_filename.startswith("/app/p03_"):
            proof["exceptions"].append({"file": Path(frame.f_code.co_filename).name,
                                        "line": frame.f_lineno, "type": arg[0].__name__})
        return trace

    def observe(model, parsed, **kwargs):
        observer.after(model, parsed, **kwargs)
        job = parsed.get("ingestionJob")
        if isinstance(job, dict):
            observer.responses[-1]["ingestion_job"] = {key: job[key] for key in
                ("knowledgeBaseId", "dataSourceId", "ingestionJobId", "status", "statistics") if key in job}
        # Publisher-only service diagnostics; never exposed by the learner API.
        error = parsed.get("Error")
        if isinstance(error, dict):
            provider_errors.append({"operation": model.name, "code": error.get("Code"),
                                    "message": str(error.get("Message", ""))[:2000]})

    def save(name, value):
        (args.output_dir / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")

    def observed_clients(region):
        sdk = clients(region)
        for client in sdk.values():
            client.meta.events.register("after-call.*.*", observe)
        return sdk

    before = prepared = None
    try:
        before = preflight(args.account_id)
        save("preflight.json", before)
        proof["module_sha256"] = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in Path("/app").glob("p03_*.py")}
        sys.settrace(trace)
        try:
            prepared = prepare_aws(database, operation, args.account_id, client_factory=observed_clients)
        finally:
            sys.settrace(None)
        save("prepared.json", prepared)
        binding = Binding(**prepared["resources"]["binding"])
        agent = clients(binding.region)["agent"]
        runtime = boto3.client("bedrock-agent-runtime", region_name=binding.region,
            config=Config(connect_timeout=5, read_timeout=20, retries={"total_max_attempts": 1}))
        for client in (agent, runtime):
            client.meta.events.register("after-call.*.*", observe)
        backend = BedrockSearchBackend(binding,
            lambda: Binding(**PreparationStore(database).resources()["binding"]), agent, runtime)
        status = backend.job_status(binding.current_job_id)
        save("job-status.json", status)
        result = backend.retrieve(binding.current_job_id)
        save("retrieval.json", result)
        assert status["status"] == "COMPLETE" and result["results"]
        assert all(item["location"]["s3Location"]["uri"] in prepared["resources"]["source_uris"]
                   for item in result["results"])
        proof["checked"] = True
    except Exception as error:
        proof["error_type"] = type(error).__name__
        raise
    finally:
        save("aws-calls.json", observer.responses)
        save("provider-errors.json", provider_errors)
        if database.exists():
            save("preparation-journal.json", PreparationStore(database).read(operation))
        try:
            if prepared is not None:
                proof["cleanup"] = cleanup_created(args.account_id, before, prepared, database)
            else:
                proof["cleanup"] = {"performed": False, "reason": "no successful creation record; inspect partial resources"}
        finally:
            save("result.json", proof)
    print(json.dumps({"checked": proof["checked"], "resources_absent": proof["cleanup"]["resources_absent"],
                      "output_dir": str(args.output_dir)}))


if __name__ == "__main__":
    main()
