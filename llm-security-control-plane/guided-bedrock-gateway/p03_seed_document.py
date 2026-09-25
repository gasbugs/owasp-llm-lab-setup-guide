"""Prepare one benign P03 source and bind a newly completed ingestion job.

Existing different content is never overwritten. This is infrastructure work,
not the learner's search decision, and it never calls Retrieve or a chat model.
"""
from copy import deepcopy
from dataclasses import asdict
import hashlib
import logging
import re
import time
from uuid import UUID

from p03_backend import Binding
from p03_ledger import LedgerError
from p03_resource_contract import require, template

DOCUMENT = ("# GUIDED-H03-ORION access procedure\n\n"
            "To request access to the ORION training workspace, submit an access request "
            "to the workspace administrator. The administrator checks the request and "
            "grants the approved training role. This is a synthetic training document.\n").encode()
DOCUMENT_SHA = hashlib.sha256(DOCUMENT).hexdigest()


def prepare_document(specification, connection, operation_id, *, s3, agent,
                     sleep=time.sleep, monotonic=time.monotonic):
    """Caller must hold the P03 preparation lock and audit connection ownership."""
    last_operation = "validation"
    try:
        t, connection = deepcopy(specification), deepcopy(connection)
        require(t == template(t["account_id"], t["region"]))
        operation = UUID(operation_id)
        require(str(operation) == operation_id)
        require(all(connection[key] == t[key] for key in ("account_id", "region", "template_digest")))
        kb, ds = connection["knowledge_base_id"], connection["data_source_id"]
        require(all(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9]{10}", value) for value in (kb, ds)))
        request_ids = []
        deadline = monotonic() + 180

        def call(method, **kwargs):
            nonlocal last_operation
            last_operation = getattr(method, "__name__", type(method).__name__)
            require(monotonic() < deadline)
            response = method(**kwargs)
            metadata = response["ResponseMetadata"]
            rid = metadata["RequestId"]
            require(type(metadata["HTTPStatusCode"]) is int and 200 <= metadata["HTTPStatusCode"] < 300
                    and isinstance(rid, str) and rid and rid not in request_ids)
            request_ids.append(rid)
            return response

        source = {"Bucket": t["source_bucket"], "ExpectedBucketOwner": t["account_id"]}
        key = t["source_prefix"] + "current-policy.md"

        def listed():
            result = call(s3.list_objects_v2, **source, Prefix=t["source_prefix"], MaxKeys=2)
            require(result.get("IsTruncated") is False and "NextContinuationToken" not in result)
            rows = result.get("Contents", [])
            require(isinstance(rows, list) and len(rows) <= 1)
            require(not rows or rows[0]["Key"] == key)
            return bool(rows)

        def verify_source():
            response = call(s3.get_object, **source, Key=key)
            body = response["Body"]
            try:
                require(response["ContentLength"] == len(DOCUMENT))
                require(body.read(len(DOCUMENT) + 1) == DOCUMENT)
            finally:
                body.close()

        existed = listed()
        if not existed:
            call(s3.put_object, **source, Key=key, Body=DOCUMENT, ContentType="text/markdown; charset=utf-8",
                 IfNoneMatch="*", Metadata={"practice": "P03", "sha256": DOCUMENT_SHA})
        verify_source()
        started = call(agent.start_ingestion_job, knowledgeBaseId=kb, dataSourceId=ds,
                       clientToken="p03-ingest-" + operation.hex,
                       description="P03 current training document ingestion")["ingestionJob"]
        job_id = started["ingestionJobId"]
        require(isinstance(job_id, str) and re.fullmatch(r"[A-Za-z0-9]{10}", job_id))

        def check_job(job):
            require(job["knowledgeBaseId"] == kb and job["dataSourceId"] == ds
                    and job["ingestionJobId"] == job_id)
            require(job["status"] in {"STARTING", "IN_PROGRESS", "COMPLETE"})

        check_job(started)
        for attempt in range(60):
            job = call(agent.get_ingestion_job, knowledgeBaseId=kb, dataSourceId=ds,
                       ingestionJobId=job_id)["ingestionJob"]
            check_job(job)
            if job["status"] == "COMPLETE":
                failed = job.get("statistics", {}).get("numberOfDocumentsFailed")
                require(type(failed) is int and failed == 0)
                break
            if attempt < 59:
                sleep(2)
        else:
            raise LedgerError(409)
        require(listed())
        verify_source()
        prefix = "s3://" + t["source_bucket"] + "/" + t["source_prefix"]
        binding = Binding("p03-" + operation.hex, job_id, kb, ds, prefix, t["region"])
        return {"snapshot": {"provider_mode": "aws", "binding": asdict(binding),
                             "source_uris": [prefix + "current-policy.md"]},
                "evidence": {"source_action": "reused" if existed else "created", "source_sha256": DOCUMENT_SHA,
                             "provider_ingestion_job_id": job_id, "status": "COMPLETE",
                             "number_of_documents_failed": 0, "preparation_request_ids": request_ids}}
    except LedgerError:
        raise
    except Exception as error:
        logging.getLogger(__name__).warning("P03 source preparation failed: operation=%s type=%s",
                                           last_operation, type(error).__name__)
        raise LedgerError(502) from None
