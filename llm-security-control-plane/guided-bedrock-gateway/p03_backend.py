"""Read-only P03 Bedrock adapter; provisioning and job start are control-only.

Bindings come from the server's prepared-resource store, never learner input.
Snapshot comparisons detect changed bindings, not concurrent external AWS edits.
"""
from dataclasses import dataclass
import math
import re


class BackendError(RuntimeError):
    def __init__(self):
        super().__init__("P03 provider evidence unavailable")


@dataclass(frozen=True)
class Binding:
    current_job_id: str
    provider_ingestion_job_id: str
    knowledge_base_id: str
    data_source_id: str
    source_uri_prefix: str
    region: str = "us-east-1"

    def __post_init__(self):
        identifiers = (self.current_job_id, self.provider_ingestion_job_id,
                       self.knowledge_base_id, self.data_source_id)
        if any(not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9-]{1,128}", value)
               for value in identifiers):
            raise BackendError()
        if (self.region != "us-east-1" or not isinstance(self.source_uri_prefix, str)
                or not re.fullmatch(r"s3://[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]/h03/knowledge/", self.source_uri_prefix)):
            raise BackendError()


def request_id(response):
    if not isinstance(response, dict):
        raise BackendError()
    metadata = response.get("ResponseMetadata")
    if not isinstance(metadata, dict) or metadata.get("HTTPStatusCode") != 200:
        raise BackendError()
    value = metadata.get("RequestId")
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise BackendError()
    return value


class BedrockSearchBackend:
    QUERY = "GUIDED-H03-ORION access procedure"
    STATUSES = {"STARTING", "IN_PROGRESS", "COMPLETE", "FAILED", "STOPPING", "STOPPED"}

    def __init__(self, binding, current_binding, agent, runtime):
        if not isinstance(binding, Binding):
            raise BackendError()
        for client, service in ((agent, "bedrock-agent"), (runtime, "bedrock-agent-runtime")):
            if (client.meta.region_name != binding.region
                    or client.meta.service_model.service_name != service):
                raise BackendError()
        self.binding, self.current_binding = binding, current_binding
        self.agent, self.runtime = agent, runtime

    def _current(self, job_id):
        if job_id != self.binding.current_job_id or self.current_binding() != self.binding:
            raise BackendError()

    def _identity(self):
        return {"ingestion_job_id": self.binding.current_job_id,
                "provider_ingestion_job_id": self.binding.provider_ingestion_job_id,
                "knowledge_base_id": self.binding.knowledge_base_id,
                "data_source_id": self.binding.data_source_id, "provider_mode": "aws"}

    def job_status(self, job_id):
        self._current(job_id)
        raw = self.agent.get_ingestion_job(
            knowledgeBaseId=self.binding.knowledge_base_id,
            dataSourceId=self.binding.data_source_id,
            ingestionJobId=self.binding.provider_ingestion_job_id)
        native_id = request_id(raw)
        job = raw.get("ingestionJob")
        if (not isinstance(job, dict)
                or job.get("ingestionJobId") != self.binding.provider_ingestion_job_id
                or job.get("knowledgeBaseId") != self.binding.knowledge_base_id
                or job.get("dataSourceId") != self.binding.data_source_id
                or job.get("status") not in self.STATUSES):
            raise BackendError()
        stats = job.get("statistics", {})
        if not isinstance(stats, dict) or any(type(value) is not int or value < 0 for value in stats.values()):
            raise BackendError()
        self._current(job_id)
        return {**self._identity(), "status": job["status"], "statistics": dict(stats),
                "provider_request_id": native_id}

    def retrieve(self, job_id):
        status = self.job_status(job_id)
        if status["status"] != "COMPLETE" or status["statistics"].get("numberOfDocumentsFailed") != 0:
            raise BackendError()
        self._current(job_id)
        raw = self.runtime.retrieve(
            knowledgeBaseId=self.binding.knowledge_base_id,
            retrievalQuery={"text": self.QUERY},
            retrievalConfiguration={"vectorSearchConfiguration": {"numberOfResults": 3}})
        native_id = request_id(raw)
        results = raw.get("retrievalResults")
        if (not isinstance(results, list) or len(results) > 3
                or raw.get("nextToken") or native_id == status["provider_request_id"]):
            raise BackendError()
        for item in results:
            if not isinstance(item, dict):
                raise BackendError()
            location, content, score = item.get("location"), item.get("content"), item.get("score")
            if (not isinstance(location, dict) or location.get("type") != "S3"
                    or not isinstance(location.get("s3Location"), dict)
                    or not isinstance(content, dict) or not isinstance(content.get("text"), str)
                    or type(score) not in (int, float) or not math.isfinite(score)
                    or not isinstance(item.get("metadata", {}), dict)):
                raise BackendError()
            uri = location["s3Location"].get("uri")
            if (not isinstance(uri, str) or not uri.startswith(self.binding.source_uri_prefix)
                    or uri == self.binding.source_uri_prefix):
                raise BackendError()
        self._current(job_id)
        return {**self._identity(), "provider_request_id": native_id,
                "status_observation": status, "results": results}
