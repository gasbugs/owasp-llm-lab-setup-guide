"""Read-only P02 KB/source/index connection check; never creates or repairs resources."""
import time
from uuid import uuid4

from p02_ledger import LedgerError

FIELDS = ("account_id", "region", "template_digest", "source_bucket", "source_prefix", "vector_bucket", "index_arn",
          "knowledge_base_id", "data_source_id", "embedding_model_id", "dimensions")


def connection_evidence(state, *, client_factory, mode):
    try:
        if (state["status"] != "READY" or state["provider_mode"] != mode or mode not in {"aws", "contract"}
                or state["region"] != "us-east-1" or state["source_prefix"] != "h02/knowledge/"
                or state["embedding_model_id"] != "amazon.titan-embed-text-v2:0" or state["dimensions"] != 1024):
            raise ValueError()
        binding = {key: state[key] for key in FIELDS}
        ids = []
        if mode == "contract":
            ids = [f"contract-resource-{uuid4()}"]
        else:
            s3, agent, vectors = (client_factory(name) for name in ("s3", "bedrock-agent", "s3vectors"))
            source = s3.head_bucket(Bucket=state["source_bucket"], ExpectedBucketOwner=state["account_id"])
            kb_response = agent.get_knowledge_base(knowledgeBaseId=state["knowledge_base_id"])
            ds_response = agent.get_data_source(knowledgeBaseId=state["knowledge_base_id"], dataSourceId=state["data_source_id"])
            index_response = vectors.get_index(indexArn=state["index_arn"])
            kb, ds, index = kb_response["knowledgeBase"], ds_response["dataSource"], index_response["index"]
            config = kb["knowledgeBaseConfiguration"]
            vector = config["vectorKnowledgeBaseConfiguration"]
            embedding = vector["embeddingModelConfiguration"]["bedrockEmbeddingModelConfiguration"]
            storage = kb["storageConfiguration"]
            data = ds["dataSourceConfiguration"]
            s3config = data["s3Configuration"]
            checks = (
                kb["knowledgeBaseId"] == state["knowledge_base_id"], kb["status"] == "ACTIVE", config["type"] == "VECTOR",
                vector["embeddingModelArn"] == f"arn:aws:bedrock:{state['region']}::foundation-model/{state['embedding_model_id']}",
                embedding["dimensions"] == 1024, embedding["embeddingDataType"] == "FLOAT32",
                storage["type"] == "S3_VECTORS", storage["s3VectorsConfiguration"]["indexArn"] == state["index_arn"],
                ds["knowledgeBaseId"] == state["knowledge_base_id"], ds["dataSourceId"] == state["data_source_id"],
                ds["status"] == "AVAILABLE", data["type"] == "S3",
                s3config["bucketArn"] == f"arn:aws:s3:::{state['source_bucket']}",
                s3config["bucketOwnerAccountId"] == state["account_id"], s3config["inclusionPrefixes"] == ["h02/knowledge/"],
                index["indexArn"] == state["index_arn"], index["dimension"] == 1024,
                index["dataType"] == "float32", index["distanceMetric"] == "cosine",
            )
            if not all(checks):
                raise ValueError()
            ids = [response["ResponseMetadata"]["RequestId"] for response in (source, kb_response, ds_response, index_response)]
            if any(not isinstance(value, str) or not value for value in ids) or len(set(ids)) != 4:
                raise ValueError()
        return {"connection_verified": True, "provider_mode": mode, "binding": binding,
                "observed_at": time.time(), "resource_request_ids": ids}
    except Exception:
        raise LedgerError(502) from None
