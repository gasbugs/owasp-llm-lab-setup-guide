"""Observe real learner-created Boto3 clients in the bounded execution worker."""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import io
import json
import math
from unittest.mock import patch

import boto3
from botocore.client import BaseClient
from botocore.response import StreamingBody
import httpx

from service_client import ServiceError

MODEL = "amazon.titan-embed-text-v2:0"


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                    allow_nan=False).encode()).hexdigest()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class NativeSDK:
    def __init__(self, configuration):
        self.configuration = configuration
        self.calls, self.clients, self.handles, self.native = [], [], [], []
        self.connection = None

    def authenticate(self):
        if self.connection is None:
            cfg = self.configuration
            try:
                with httpx.Client(timeout=30, trust_env=False, follow_redirects=False) as client:
                    response = client.post(cfg["origin"] + "/v1/p02/native-credentials",
                        headers={"Authorization": "Bearer " + cfg["capability"]},
                        json={"suite_id": cfg["suite_id"], "execution_id": cfg["execution_id"]})
                    if response.status_code != 200 or len(response.content) > 8192:
                        raise ServiceError()
                    value = response.json()
                if set(value) != {"region", "bucket", "credentials", "provider_mode"} or value["provider_mode"] not in {"aws", "contract"} or value["region"] != "us-east-1":
                    raise ServiceError()
                if (not isinstance(value["bucket"], str) or not value["bucket"]
                        or set(value["credentials"]) != {"AccessKeyId", "SecretAccessKey", "SessionToken"}
                        or any(not isinstance(v, str) or not v for v in value["credentials"].values())):
                    raise ServiceError()
                self.connection = value
            except Exception:
                raise ServiceError("P02 AWS authentication failed") from None
        return self.connection

    @contextmanager
    def observe(self):
        factory = boto3.session.Session.client

        def create(session, service_name, **kwargs):
            if service_name not in {"s3", "bedrock-runtime"} or set(kwargs) != {"region_name", "config"}:
                raise ServiceError("create the bounded AWS SDK client")
            config = kwargs["config"]
            if (kwargs["region_name"] != "us-east-1" or config.connect_timeout != 5
                    or config.read_timeout != 20 or config.retries.get("total_max_attempts") != 1
                    or service_name in [row["service"] for row in self.clients]):
                raise ServiceError("bounded client settings required")
            connection = self.authenticate()
            credentials = session.get_credentials().get_frozen_credentials()
            issued = connection["credentials"]
            if ((credentials.access_key, credentials.secret_key, credentials.token) !=
                    (issued["AccessKeyId"], issued["SecretAccessKey"], issued["SessionToken"])):
                raise ServiceError("use the provided AWS session")
            client = factory(session, service_name, **kwargs)
            if not isinstance(client, BaseClient):
                raise ServiceError("native Boto3 client required")
            self.handles.append(client)
            self.clients.append({"service": service_name, "region": "us-east-1", "native_sdk": True})
            original = client._make_api_call
            if connection["provider_mode"] == "contract":
                original = self.contract_call
            client._make_api_call = lambda operation, arguments: self.invoke(service_name, original, operation, arguments)
            return client

        try:
            with patch.object(boto3.session.Session, "client", create):
                yield
        finally:
            for client in self.handles:
                client.close()

    def invoke(self, service, original, operation, arguments):
        key = f"h02/knowledge/{self.configuration['execution_id']}.md"
        if len(self.calls) >= 2 or (self.calls and self.calls[-1]["state"] != "complete"):
            raise ServiceError("two ordered SDK calls required")
        if service == "s3" and operation == "PutObject" and not self.calls:
            if (set(arguments) != {"Bucket", "Key", "Body", "ContentType", "Metadata"}
                    or arguments["Bucket"] != self.authenticate()["bucket"] or arguments["Key"] != key
                    or arguments["ContentType"] != "text/markdown; charset=utf-8"
                    or arguments["Metadata"] != {"course": "tenant-03", "activity": "h02"}):
                raise ServiceError("server-issued S3 location required")
            raw = arguments["Body"]
            if isinstance(raw, str):
                raw = raw.encode()
            if not isinstance(raw, bytes) or not 0 < len(raw) <= 32768:
                raise ServiceError("bounded UTF-8 source required")
            payload = {"key": key, "content": raw.decode()}
            name = "store_source"
        elif service == "bedrock-runtime" and operation == "InvokeModel" and len(self.calls) == 1:
            if (set(arguments) != {"modelId", "contentType", "accept", "body"}
                    or arguments["modelId"] != MODEL or arguments["contentType"] != "application/json"
                    or arguments["accept"] != "application/json"):
                raise ServiceError("Titan embedding request required")
            request = json.loads(arguments["body"])
            if (set(request) != {"inputText", "dimensions", "normalize"}
                    or not isinstance(request["inputText"], str) or not 1 <= len(request["inputText"]) <= 4000
                    or type(request["dimensions"]) is not int or request["dimensions"] != 1024
                    or request["normalize"] is not True):
                raise ServiceError("bounded normalized embedding required")
            payload = {"text": request["inputText"]}
            name = "embed"
        else:
            raise ServiceError("store the source before embedding")
        call = {"operation": name, "state": "error", "request_digest": digest(payload),
                "sdk_service": service, "sdk_operation": operation, "native_sdk": True}
        self.calls.append(call)
        response = original(operation, arguments)
        meta = response["ResponseMetadata"]
        identity = meta["RequestId"]
        if meta.get("HTTPStatusCode") != 200 or not isinstance(identity, str) or not identity:
            raise ServiceError("actual AWS response required")
        if name == "store_source":
            native = deepcopy(response)
            proof = {"provider_mode": self.connection["provider_mode"], "provider_request_id": identity, "object_key": key,
                     "object_uri": f"s3://{self.connection['bucket']}/{key}",
                     "source_digest": sha(raw), "source_bytes": len(raw)}
        else:
            stream = response["body"]
            try:
                raw = stream.read(131073)
            finally:
                stream.close()
            if len(raw) > 131072:
                raise ServiceError("bounded embedding response required")
            native = json.loads(raw)
            vector, count = native["embedding"], native["inputTextTokenCount"]
            if (not isinstance(vector, list) or len(vector) != 1024
                    or any(type(v) not in (int, float) or not math.isfinite(v) for v in vector)
                    or type(count) is not int or count < 1):
                raise ServiceError("valid embedding response required")
            response["body"] = StreamingBody(io.BytesIO(raw), len(raw))
            proof = {"provider_mode": self.connection["provider_mode"], "provider_request_id": identity, "model_id": MODEL,
                     "input_digest": sha(payload["text"].encode()), "input_token_count": count,
                     "embedding_dimension": 1024, "embedding_norm": math.sqrt(sum(v*v for v in vector)),
                     "vector_digest": sha(json.dumps(vector, separators=(",", ":"), allow_nan=False).encode())}
        self.native.append(native)
        call.update(state="complete", http_status=200, response=proof, response_digest=digest(proof))
        return response

    def contract_call(self, operation, arguments):
        if operation == "PutObject":
            content = arguments["Body"]
            if isinstance(content, bytes):
                content = content.decode()
            name, payload = "store_source", {"key": arguments["Key"], "content": content}
        else:
            text = json.loads(arguments["body"])["inputText"]
            name, payload = "embed", {"text": text}
        cfg = self.configuration
        with httpx.Client(timeout=30, trust_env=False, follow_redirects=False) as client:
            response = client.post(cfg["origin"] + "/v1/p02/invoke",
                headers={"Authorization": "Bearer " + cfg["capability"]},
                json={"suite_id": cfg["suite_id"], "execution_id": cfg["execution_id"],
                      "operation": name, "payload": payload})
            if response.status_code != 200:
                raise ServiceError("contract fixture invocation failed")
            proof = response.json()["response"]
        if proof["provider_mode"] != "contract":
            raise ServiceError("explicit contract fixture required")
        result = {"ResponseMetadata": {"RequestId": proof["provider_request_id"], "HTTPStatusCode": 200}}
        if name == "embed":
            seed = hashlib.sha256(text.encode()).digest()
            vector = [(seed[index % 32] - 127.5) / 127.5 for index in range(1024)]
            norm = math.sqrt(sum(value * value for value in vector))
            raw = json.dumps({"embedding": [value / norm for value in vector],
                              "inputTextTokenCount": max(1, len(text.split()))}).encode()
            result["body"] = StreamingBody(io.BytesIO(raw), len(raw))
        return result

    def normalize(self, value):
        if (len(self.native) != 2 or value != {"source": self.native[0], "embedding": self.native[1]}):
            raise ServiceError("return the actual AWS source and parsed embedding responses")
        return {"source": self.calls[0]["response"], "embedding": self.calls[1]["response"]}
