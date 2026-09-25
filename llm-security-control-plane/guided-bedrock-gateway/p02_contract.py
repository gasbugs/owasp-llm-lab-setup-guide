"""Explicit offline SDK fixture: persistent source bytes and synthetic unit vectors.

This does not simulate AWS authorization or semantic embedding quality.
"""
import hashlib
import io
import json
import math
import sqlite3
from uuid import uuid4


class ContractSDK:
    def __init__(self, path):
        self.path = str(path)
        with sqlite3.connect(self.path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS p02_contract_objects (bucket TEXT, key TEXT, content BLOB, PRIMARY KEY(bucket,key))")

    def metadata(self, operation):
        return {"RequestId": f"contract-{operation}-{uuid4()}"}

    def put_object(self, *, Bucket, Key, Body, ContentType, Metadata):
        if ContentType != "text/markdown; charset=utf-8" or Metadata != {"course": "tenant-03", "activity": "h02"}:
            raise ValueError("invalid contract source parameters")
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT OR REPLACE INTO p02_contract_objects VALUES(?,?,?)", (Bucket, Key, Body))
        return {"ResponseMetadata": self.metadata("put")}

    def get_object(self, *, Bucket, Key):
        with sqlite3.connect(self.path) as db:
            row = db.execute("SELECT content FROM p02_contract_objects WHERE bucket=? AND key=?", (Bucket, Key)).fetchone()
        if row is None:
            raise ValueError("contract source missing")
        return {"Body": io.BytesIO(row[0]), "ResponseMetadata": self.metadata("get")}

    def invoke_model(self, *, modelId, contentType, accept, body):
        request = json.loads(body)
        if (modelId != "amazon.titan-embed-text-v2:0" or contentType != "application/json" or accept != "application/json"
                or set(request) != {"inputText", "dimensions", "normalize"}
                or request["dimensions"] != 1024 or request["normalize"] is not True):
            raise ValueError("invalid contract embedding parameters")
        seed = hashlib.sha256(request["inputText"].encode()).digest()
        vector = [(seed[index % 32] - 127.5) / 127.5 for index in range(1024)]
        norm = math.sqrt(sum(value * value for value in vector))
        payload = {"embedding": [value / norm for value in vector], "inputTextTokenCount": max(1, len(request["inputText"].split()))}
        return {"body": io.BytesIO(json.dumps(payload).encode()), "ResponseMetadata": self.metadata("embed")}
