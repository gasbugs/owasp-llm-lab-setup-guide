"""Immutable execution and provider evidence for the first model-call mission."""
import hashlib
import hmac
import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from unittest.mock import patch
from botocore.client import BaseClient
from copy import deepcopy
from pathlib import Path
from uuid import UUID
import boto3
from botocore.config import Config
from botocore.exceptions import EndpointConnectionError
from fastapi import FastAPI, Header, HTTPException, Depends
from pydantic import BaseModel, ConfigDict, Field
import learner

MODEL = "us.amazon.nova-lite-v1:0"
ROOT = Path(__file__).parent
CONTROL = hmac.new(os.environ["GUIDED_CONTROL_LAB01_TOKEN"].encode(), b"model-call:P23", "sha256").hexdigest()
VERIFIER = hmac.new(os.environ["GUIDED_VERIFIER_LAB01_TOKEN"].encode(), b"model-call:P23", "sha256").hexdigest()
app = FastAPI(docs_url=None, redoc_url=None)

def auth(expected, authorization):
    if not hmac.compare_digest(authorization or "", "Bearer " + expected):
        raise HTTPException(401, "invalid token")

def control(authorization: str | None = Header(None)):
    auth(CONTROL, authorization)

def verifier(authorization: str | None = Header(None)):
    auth(VERIFIER, authorization)

class Run(BaseModel):
    model_config = ConfigDict(extra="forbid")
    execution_id: UUID

def identity():
    return {"source_digest": hashlib.sha256((ROOT/"learner.py").read_bytes()).hexdigest(),
            "runner_digest": hashlib.sha256((ROOT/"server.py").read_bytes()).hexdigest()}

SDK_LOCK = threading.Lock()
PROGRESS = {}
CASE_DEFINITIONS = [
    ("normal", "계정 비밀번호를 바꾸는 이유를 한 문장으로 설명해 주세요.", False),
    ("blank", "   ", False),
    ("provider-error", "연결 오류 처리 확인", True),
]

class SDKRecorder:
    def __init__(self, failure=False, preview_tokens=None):
        self.failure = failure
        self.preview_tokens = preview_tokens
        self.calls, self.results, self.clients = [], [], []
        self.attempts = self.errors = 0

    @contextmanager
    def observe(self):
        original_factory = boto3.client
        opened = []
        def create(service_name, **kwargs):
            config = kwargs.get("config")
            if (service_name != "bedrock-runtime" or set(kwargs) != {"region_name", "config"}
                or not kwargs["region_name"] or kwargs["region_name"] != boto3.session.Session().region_name or not isinstance(config, Config)
                or config.connect_timeout != 5 or config.read_timeout != 90
                or config.retries.get("total_max_attempts") != 1 or self.clients):
                raise ValueError("create one bounded Bedrock SDK client")
            sdk = original_factory(service_name, **kwargs)
            if not isinstance(sdk, BaseClient):
                raise ValueError("native Boto3 client required")
            self.clients.append({"service":"bedrock-runtime", "region":kwargs["region_name"], "native_sdk":True})
            original_call = sdk._make_api_call
            def invoke(operation, arguments):
                self.calls.append(deepcopy(arguments))
                if (operation != "Converse" or len(self.calls) != 1 or arguments.get("modelId") != MODEL
                    or arguments.get("inferenceConfig") != {"maxTokens":64,"temperature":0}):
                    raise ValueError("bounded Converse call required")
                if self.failure:
                    self.errors += 1
                    raise EndpointConnectionError(endpoint_url=sdk.meta.endpoint_url)
                self.attempts += 1
                provider_arguments = deepcopy(arguments)
                if self.preview_tokens is not None:
                    provider_arguments["inferenceConfig"]["maxTokens"] = self.preview_tokens
                response = original_call(operation, provider_arguments)
                self.results.append(deepcopy(response))
                return response
            sdk._make_api_call = invoke
            opened.append(sdk)
            return sdk
        with patch.object(boto3, "client", create):
            try:
                yield
            finally:
                for sdk in opened:
                    sdk.close()

@app.get("/readyz")
def ready():
    return {"status":"ready"}

@app.get("/v1/build-info")
def build(_=Depends(verifier)):
    return identity()

def sdk_session():
    if not SDK_LOCK.acquire(blocking=False):
        raise HTTPException(409, "모델 요청이 진행 중입니다.")
    try:
        yield
    finally:
        SDK_LOCK.release()

@app.post("/v1/run-suite")
def run(body: Run, _=Depends(control), _sdk=Depends(sdk_session)):
    execution = str(body.execution_id)
    with sqlite3.connect("/tmp/model-call.sqlite3") as db:
        db.execute("CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, payload TEXT NOT NULL)")
        try:
            db.execute("INSERT INTO runs VALUES (?, ?)", (execution, "{}"))
        except sqlite3.IntegrityError:
            raise HTTPException(409, "execution already exists")
    cases=[]
    progress={"suite_id":execution,"phase":"running","total":len(CASE_DEFINITIONS),"cases":[],"current_case":None}
    PROGRESS[execution]=progress
    for number, (name, message, fail) in enumerate(CASE_DEFINITIONS, 1):
        progress["current_case"]={"number":number,"case_id":name,"status":"실행 중"}
        client=SDKRecorder(fail)
        returned=None
        error=None
        try:
            with client.observe():
                returned=learner.forward_question(message)
        except Exception as exc:
            error={"type":type(exc).__name__, "message":str(exc)}
        case={"case_id":name,"input":message,"failure_fixture":fail,
            "returned":returned,"error":error,"sdk_clients":client.clients,"calls":client.calls,"provider_attempts":client.attempts,
            "provider_results":client.results,"fixture_errors":client.errors}
        cases.append(case)
        progress["cases"].append({"number":number,"case_id":name,"status":"실행 완료","provider_attempts":client.attempts,
            "error_type":error.get("type") if error else None})
        progress["current_case"]=None
    progress["phase"]="verifying"
    payload={"activity_id":"P23","execution_id":execution,"closed":True,**identity(),"cases":cases}
    with sqlite3.connect("/tmp/model-call.sqlite3") as db:
        db.execute("UPDATE runs SET payload=? WHERE id=?", (json.dumps(payload,ensure_ascii=False),execution))
    return {"execution_id":execution}

@app.get("/v1/progress/{execution_id}")
def progress(execution_id: UUID, _=Depends(control)):
    state=PROGRESS.get(str(execution_id))
    if state is None:
        raise HTTPException(404,"progress unavailable")
    return deepcopy(state)

@app.get("/v1/receipts/{execution_id}")
def receipt(execution_id: UUID, _=Depends(verifier)):
    try:
        with sqlite3.connect("/tmp/model-call.sqlite3") as db:
            row=db.execute("SELECT payload FROM runs WHERE id=?", (str(execution_id),)).fetchone()
    except sqlite3.OperationalError:
        row=None
    if not row:
        raise HTTPException(404,"receipt unavailable")
    return json.loads(row[0])


class Chat(BaseModel):
    model_config = ConfigDict(extra="forbid")
    message: str = Field(min_length=1, max_length=4000)

@app.post("/v1/chat")
def chat(body: Chat, _=Depends(control), _sdk=Depends(sdk_session)):
    client=SDKRecorder(preview_tokens=2048)
    try:
        with client.observe():
            response=learner.forward_question(body.message)
    except NotImplementedError:
        raise HTTPException(501,"forward_question을 작성하고 모델 연결 앱에 적용하세요.")
    except ValueError:
        raise HTTPException(422,"질문 내용을 확인하세요. 빈 질문은 보낼 수 없습니다.")
    except Exception:
        raise HTTPException(502,"모델 응답을 받지 못했습니다. 코드 적용 상태와 AWS 모델 호출 권한을 확인하세요.")
    if client.attempts != 1 or len(client.results) != 1 or response != client.results[0] or not isinstance(response,dict):
        raise HTTPException(502,"실제 Converse 응답을 그대로 반환하는지 확인하세요.")
    content=response.get("output",{}).get("message",{}).get("content",[])
    return {"graded":False,"reply":"\n".join(part["text"] for part in content if isinstance(part,dict) and isinstance(part.get("text"),str)),
        "model_id":MODEL,"usage":response.get("usage"),"stop_reason":response.get("stopReason"),
        "provider_attempts":client.attempts, "preview_max_tokens":2048, "learner_max_tokens":64, **identity(),"response":response}
