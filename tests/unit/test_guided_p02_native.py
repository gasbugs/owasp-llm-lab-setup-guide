"""Actual Boto3 objects with Stubber responses; no live AWS or secret payload output."""
import asyncio
from contextlib import ExitStack
from copy import deepcopy
from datetime import datetime, timezone
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock
from uuid import uuid4

import boto3
from botocore.config import Config
from botocore.response import StreamingBody
from botocore.stub import Stubber
from fastapi.testclient import TestClient

ROOT=Path(__file__).resolve().parents[2]/"llm-security-control-plane"
LAB=ROOT/"guided-labs/h02-document-ingestion"
GATEWAY=ROOT/"guided-bedrock-gateway"
sys.path.insert(0,str(LAB));sys.path.insert(0,str(GATEWAY))
from native_runtime import NativeSDK
from service_client import ServiceError
from p02_api import create_app
from p02_ledger import DocumentLedger
from p02_gateway import configured_app

class NativeTests(unittest.TestCase):
    def setUp(self):
        self.connection={"provider_mode":"aws","region":"us-east-1","bucket":"native-fixture-bucket",
            "credentials":{"AccessKeyId":"fixture-key","SecretAccessKey":"fixture-secret","SessionToken":"fixture-session"}}
        self.config={"suite_id":str(uuid4()),"execution_id":str(uuid4()),
            "origin":"http://gateway.invalid","capability":"x"*48}
        self.sdk=NativeSDK(self.config)
        self.body={"title":"계정 안내","body":"계정 설정은 개인 계정으로 로그인한 뒤 변경합니다."}
        namespace={}
        exec((Path(__file__).resolve().parents[1]/"fixtures/p02-native-solution.py").read_text(),namespace)
        self.function=namespace["prepare_document"]
        self.response={"embedding":[0.03125]*1024,"inputTextTokenCount":14}
    def run_function(self, body=None, *, fail_store=False, transform=None):
        native_factory=boto3.session.Session.client
        stubbers=[]
        def client(session,name,**kwargs):
            value=native_factory(session,name,**kwargs)
            stub=Stubber(value)
            if name=="s3":
                if fail_store:
                    stub.add_client_error("put_object",service_error_code="AccessDenied")
                else:
                    stub.add_response("put_object",{"ETag":"fixture","ResponseMetadata":{"RequestId":"source-id","HTTPStatusCode":200}})
            else:
                raw=json.dumps(self.response).encode()
                stub.add_response("invoke_model",{"body":StreamingBody(io.BytesIO(raw),len(raw)),"contentType":"application/json",
                    "ResponseMetadata":{"RequestId":"embedding-id","HTTPStatusCode":200}})
            stub.activate();stubbers.append(stub)
            return value
        try:
            with patch.object(self.sdk,"authenticate",side_effect=self.auth),patch.object(boto3.session.Session,"client",client):
                with self.sdk.observe():
                    result=asyncio.run(self.function(self.body if body is None else body,self.config["execution_id"],self.sdk))
                    if transform: result=transform(result)
                    return self.sdk.normalize(result)
        finally:
            for stub in stubbers:stub.deactivate()
    def auth(self):
        self.sdk.connection=self.connection
        return self.connection
    def test_actual_sdk_and_responses(self):
        result=self.run_function()
        self.assertEqual({c["service"] for c in self.sdk.clients},{"s3","bedrock-runtime"})
        self.assertTrue(all(c["native_sdk"] for c in self.sdk.clients))
        self.assertEqual([c["sdk_operation"] for c in self.sdk.calls],["PutObject","InvokeModel"])
        self.assertEqual(result["embedding"]["embedding_dimension"],1024)
        self.assertEqual(result["source"]["source_digest"],__import__("hashlib").sha256(f"# {self.body['title']}\n\n{self.body['body']}\n".encode()).hexdigest())
    def test_invalid_input_has_no_sdk_or_auth(self):
        for body in ({}, {"title":"ok","body":"short"}, {"title":" ","body":"x"*10}):
            with self.assertRaises(ValueError): self.run_function(body)
            self.assertEqual(self.sdk.calls,[]);self.assertEqual(self.sdk.clients,[])
            self.assertIsNone(self.sdk.connection)
    def test_store_failure_stops_embedding(self):
        with self.assertRaises(Exception):self.run_function(fail_store=True)
        self.assertEqual(len(self.sdk.calls),1)
        self.assertEqual(self.sdk.calls[0]["operation"],"store_source")
        self.assertEqual(self.sdk.calls[0]["state"],"error")
    def test_fabricated_return_is_rejected(self):
        with self.assertRaises(ServiceError):self.run_function(transform=lambda result:{"source":{},"embedding":{}})
    def test_embedding_before_store_is_rejected(self):
        from aws_auth import load_aws_session
        with patch.object(self.sdk,"authenticate",side_effect=self.auth),self.sdk.observe():
            session,_=load_aws_session(self.sdk)
            client=session.client("bedrock-runtime",region_name="us-east-1",config=Config(connect_timeout=5,read_timeout=20,retries={"total_max_attempts":1}))
            with self.assertRaises(ServiceError):client.invoke_model(modelId="wrong",body="{}")
        self.assertEqual(self.sdk.calls,[])

class CredentialBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.ledger=DocumentLedger(Path(self.tmp.name)/"ledger.sqlite")
        self.suite,self.execution=str(uuid4()),str(uuid4())
        self.grant=self.ledger.register(self.suite,self.execution,"a"*64,"b"*64)
        self.issuer=MagicMock(return_value={"credentials":{"SecretAccessKey":"fixture"}})
        self.client=TestClient(create_app(self.ledger,lambda:None,control_token="control",verifier_token="verifier",native_credentials=self.issuer))
        self.body={"suite_id":self.suite,"execution_id":self.execution}
    def tearDown(self):self.tmp.cleanup()
    def test_capability_binding_and_no_store(self):
        for token,status in (("wrong",401),("verifier",401),("control",401)):
            self.assertEqual(self.client.post("/native-credentials",json=self.body,headers={"Authorization":"Bearer "+token}).status_code,status)
        response=self.client.post("/native-credentials",json=self.body,headers={"Authorization":"Bearer "+self.grant["capability"]})
        self.assertEqual(response.status_code,200);self.assertEqual(response.headers["cache-control"],"no-store")
        self.issuer.assert_called_once_with(self.execution)
        self.assertEqual(self.client.post("/native-credentials",json=self.body,headers={"Authorization":"Bearer "+self.grant["capability"]}).status_code,409)
        self.issuer.assert_called_once_with(self.execution)
        public=self.client.get("/executions/"+self.execution,headers={"Authorization":"Bearer verifier"})
        self.assertNotIn("SecretAccessKey",public.text)
    def test_wrong_suite_closed_execution_and_learner_record(self):
        headers={"Authorization":"Bearer "+self.grant["capability"]}
        self.assertEqual(self.client.post("/native-credentials",json={**self.body,"suite_id":str(uuid4())},headers=headers).status_code,403)
        self.ledger.close(self.execution)
        self.assertEqual(self.client.post("/native-credentials",json=self.body,headers=headers).status_code,409)
        self.assertEqual(self.client.post("/native-record",json={**self.body,"capability":self.grant["capability"],"operation":"store_source","request_digest":"c"*64,"response":None},headers=headers).status_code,401)
        self.issuer.assert_not_called()
    def test_sts_policy_is_one_document_and_one_model(self):
        state={"status":"READY","provider_mode":"aws","region":"us-east-1","source_prefix":"h02/knowledge/","source_bucket":"native-fixture-bucket"}
        sts=boto3.client("sts",region_name="us-east-1",aws_access_key_id="fixture",aws_secret_access_key="fixture")
        stub=Stubber(sts)
        stub.add_response("get_federation_token",{"Credentials":{"AccessKeyId":"A"*20,"SecretAccessKey":"S"*40,
            "SessionToken":"fixture-session","Expiration":datetime.now(timezone.utc)},
            "FederatedUser":{"FederatedUserId":"123456789012:fixture","Arn":"arn:aws:sts::123456789012:federated-user/fixture"}})
        stub.activate()
        sts.get_federation_token=MagicMock(wraps=sts.get_federation_token)
        def factory(name,**kwargs):return sts if name=="sts" else MagicMock()
        with patch("p02_gateway.boto3.client",side_effect=factory):
            app=configured_app(lambda:state,Path(self.tmp.name)/"other.sqlite",provider_mode="aws",control_token="control",verifier_token="verifier",region="us-east-1")
            client=TestClient(app)
            grant=client.post("/executions",headers={"Authorization":"Bearer control"},json={**self.body,"source_digest":"a"*64,"runner_digest":"b"*64}).json()
            response=client.post("/native-credentials",headers={"Authorization":"Bearer "+grant["capability"]},json=self.body)
        self.assertEqual(response.status_code,200)
        args=sts.get_federation_token.call_args.kwargs
        self.assertEqual(args["DurationSeconds"],900)
        statements=json.loads(args["Policy"])["Statement"]
        self.assertEqual(statements,[{"Effect":"Allow","Action":"s3:PutObject","Resource":f"arn:aws:s3:::native-fixture-bucket/h02/knowledge/{self.execution}.md"},
            {"Effect":"Allow","Action":"bedrock:InvokeModel","Resource":"arn:aws:bedrock:us-east-1::foundation-model/amazon.titan-embed-text-v2:0"}])
        self.assertEqual(set(response.json()["credentials"]),{"AccessKeyId","SecretAccessKey","SessionToken"})
        stub.assert_no_pending_responses();stub.deactivate()

class NativeChildIntegrationTests(unittest.TestCase):
    def test_bounded_child_http_ledger_and_independent_source(self):
        import socket, threading, time
        import uvicorn
        execution_spec=importlib.util.spec_from_file_location("p02_native_execution",LAB/"execution.py")
        execution_module=importlib.util.module_from_spec(execution_spec);execution_spec.loader.exec_module(execution_module)
        spec=importlib.util.spec_from_file_location("p02_native_workflow",LAB/"workflow.py")
        workflow_module=importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules,{"execution":execution_module}):spec.loader.exec_module(workflow_module)
        Workflow=workflow_module.Workflow
        from p02_provider import DocumentProvider
        from p02_contract import ContractSDK
        sys.path.insert(0,str(ROOT/"guided-evidence-verifier"))
        from p02_results import verify_case
        with tempfile.TemporaryDirectory() as tmp:
            ledger=DocumentLedger(Path(tmp)/"ledger.sqlite")
            provider=DocumentProvider(ledger,ContractSDK(ledger.path),ContractSDK(ledger.path),"contract-source",provider_mode="contract")
            app=create_app(ledger,lambda:provider,control_token="control",verifier_token="verifier",
                native_credentials=lambda execution:{"provider_mode":"contract","region":"us-east-1","bucket":"contract-source",
                    "credentials":{"AccessKeyId":"contract-key","SecretAccessKey":"contract-secret","SessionToken":"contract-session"}})
            from fastapi import FastAPI
            outer=FastAPI();outer.mount("/v1/p02",app)
            sock=socket.socket();sock.bind(("127.0.0.1",0));sock.listen()
            origin="http://127.0.0.1:"+str(sock.getsockname()[1])
            server=uvicorn.Server(uvicorn.Config(outer,log_level="error"))
            thread=threading.Thread(target=server.run,kwargs={"sockets":[sock]},daemon=True);thread.start()
            try:
                deadline=time.monotonic()+5
                while not server.started:
                    if time.monotonic()>deadline:raise TimeoutError("fixture startup")
                    time.sleep(.01)
                workflow=Workflow(origin,"control",native_sdk=True)
                source=Path(__file__).resolve().parents[1]/"fixtures/p02-native-solution.py"
                for body,valid in (({"title":"계정 안내","body":"계정은 개인 계정으로 로그인한 뒤 변경합니다."},True),
                                   ({"title":"invalid","body":"short"},False)):
                    suite,execution=str(uuid4()),str(uuid4())
                    result=workflow.run_case(source,body,suite_id=suite,execution_id=execution,runner_digest="b"*64)
                    self.assertEqual(result["lifecycle_status"],"finished")
                    verified=verify_case({"suite_id":suite,"execution_id":execution,"body":body,"valid":valid},
                        result,ledger.read(execution),provider.source_evidence(execution) if valid else None,
                        source_digest=result["source_digest"],runner_digest="b"*64,bucket="contract-source",
                        provider_mode="contract",native_sdk=True)
                    self.assertTrue(verified["case_verified"])
                    self.assertEqual(verified["calls"],2 if valid else 0)
            finally:
                server.should_exit=True;thread.join(5);sock.close()


if __name__=="__main__":unittest.main()
