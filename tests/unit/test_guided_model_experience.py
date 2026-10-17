import importlib.util
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from types import ModuleType
import boto3
from botocore.config import Config
from fastapi.testclient import TestClient
ROOT=Path(__file__).resolve().parents[2]/"llm-security-control-plane/guided-labs/h23-model-call"
class Experience(unittest.TestCase):
    def setUp(self):
        learner=ModuleType("learner")
        learner.forward_question=lambda *args:None
        with patch.dict(os.environ,{"GUIDED_CONTROL_LAB01_TOKEN":"test-control", "GUIDED_VERIFIER_LAB01_TOKEN":"test-verifier"}),patch.dict(sys.modules,{"learner":learner}):
            spec=importlib.util.spec_from_file_location("model_experience",ROOT/"server.py")
            self.m=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.m)
        self.client=TestClient(self.m.app)
        self.headers={"Authorization":"Bearer "+self.m.CONTROL}
    def send(self,body):return self.client.post("/v1/chat",json=body,headers=self.headers)
    def test_authentication(self):self.assertEqual(self.client.post("/v1/chat",json={"message":"hi"}).status_code,401)
    def test_browser_cannot_claim_verdict(self):self.assertEqual(self.send({"message":"hi","task_completed":True}).status_code,422)
    def test_starter(self):
        def starter(*args):raise NotImplementedError()
        self.m.learner.forward_question=starter
        self.assertEqual(self.send({"message":"hi"}).status_code,501)
    def test_blank(self):
        def blank(*args):raise ValueError()
        self.m.learner.forward_question=blank
        self.assertEqual(self.send({"message":" "}).status_code,422)
    def test_fabricated_answer(self):
        self.m.learner.forward_question=lambda *args:{"reply":"fake"}
        self.assertEqual(self.send({"message":"hi"}).status_code,502)
    def test_actual_response_and_no_grade(self):
        response={"output":{"message":{"content":[{"text":"real answer"}]}},"usage":{"inputTokens":3,"outputTokens":2},"stopReason":"end_turn"}
        def forward(message):
            client=self.m.boto3.client("bedrock-runtime",region_name="us-east-1",config=Config(connect_timeout=5,read_timeout=90,retries={"total_max_attempts":1}))
            return client.converse(modelId=self.m.MODEL,messages=[{"role":"user","content":[{"text":message}]}],inferenceConfig={"maxTokens":64,"temperature":0})
        self.m.learner.forward_question=forward
        native=boto3.client("bedrock-runtime",region_name="us-east-1",aws_access_key_id="fixture",aws_secret_access_key="fixture")
        with patch.dict(os.environ, {"AWS_DEFAULT_REGION": "us-east-1"}), patch.object(native,"_make_api_call",return_value=response), patch.object(self.m.boto3,"client",return_value=native):
            result=self.send({"message":"hi"}).json()
        self.assertEqual(result['reply'],'real answer');self.assertIs(result['graded'],False)
        self.assertNotIn('task_completed',result);self.assertNotIn('security_verdict',result)
    def test_provider_error_has_no_answer(self):
        def unavailable(*args):raise RuntimeError("sensitive SDK details")
        self.m.learner.forward_question=unavailable
        response=self.send({"message":"hi"})
        self.assertEqual(response.status_code,502);self.assertNotIn("sensitive",response.text)
if __name__=='__main__':unittest.main()
