import copy
import importlib.util
import sys
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]/"llm-security-control-plane"
spec=importlib.util.spec_from_file_location("p23_verification",ROOT/"guided-evidence-verifier/p23_verification.py")
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Checks(unittest.TestCase):
    def receipt(self):
        response={"ResponseMetadata":{"RequestId":"actual-aws-id"},"output":{"message":{"content":[{"text":"answer"}]}},"usage":{"outputTokens":4}}
        call={"modelId":m.MODEL,"messages":[{"role":"user","content":[{"text":"계정 비밀번호를 바꾸는 이유를 한 문장으로 설명해 주세요."}]}],"inferenceConfig":{"maxTokens":64,"temperature":0}}
        return {"activity_id":"P23","execution_id":"fresh","closed":True,"source_digest":"a"*64,"runner_digest":"b"*64,"cases":[
            {"case_id":"normal","sdk_clients":[{"service":"bedrock-runtime","region":"us-east-1","native_sdk":True}],"returned":response,"error":None,"calls":[call],"provider_attempts":1,"provider_results":[copy.deepcopy(response)]},
            {"case_id":"blank","sdk_clients":[],"returned":None,"error":{"type":"ValueError","message":"empty"},"calls":[],"provider_attempts":0},
            {"case_id":"provider-error","sdk_clients":[{"service":"bedrock-runtime","region":"us-east-1","native_sdk":True}],"returned":None,"error":{"type":"RuntimeError","message":"model unavailable"},"calls":[{**call,"messages":[{"role":"user","content":[{"text":"연결 오류 처리 확인"}]}]}],"fixture_errors":1,"provider_attempts":0,"provider_results":[]}]}
    def grade(self,r):
        return m.check(r,{"source_digest":"a"*64,"runner_digest":"b"*64},"b"*64,"fresh")
    def test_complete(self): self.assertTrue(self.grade(self.receipt())["task_completed"])
    def test_fake_answer(self):
        r=self.receipt();r["cases"][0]["returned"]["output"]["message"]["content"]=[{"text":"fake"}]
        self.assertFalse(self.grade(r)["task_completed"])
    def test_mock_provider(self):
        r=self.receipt();r["cases"][0]["returned"]["ResponseMetadata"]["RequestId"]="contract-mock"
        r["cases"][0]["provider_results"]=[copy.deepcopy(r["cases"][0]["returned"])]
        self.assertFalse(self.grade(r)["task_completed"])
    def test_blank_calls_model(self):
        r=self.receipt();r["cases"][1]["calls"]=[{}];self.assertFalse(self.grade(r)["task_completed"])
    def test_swallowed_error(self):
        r=self.receipt();r["cases"][2]["error"]=None;self.assertFalse(self.grade(r)["task_completed"])
    def test_missing_case(self):
        r=self.receipt();r["cases"].pop()
        with self.assertRaises(ValueError):self.grade(r)
    def test_stale_or_runner_changed(self):
        for field,value in [("execution_id","old"),("runner_digest","x"),("source_digest","x"),("closed",False)]:
            r=self.receipt();r[field]=value
            with self.assertRaises(ValueError):self.grade(r)
    def test_wrong_forwarding(self):
        r=self.receipt();r["cases"][0]["calls"][0]["messages"][0]["content"][0]["text"]="different"
        self.assertFalse(self.grade(r)["task_completed"])
if __name__=="__main__":unittest.main()
