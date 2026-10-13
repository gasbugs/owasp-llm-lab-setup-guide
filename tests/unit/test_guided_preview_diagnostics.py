"""Direct-test budgets and safe, mission-specific troubleshooting."""
import importlib.util
import sys
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
CC=ROOT/"llm-security-control-plane/guided-control-center"
sys.path.insert(0,str(CC))
from diagnostics import diagnosis,FILES,CHECKS,SERVICES

class DiagnosticsTest(unittest.TestCase):
    def test_all_missions_have_existing_edit_file_and_action(self):
        self.assertEqual(set(FILES), {f"P{n:02d}" for n in range(24)})
        for mission,path in FILES.items():
            if mission != "P00":
                self.assertTrue((ROOT/path.removeprefix("~/owasp-llm-lab-setup-guide/")).is_file(),mission)
            hint=diagnosis(mission,502)
            self.assertEqual(hint["model_calls"],"기록 없음")
            self.assertTrue(hint["next_action"])
    def test_logs_target_the_mission_runner_not_a_shared_dependency(self):
        self.assertEqual(SERVICES['P12'],'guided-h12-application-pipeline')
        self.assertEqual(SERVICES['P20'],'guided-h20-alerts')
        for mission,service in SERVICES.items():
            self.assertTrue(diagnosis(mission,502)['log_command'].endswith(service))

    def test_observed_initialization_failure_preserves_proven_zero(self):
        hint=diagnosis("P07",502,{"cause":"등록되지 않은 input Rail: check input safety", "model_calls":"0회 — LLMRails 초기화에서 중단", "evidence":"실제 설정 검증 오류"})
        self.assertIn("check input safety",hint["cause"])
        self.assertTrue(hint["model_calls"].startswith("0회"))
    def test_raw_exception_and_credentials_are_not_forwarded(self):
        hint=diagnosis("P07",502,{"traceback":"secret", "authorization":"Bearer secret", "cause":{"secret":"hidden"}})
        self.assertNotIn("secret",str(hint))
    def test_authentication_and_input_errors_have_distinct_actions(self):
        self.assertNotEqual(diagnosis("P23",401)["cause"],diagnosis("P23",422)["cause"])

if __name__=="__main__":unittest.main()

class PreviewTransportTests(unittest.TestCase):
    def test_model_preview_sends_2048_but_records_learner_64(self):
        import os
        import boto3
        from botocore.config import Config
        from botocore.stub import Stubber
        from unittest.mock import patch
        location=ROOT/'llm-security-control-plane/guided-labs/h23-model-call'
        sys.path.insert(0,str(location))
        try:
            spec=importlib.util.spec_from_file_location('model_preview_budget',location/'server.py')
            module=importlib.util.module_from_spec(spec)
            with patch.dict(os.environ, {'GUIDED_CONTROL_LAB01_TOKEN':'test-control','GUIDED_VERIFIER_LAB01_TOKEN':'test-verifier'}):
                spec.loader.exec_module(module)
            config=Config(connect_timeout=5,read_timeout=90,retries={'total_max_attempts':1})
            client=boto3.client('bedrock-runtime',region_name='us-east-1',aws_access_key_id='fixture',aws_secret_access_key='fixture',config=config)
            args={'modelId':module.MODEL,'messages':[{'role':'user','content':[{'text':'question'}]}],'inferenceConfig':{'maxTokens':64,'temperature':0}}
            from copy import deepcopy
            actual=deepcopy(args);actual['inferenceConfig']['maxTokens']=2048
            result={'output':{'message':{'role':'assistant','content':[{'text':'answer'}]}},'stopReason':'end_turn','usage':{'inputTokens':1,'outputTokens':2,'totalTokens':3},'metrics':{'latencyMs':1}}
            recorder=module.SDKRecorder(preview_tokens=2048)
            with Stubber(client) as stub:
                stub.add_response('converse',result,actual)
                with patch.object(module.boto3,'client',return_value=client):
                    with recorder.observe():
                        sdk=module.boto3.client('bedrock-runtime',region_name='us-east-1',config=config)
                        self.assertEqual(sdk.converse(**args),result)
                stub.assert_no_pending_responses()
            self.assertEqual(recorder.calls[0]['inferenceConfig']['maxTokens'],64)
            self.assertEqual(args['inferenceConfig']['maxTokens'],64)
        finally:sys.path.remove(str(location))
