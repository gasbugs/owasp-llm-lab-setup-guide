"""Real Boto3 objects with Stubber, plus bounded child/HTTP contract cases. No AWS."""
import asyncio
from contextlib import ExitStack
import importlib.util
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from uuid import uuid4

import boto3
from botocore.stub import Stubber
from fastapi import FastAPI
from fastapi.testclient import TestClient
import uvicorn

BASE = Path(__file__).resolve().parents[2] / 'llm-security-control-plane'
LAB = BASE / 'guided-labs/h03-ingestion-search'
GATEWAY = BASE / 'guided-bedrock-gateway'

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); sys.modules[name] = value
    spec.loader.exec_module(value); return value

service = load('p03_native_service', LAB/'service_client.py')
with patch.dict(sys.modules, {'service_client': service}):
    runtime = load('p03_native_runtime', LAB/'native_runtime.py')
auth = load('p03_native_auth', LAB/'aws_auth.py')
with patch.dict(sys.modules, {'aws_auth': auth}):
    scope = {};exec((Path(__file__).resolve().parents[1]/'e2e/fixtures/p03_search_current.py').read_text(),scope)
function = scope['search_current']

class NativeTests(unittest.TestCase):
    def setUp(self):
        self.connection={'provider_mode':'aws','region':'us-east-1','current_job_id':'current-alias',
            'binding':{'knowledgeBaseId':'ABCDEFGHIJ','dataSourceId':'KLMNOPQRST','ingestionJobId':'UVWXYZABCD'},
            'credentials':{'AccessKeyId':'fixture-key','SecretAccessKey':'fixture-secret','SessionToken':'fixture-session'}}
        self.sdk=runtime.NativeSDK(suite_id=str(uuid4()),execution_id=str(uuid4()),origin='http://fixture.invalid',capability='x'*48)
        self.sdk.connection=self.connection
    def run_case(self,status='COMPLETE',fail=False):
        original=boto3.session.Session.client;stubbers=[]
        def client(session,name,**kw):
            result=original(session,name,**kw);stub=Stubber(result)
            if name=='bedrock-agent':
                if fail:stub.add_client_error('get_ingestion_job',service_error_code='AccessDeniedException')
                else:
                    from datetime import datetime, timezone
                    stamp=datetime.now(timezone.utc)
                    stub.add_response('get_ingestion_job',{'ingestionJob':{**self.connection['binding'],'status':status,
                        'startedAt':stamp,'updatedAt':stamp,'statistics':{'numberOfDocumentsFailed':0}},
                        'ResponseMetadata':{'HTTPStatusCode':200,'RequestId':'status-native-id'}})
            else:
                stub.add_response('retrieve',{'retrievalResults':[{'content':{'text':'current policy'},
                    'location':{'type':'S3','s3Location':{'uri':'s3://fixture/h03/knowledge/current.md'}},'score':.8}],
                    'ResponseMetadata':{'HTTPStatusCode':200,'RequestId':'retrieval-native-id'}}, expected_params={'knowledgeBaseId':self.connection['binding']['knowledgeBaseId'], 'retrievalQuery':{'text':self.sdk.query}, 'retrievalConfiguration':{'vectorSearchConfiguration':{'numberOfResults':3}}})
            stub.activate();stubbers.append(stub);return result
        try:
            with patch.object(boto3.session.Session,'client',client),self.sdk.observe():
                value=asyncio.run(function('current-alias',self.sdk))
                return self.sdk.normalize(value)
        finally:
            for stub in stubbers:stub.deactivate()
    def test_real_sdk_and_native_response(self):
        result=self.run_case()
        self.assertEqual(result['status'],'ready');self.assertEqual(len(self.sdk.calls),2)
        self.assertEqual([c['sdk_operation'] for c in self.sdk.calls],['GetIngestionJob','Retrieve'])
        self.assertEqual(self.sdk.native['retrieve']['ResponseMetadata']['RequestId'],'retrieval-native-id')
    def test_direct_query_reaches_real_sdk_retrieve_parameters(self):
        self.sdk.query = '계정 접근 절차를 검색합니다'
        self.assertEqual(self.run_case()['status'], 'ready')
        self.assertEqual(self.sdk.native['retrieve']['ResponseMetadata']['RequestId'], 'retrieval-native-id')

    def test_pending_never_retrieves(self):
        self.assertEqual(self.run_case('IN_PROGRESS'),{'status':'waiting','result':None})
        self.assertEqual(len(self.sdk.calls),1)
    def test_failed_job_never_retrieves(self):
        with self.assertRaises(ValueError):self.run_case('FAILED')
        self.assertEqual(len(self.sdk.calls),1)
    def test_aws_failure_never_retrieves(self):
        with self.assertRaises(service.ServiceError):self.run_case(fail=True)
        self.assertEqual(len(self.sdk.calls),1);self.assertEqual(self.sdk.calls[0]['state'],'error')
    def test_fabricated_search_response_rejected(self):
        self.run_case()
        with self.assertRaises(service.ServiceError):self.sdk.normalize({'status':'ready','result':{}})

class ContractChildTests(unittest.TestCase):
    def test_all_19_cases_real_child_sdk_and_closed_ledger(self):
        with ExitStack() as cleanup, tempfile.TemporaryDirectory() as tmp:
            cleanup.enter_context(patch.object(sys,'path',[str(GATEWAY),str(LAB),str(BASE/'guided-evidence-verifier')]+sys.path))
            from p03_gateway import configured_app
            from p03_ledger import SearchLedger
            from p03_results import verify_case
            from p03_suite_verification import fixture_status
            execution=load('p03_native_execution',LAB/'execution.py')
            with patch.dict(sys.modules,{'execution':execution}):flow=load('p03_native_workflow',LAB/'workflow.py')
            cases=load('p03_native_cases',LAB/'cases.py').cases()
            database=Path(tmp)/'ledger.sqlite'
            child=configured_app(database,provider_mode='contract',control_token='control',verifier_token='verifier',region='us-east-1')
            app=FastAPI();app.mount('/v1/p03',child)
            sock=socket.socket();sock.bind(('127.0.0.1',0));sock.listen()
            origin='http://127.0.0.1:'+str(sock.getsockname()[1])
            server=uvicorn.Server(uvicorn.Config(app,log_level='error'))
            thread=threading.Thread(target=server.run,kwargs={'sockets':[sock]},daemon=True);thread.start()
            try:
                deadline=time.monotonic()+5
                while not server.started:
                    if time.monotonic()>deadline:raise TimeoutError()
                    time.sleep(.01)
                workflow=flow.Workflow(origin,'control',native_sdk=True)
                suite=str(uuid4());rows=[{'case_id':c['case_id'],'execution_id':str(uuid4())} for c in cases]
                workflow.prepare_suite(suite_id=suite,executions=rows)
                ledger=SearchLedger(database)
                source=Path(__file__).resolve().parents[1]/'e2e/fixtures/p03_search_current.py'
                for case,row in zip(cases,rows):
                    with self.subTest(case=case['case_id']):
                        result=workflow.run_case(source,suite_id=suite,execution_id=row['execution_id'],runner_digest='b'*64)
                        record=ledger.read(row['execution_id']);job=record['current_job_id']
                        expected={**case,'suite_id':suite,'execution_id':row['execution_id'],'current_job_id':job,
                            'status_response':fixture_status(case,job),'source_uris':['s3://p03-contract/h03/knowledge/current-policy.md']}
                        checked=verify_case(expected,result,record,source_digest=result['source_digest'],runner_digest='b'*64,now=time.time(),provider_mode='contract')
                        self.assertTrue(checked['case_verified']);self.assertTrue(result['execution']['native_sdk'])
                        self.assertTrue(all(c['native_sdk'] for c in result['execution']['calls']))
                with TestClient(child) as client:
                    request={'suite_id':suite,'execution_id':rows[0]['execution_id']}
                    self.assertEqual(client.post('/native-credentials',json=request,headers={'Authorization':'Bearer verifier'}).status_code,401)
                    self.assertEqual(client.post('/native-record',json={**request,'capability':'x'*48,'operation':'retrieve','response':{}},headers={'Authorization':'Bearer '+'x'*48}).status_code,401)
            finally:
                server.should_exit=True;thread.join(5);sock.close()

if __name__=='__main__':unittest.main()
