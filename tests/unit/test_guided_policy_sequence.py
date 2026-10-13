import asyncio,unittest
from unittest.mock import patch
import httpx
from test_guided_control_center import load_server
class PolicySequenceTests(unittest.TestCase):
    def test_first_risk_failure_never_runs_later_case_or_promotion(self):
        server=load_server();calls=[]
        class Client:
            async def __aenter__(self):return self
            async def __aexit__(self,*args):pass
            async def post(self,url,**kwargs):
                calls.append(url);body=kwargs['json']
                if url.endswith('/v1/run-case'):return httpx.Response(200,json={'suite_id':body['suite_id']})
                name=body['case_id'];failed=name=='risk-marker'
                return httpx.Response(200,json={'activity_id':'H16','execution_id':body['suite_id'],'started_at':body['started_at'],
                    'verified_by':'guided-evidence-verifier','course_verdict':'HIT' if failed else 'PASS',
                    'case_verified':not failed,'task_completed':False,'reason':'fixture','result':{'cases':[{'case_id':name,'decision':'allow'}]}})
        with patch.object(server.httpx,'AsyncClient',return_value=Client()):result=asyncio.run(server.run_policy_checks('http://worker','token'))
        self.assertEqual([x['status'] for x in result['result']['cases']],['PASS','PASS','HIT','미실행','미실행'])
        self.assertEqual(len(calls),6)
        self.assertFalse(any('promote' in x for x in calls))
