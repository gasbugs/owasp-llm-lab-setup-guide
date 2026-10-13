import asyncio,json,unittest
from unittest.mock import patch
import httpx
from test_guided_control_center import load_server
class AlertSequenceTests(unittest.TestCase):
    def test_configuration_failure_never_generates_business_requests(self):
        server=load_server();calls=[]
        class Client:
            async def __aenter__(self):return self
            async def __aexit__(self,*args):pass
            async def post(self,url,**kwargs):
                calls.append(url);body=kwargs['json']
                return httpx.Response(200,json={'activity_id':'P20','execution_id':body['suite_id'],'started_at':body['started_at'],
                    'verified_by':'guided-evidence-verifier','course_verdict':'ERR','case_verified':False,'task_completed':False,'reason':'fixture','result':{}})
        with patch.object(server.httpx,'AsyncClient',return_value=Client()):result=asyncio.run(server.run_alert_checks('http://worker','token'))
        self.assertEqual(len(calls),1)
        self.assertEqual([x['status'] for x in result['result']['cases']],['ERR','미실행'])

        json.dumps(result)
