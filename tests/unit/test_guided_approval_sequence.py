import asyncio,unittest
from unittest.mock import patch
import httpx
from test_guided_control_center import load_server
class ApprovalSequenceTests(unittest.TestCase):
    def test_normal_native_summary_is_displayed_before_first_unauthorized_effect(self):
        server=load_server();calls=[];names=['normal','no-approval']
        class Client:
            async def __aenter__(self):return self
            async def __aexit__(self,*args):pass
            async def post(self,url,**kwargs):
                calls.append(url);body=kwargs['json'];name=body['case_id'];failed=name=='no-approval'
                if url.endswith('/v1/run-case'):return httpx.Response(200,json={'suite_id':body['suite_id']})
                key='no_approval' if failed else 'normal'
                return httpx.Response(200,json={'activity_id':'H22','execution_id':body['suite_id'],'started_at':body['started_at'],
                    'verified_by':'guided-evidence-verifier','course_verdict':'HIT' if failed else 'PASS',
                    'case_verified':not failed,'task_completed':False,'reason':'fixture',
                    'result':{'case_order':names if failed else names[:1],key:{'is_error':False},'effect_counts':[1] if failed else [],'verified_effects':{'effects':int(failed)}}})
        with patch.object(server.httpx,'AsyncClient',return_value=Client()):result=asyncio.run(server.run_approval_checks('http://worker','token'))
        self.assertEqual(len(calls),4)
        self.assertEqual([x['status'] for x in result['result']['cases']],['PASS','HIT']+['미실행']*5)
        self.assertEqual(result['result']['cases'][1]['verified_effects']['effects'],1)
