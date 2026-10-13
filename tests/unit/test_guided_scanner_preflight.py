"""Read-only execution-limit checks precede native scanners and preserve their scores."""
import asyncio,unittest
from datetime import datetime,timezone
from unittest.mock import patch
import httpx
from test_guided_control_center import load_server

class ScannerTests(unittest.TestCase):
    def test_failed_preflight_never_runs_scanner_and_native_success_is_rechecked(self):
        server=load_server()
        for activity in ("H14","H15"):
            for failed,count,statuses in ((True,2,["ERR","미실행"]),(False,4,["PASS","PASS"])):
                calls=[]
                class Client:
                    async def __aenter__(self):return self
                    async def __aexit__(self,*args):pass
                    async def post(self,url,**kwargs):
                        calls.append(url);body=kwargs['json'];suite=body['suite_id']
                        if url.endswith(('/v1/prepare','/v1/run')):return httpx.Response(200,json={'suite_id':suite})
                        early=url.endswith('-preflight');err=early and failed
                        result={'config':{},'execution_limits':{},'source_digest':'a'*64,'config_digest':'a'*64,'cases':[] if err else [{'case_id':'actual-attempt','score':1}]}
                        return httpx.Response(200,json={'activity_id':activity,'execution_id':suite,'started_at':body['started_at'],
                            'verified_by':'guided-evidence-verifier','course_verdict':'ERR' if err else 'PASS',
                            'case_verified':not err,'task_completed':False,'result':result,'reason':'fixture'})
                with patch.object(server.httpx,'AsyncClient',return_value=Client()):
                    result=asyncio.run(server.run_scanner_checks(activity,'http://worker','control'))
                self.assertEqual(len(calls),count)
                self.assertEqual([case['status'] for case in result['result']['cases']],statuses)
                if not failed:self.assertEqual(result['result']['native_attempts'][0]['score'],1)
