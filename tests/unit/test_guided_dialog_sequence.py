import asyncio,json,unittest
from unittest.mock import patch
import httpx
from test_guided_control_center import load_server
class DialogSequenceTests(unittest.TestCase):
    def test_transport_error_is_err_and_later_cases_never_run(self):
        server=load_server();calls=[]
        class Request:
            async def body(self):return b''
        class Client:
            async def __aenter__(self):return self
            async def __aexit__(self,*args):pass
            async def post(self,url,**kwargs):
                calls.append(url)
                raise httpx.ConnectError('fixture')
        with patch.object(server.httpx,'AsyncClient',return_value=Client()):
            result=asyncio.run(server.verify_h05_dialog_rail(Request(),('sequence-fixture',{})))
        self.assertEqual(len(calls),1)
        self.assertEqual(result['course_verdict'],'ERR')
        self.assertFalse(result['task_completed'])
        self.assertEqual([x['status'] for x in result['result']['cases']],['ERR','미실행','미실행','미실행'])
        json.dumps(result)
