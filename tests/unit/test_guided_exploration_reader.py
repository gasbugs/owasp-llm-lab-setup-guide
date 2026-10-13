import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
import httpx
from fastapi import HTTPException
PATH=Path(__file__).resolve().parents[2]/'llm-security-control-plane/guided-evidence-verifier/exploration_read.py'
spec=importlib.util.spec_from_file_location('exploration_read',PATH);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
ID='12345678-1234-4234-8234-123456789abc'
class ReaderTests(unittest.IsolatedAsyncioTestCase):
    async def test_all_native_paths_read_only_and_no_grading(self):
        for n in list(range(6,12))+list(range(13,23)):
            calls=[]
            def mock(request):
                calls.append(request)
                return httpx.Response(200,json={'suite_id':ID,'cases':[{'reply':'native'}]})
            factory=httpx.AsyncClient
            config={f'LAB{n:02d}_URL':'http://runtime',f'LAB{n:02d}_TOKEN':'read-token',f'H{n}_URL':'http://runtime',f'H{n}_HOST_URL':'http://runtime',f'H{n}_TOKEN':'read-token'}
            with patch.object(module.httpx,'AsyncClient',lambda **kwargs:factory(**kwargs,transport=httpx.MockTransport(mock))):
                result=await module.read_records(f'P{n:02d}',{'suite_id':ID},config)
            self.assertEqual(result['records'][0]['cases'][0]['reply'],'native')
            self.assertEqual(len(calls),1);self.assertEqual(calls[0].method,'GET')
            self.assertNotIn('/verify/',str(calls[0].url));self.assertNotIn('task_completed',result)
    async def test_invalid_ids_never_reach_runtime(self):
        with self.assertRaises(HTTPException):
            await module.read_records('P07',{'suite_id':'../../secret'},{'LAB07_URL':'http://runtime','LAB07_TOKEN':'t'})
