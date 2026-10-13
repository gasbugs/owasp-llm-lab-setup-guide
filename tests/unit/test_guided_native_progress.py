"""Actual case timing, selected-call isolation and no premature grading verdict."""
import asyncio,contextvars,functools,hmac,inspect,json,unittest
from pathlib import Path
from datetime import datetime,timezone
from fastapi import FastAPI,Header,HTTPException,Request
from fastapi.testclient import TestClient
ROOT=Path(__file__).resolve().parents[2]/"llm-security-control-plane/guided-labs"
class ProgressTests(unittest.TestCase):
 def setUp(self):
  source=(ROOT/"h06-nemo-action/server.py").read_text()
  source=source[source.index("# Runtime-owned progress:"):source.index("execute_case = _native_case")]
  self.ns={"datetime":datetime,"timezone":timezone,"hmac":hmac,"Header":Header,"HTTPException":HTTPException}
  exec(source,self.ns)
  self.app=FastAPI();self.calls=[]
  async def run_case(case_id):
   self.calls.append(case_id)
   if case_id=="bad":raise ValueError("broken")
   return {"case_id":case_id,"reply":"real reply"}
  self.observed=self.ns["_native_case"](run_case)
  @self.app.post("/v1/run")
  async def run(request:Request):
   if request.headers.get("authorization")!="Bearer control":raise HTTPException(401)
   body=await request.json()
   return {"cases":[await self.observed(case) for case in body["cases"]]}
  self.ns["_install_native_progress"](self.app,"control")
  self.client=TestClient(self.app)
 def test_preview_executes_only_selected_function_and_never_assigns_pass(self):
  result=self.client.post('/v1/run',json={'suite_id':'preview','cases':['normal','risk']},headers={'Authorization':'Bearer control','X-Preview-Case':'risk'}).json()
  self.assertEqual(self.calls,['risk'])
  self.assertTrue(result['cases'][0]['direct_skipped'])
  progress=self.client.get('/v1/progress/preview',headers={'Authorization':'Bearer control'}).json()
  self.assertEqual(progress['total'],1);self.assertEqual(progress['phase'],'finished')
  self.assertEqual(progress['cases'][0]['status'],'실행 완료');self.assertNotIn('case_verified',progress['cases'][0])
  self.assertEqual(self.client.get('/v1/progress/preview').status_code,401)
 def test_exception_stops_loop_without_fabricating_next_case(self):
  try:self.client.post('/v1/run',json={'suite_id':'grade','cases':['normal','bad','later']},headers={'Authorization':'Bearer control'})
  except ValueError:pass
  self.assertEqual(self.calls,['normal','bad'])
  progress=self.client.get('/v1/progress/grade',headers={'Authorization':'Bearer control'}).json()
  self.assertEqual([c['status'] for c in progress['cases']],['실행 완료','ERR'])
  self.assertIsNone(progress['current_case'])
  self.assertEqual(progress['phase'],'finished')
if __name__=='__main__':unittest.main()
