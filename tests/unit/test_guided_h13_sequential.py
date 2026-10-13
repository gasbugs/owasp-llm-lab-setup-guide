"""Native artifact fixtures test independent grading and first-failure orchestration."""
from copy import deepcopy
from datetime import datetime,timezone
import hashlib,json,sys,unittest
from pathlib import Path
from unittest.mock import patch
import httpx
from fastapi.testclient import TestClient
from test_guided_control_center import load_server
ROOT=Path(__file__).resolve().parents[2]/"llm-security-control-plane/guided-evidence-verifier"
sys.path.insert(0,str(ROOT))
from h13_sequential import NAMES,verify_prefix

class PrefixTests(unittest.TestCase):
    def setUp(self):
        self.started=datetime.now(timezone.utc).isoformat();self.suite="00000000-0000-0000-0000-000000000013"
        self.entries=[]
        for i,name in enumerate(NAMES):
            output={"decision":"allow" if i==0 else "block","upstream_called":i==0,"policy_rule":"application-self-check"}
            row={"testCase":{"description":name},"success":True,"gradingResult":{"pass":True},"response":{"output":json.dumps(output)}}
            raw=json.dumps({"metadata":{"promptfooVersion":"0.121.20"},"results":{"results":[row]}})
            self.entries.append({"case_id":name,"child":f"{self.suite}-{i}","exit_code":0,
                "observed_at":datetime.now(timezone.utc).isoformat(),"artifact_raw":raw,"artifact_digest":hashlib.sha256(raw.encode()).hexdigest()})
        self.data={"suite_id":self.suite,"started_at":self.started,"state":"finished","entries":self.entries,
            "config_digest":"a"*64,"current_config_digest":"a"*64,"scaffold_digest":"b"*64,"current_scaffold_digest":"b"*64}
    def verify(self,case=None):
        return verify_prefix(self.data,suite_id=self.suite,started_at=self.started,scaffold_digest="b"*64,through_case=case)
    def test_prefix_and_full_completion_are_distinct(self):
        self.assertTrue(self.verify()["task_completed"])
        self.data["entries"]=self.entries[:1];self.data["state"]="paused"
        r=self.verify(NAMES[0]);self.assertTrue(r["case_verified"]);self.assertFalse(r["task_completed"])
        self.assertEqual(self.verify()["course_verdict"],"ERR")
    def test_future_stale_changed_and_forged_artifacts_fail(self):
        original=deepcopy(self.data)
        mutations=[lambda d:d.update(suite_id="stale"),lambda d:d.update(current_config_digest="c"*64),
            lambda d:d["entries"][0].update(artifact_raw="{}"),lambda d:d["entries"][0].update(exit_code=1),
            lambda d:d["entries"].reverse(),lambda d:d["entries"].append(deepcopy(d["entries"][0]))]
        for change in mutations:
            self.data=deepcopy(original);change(self.data);self.assertEqual(self.verify()["course_verdict"],"ERR")
        self.data=original;self.assertEqual(self.verify(NAMES[0])["course_verdict"],"ERR")
    def test_native_assertion_pass_cannot_override_wrong_application_effect(self):
        native=json.loads(self.entries[1]["artifact_raw"]);native["results"]["results"][0]["response"]["output"]=json.dumps({"decision":"allow","upstream_called":True})
        raw=json.dumps(native);self.entries[1].update(artifact_raw=raw,artifact_digest=hashlib.sha256(raw.encode()).hexdigest())
        self.assertEqual(self.verify()["course_verdict"],"ERR")

class ControlTests(unittest.TestCase):
    def test_first_error_never_executes_risk_and_success_rechecks_whole(self):
        server=load_server()
        for failed,expected_count,statuses in ((True,2,["ERR","미실행"]),(False,5,["PASS","PASS"])):
            client=TestClient(server.app);client.get("/");boot=client.get("/api/bootstrap").json();calls=[]
            async def post(_client,url,**kwargs):
                calls.append(url);body=kwargs["json"];name=body.get("case_id");suite=body["suite_id"]
                if url.endswith("/v1/run-case"):return httpx.Response(200,json={"suite_id":suite,"case_id":name})
                err=failed and name==NAMES[0]
                return httpx.Response(200,json={"activity_id":"H13","execution_id":suite,"started_at":body["started_at"],
                    "case_id":name,"course_verdict":"ERR" if err else "PASS","verified_by":"guided-evidence-verifier",
                    "case_verified":bool(name) and not err,"task_completed":name is None and not err,"reason":"fixture",
                    "result":{"cases":[] if err else [{"case_id":n,"status":"PASS","case_verified":True} for n in (NAMES if name is None else NAMES[:NAMES.index(name)+1])]}})
            with patch.object(server,"native_post",side_effect=post):
                response=client.post("/api/hands-on/H13/verify",headers={"Origin":"http://testserver","X-CSRF-Token":boot["csrf_token"]}).json()
            self.assertEqual(len(calls),expected_count)
            self.assertEqual([r["status"] for r in response["result"]["cases"]],statuses)
            self.assertFalse(server.ACTIVE_SESSIONS)

    def test_verifying_progress_retains_current_case_and_elapsed_origin(self):
        import asyncio
        server=load_server()
        state={"native_progress":{"cases":[],"phase":"running","current_case":{"case_id":"normal","status":"실행 중","started_at":"original"}}}
        async def run():
            token=server.NATIVE_SESSION.set(state)
            try:
                class Client:
                    async def post(self,url,**kwargs):
                        current=state["native_progress"]["current_case"]
                        self_test.assertEqual(current,{"case_id":"normal","status":"독립 검증 중","started_at":"original"})
                        return httpx.Response(200,json={})
                await server.native_post(Client(),"http://verifier/v1/verify/h13-case",json={"case_id":"normal"})
            finally:server.NATIVE_SESSION.reset(token)
        self_test=self
        asyncio.run(run())
