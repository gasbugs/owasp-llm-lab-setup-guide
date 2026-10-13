"""Sequential RAG execution never runs future queries or accepts changed suite identity."""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient
ROOT=Path(__file__).resolve().parents[2]/"llm-security-control-plane/guided-labs/h11-rag-provenance"
class SequentialRagTests(unittest.TestCase):
    def setUp(self):
        self.folder=tempfile.TemporaryDirectory();self.addCleanup(self.folder.cleanup)
        env={"GUIDED_CONTROL_LAB11_TOKEN":"control","GUIDED_VERIFIER_LAB11_TOKEN":"reader","GUIDED_H11_GATEWAY_URL":"http://gateway","GUIDED_H11_GATEWAY_TOKEN":"embedding","GUIDED_H11_DATABASE":self.folder.name+"/receipts.sqlite3"}
        spec=importlib.util.spec_from_file_location("sequential_rag",ROOT/"server.py");module=importlib.util.module_from_spec(spec)
        policy_spec=importlib.util.spec_from_file_location("policy",ROOT/"policy.py");policy=importlib.util.module_from_spec(policy_spec);policy_spec.loader.exec_module(policy)
        with patch.dict(os.environ,env),patch.dict(sys.modules,{"policy":policy,"sequential_rag":module}):spec.loader.exec_module(module)
        self.module=module;self.client=TestClient(module.app);self.calls=[]
        async def embed(client,request,item_id,text):
            self.calls.append(item_id)
            return {"vector":[1.0,0.0],"provider_request_id":"provider-"+item_id}
        self.patcher=patch.object(module,"embed",embed);self.patcher.start();self.addCleanup(self.patcher.stop)
        self.body={"suite_id":"11000000-0000-0000-0000-000000000001","execution_id":"11000000-0000-0000-0000-000000000002","started_at":"2026-10-11T00:00:00+00:00"}
    def send(self,case,**changes):
        return self.client.post("/v1/run-case",json={**self.body,"case_id":case,**changes},headers={"Authorization":"Bearer control"})
    def test_one_case_at_a_time_reuses_vectors_and_rejects_skip_or_replay(self):
        self.assertEqual(self.send("client-self-approval").status_code,409)
        self.assertEqual(self.calls,[])
        self.assertEqual(self.send("normal-approved").status_code,200)
        self.assertEqual(self.calls,["doc-public","doc-draft","doc-foreign","query-normal-approved"])
        self.assertEqual(self.send("normal-approved").status_code,409)
        self.assertEqual(self.send("client-self-approval",execution_id="11000000-0000-0000-0000-000000000009").status_code,409)
        self.assertEqual(self.send("client-self-approval").status_code,200)
        self.assertEqual(self.calls[-1],"query-client-self-approval");self.assertEqual(len(self.calls),5)
        receipt=self.client.get("/v1/receipts/"+self.body["suite_id"],headers={"Authorization":"Bearer reader"}).json()
        self.assertEqual([row["case_id"] for row in receipt["cases"]],["normal-approved","client-self-approval"])
        self.assertNotIn("document_vectors",receipt)
    def test_case_execution_requires_control_credential_and_server_owned_body(self):
        self.assertEqual(self.client.post("/v1/run-case",json={**self.body,"case_id":"normal-approved"}).status_code,401)
        self.assertEqual(self.send("normal-approved",principal={"tenant":"beta"}).status_code,422)
        self.assertEqual(self.calls,[])
