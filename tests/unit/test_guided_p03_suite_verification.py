"""Whole-suite checks: actual child/TCP/SQLite, then explicit damaged replays."""
from copy import deepcopy
import importlib.util
import json
import socket
import sys
import threading
import time
import unittest
from unittest.mock import patch

import httpx
import uvicorn
from fastapi.testclient import TestClient

import test_guided_p03_run_server as runner_tests
import test_guided_p03_results as case_tests

spec = importlib.util.spec_from_file_location("p03_suite_verification_test",
    case_tests.PATH.with_name("p03_suite_verification.py"))
module = importlib.util.module_from_spec(spec)
with patch.dict(sys.modules, {"p03_results": case_tests.module}):
    spec.loader.exec_module(module)
api_spec = importlib.util.spec_from_file_location("p03_grading_api_test", case_tests.PATH.with_name("p03_grading_api.py"))
grading_api = importlib.util.module_from_spec(api_spec)
api_spec.loader.exec_module(grading_api)


class SuiteChecks(unittest.TestCase):
    control = runner_tests.RunnerTests.control
    verifier = runner_tests.RunnerTests.verifier
    setUp = runner_tests.RunnerTests.setUp
    client_for = runner_tests.RunnerTests.client_for
    live_workflow = runner_tests.RunnerTests.live_workflow
    run_suite = runner_tests.RunnerTests.run_suite

    def make_suite(self, starter=False):
        if not starter:
            (self.root / "learner.py").write_text(runner_tests.flow.worker.IMPLEMENTATION)
        app = self.client_for(self.live_workflow())
        root = self.run_suite(app).json()
        self.assertEqual(root["run_state"], "finished")
        return app, root

    def start_http(self, app):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        self.addCleanup(sock.close)
        origin = f"http://127.0.0.1:{sock.getsockname()[1]}"
        server = uvicorn.Server(uvicorn.Config(app, log_level="critical", lifespan="off"))
        thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
        thread.start()
        def stop():
            server.should_exit = True
            thread.join(5)
            self.assertFalse(thread.is_alive())
        self.addCleanup(stop)
        deadline = time.monotonic() + 5
        while not server.started:
            if not thread.is_alive() or time.monotonic() >= deadline:
                self.fail("runner TCP server did not start")
            time.sleep(.01)
        return origin

    def test_full_read_only_tcp_collection_and_build_change_detection(self):
        app, root = self.make_suite()
        app_origin = self.start_http(app.app)
        verifier = module.SuiteVerification(self.root, app_origin, self.origin,
                                            "runner-verifier", "workflow-verifier")
        result = verifier.collect(root["suite_id"])
        self.assertTrue(result["case_contract_verified"])
        self.assertEqual(result["provider_mode"], "contract")
        self.assertEqual(len(result["cases"]), 19)
        self.assertTrue(all(case["case_verified"] for case in result["cases"]))
        self.assertEqual(len(result["provider_evidence"]), 19)
        self.assertEqual(result["root"], root)
        self.assertNotIn("task_completed", result)
        self.assertNotIn("security_verdict", result)
        self.native_factory.assert_not_called()
        with TestClient(grading_api.create_app(verifier, control_token="grading-control")) as grading:
            body = {"suite_id": root["suite_id"]}
            headers = {"Authorization": "Bearer grading-control"}
            graded = grading.post("/v1/verify/p03", headers=headers, json=body)
            self.assertEqual(graded.status_code, 200)
            self.assertTrue(graded.json()["task_completed"])
            self.assertEqual(graded.json()["provider_mode"], "contract")
            self.assertEqual(graded.json()["security_verdict"], "PASS")
            (self.root / "learner.py").write_text("# changed after execution\n")
            with self.assertRaises(case_tests.module.EvidenceError):
                verifier.collect(root["suite_id"])
            changed = grading.post("/v1/verify/p03", headers=headers, json=body).json()
            self.assertFalse(changed["task_completed"])
            self.assertEqual(changed["security_verdict"], "ERR")
        self.assertEqual(app.get("/v1/receipts/" + root["suite_id"], headers=self.verifier).json(), root)

    def test_starter_and_wrong_role_are_not_accepted_by_full_collection(self):
        app, root = self.make_suite(starter=True)
        app_origin = self.start_http(app.app)
        for app_token, gateway_token in (("runner-verifier", "workflow-verifier"),
                                        ("runner-control", "workflow-verifier"),
                                        ("runner-verifier", "workflow-control")):
            verifier = module.SuiteVerification(self.root, app_origin, self.origin, app_token, gateway_token)
            with self.assertRaises(case_tests.module.EvidenceError):
                verifier.collect(root["suite_id"])
        verifier = module.SuiteVerification(self.root, app_origin, self.origin, "runner-verifier", "workflow-verifier")
        with TestClient(grading_api.create_app(verifier, control_token="grading-control")) as grading:
            outcome = grading.post("/v1/verify/p03", headers={"Authorization": "Bearer grading-control"},
                                   json={"suite_id": root["suite_id"]}).json()
            self.assertFalse(outcome["task_completed"])
            self.assertEqual(outcome["security_verdict"], "ERR")

    def test_damaged_replays_cannot_pass_even_when_locally_self_consistent(self):
        app, root = self.make_suite()
        suite = root["suite_id"]
        root_key, prep_key = "/v1/receipts/" + suite, "/v1/p03/suites/" + suite
        resources_key = prep_key + "/resources"
        first_key = "/v1/p03/executions/" + root["cases"][0]["execution_id"]
        second_key = "/v1/p03/executions/" + root["cases"][1]["execution_id"]
        snapshot = {root_key: root, "/v1/build-info": root["build"], prep_key: self.store.read(suite),
                    resources_key: self.store.inspect_resources(suite)}
        snapshot.update({"/v1/p03/executions/" + row["execution_id"]: self.ledger.read(row["execution_id"])
                         for row in root["cases"]})

        def replay(data):
            methods = []
            def respond(request):
                methods.append(request.method)
                value = data[request.url.path]
                return value if isinstance(value, httpx.Response) else httpx.Response(200, json=value)
            verifier = module.SuiteVerification(self.root, "http://runner", "http://gateway",
                "runner-verifier", "workflow-verifier", transport=httpx.MockTransport(respond))
            return verifier, methods

        verifier, methods = replay(snapshot)
        self.assertTrue(verifier.collect(suite)["case_contract_verified"])
        self.assertEqual(set(methods), {"GET"})

        def duplicate_observation(data):
            response = data[second_key]["calls"][0]["response"]
            response["observation_id"] = data[first_key]["calls"][0]["observation_id"]
            data[second_key]["calls"][0]["observation_id"] = response["observation_id"]
            data[root_key]["cases"][1]["execution"]["execution"]["calls"][0]["response_digest"] = module.json_digest(response)

        mutations = [
            lambda d: d[root_key].update(practice_id="H03"),
            lambda d: d[root_key].update(run_state="running"),
            lambda d: d[root_key]["cases"].pop(),
            lambda d: d[root_key]["cases"].reverse(),
            lambda d: d[root_key]["cases"][1].update(execution_id=d[root_key]["cases"][0]["execution_id"]),
            lambda d: d[root_key]["final_build"].update(source_digest="f" * 64),
            lambda d: d["/v1/build-info"].update(runner_digest="f" * 64),
            lambda d: d[root_key].update(finished_at=time.time() + 100),
            lambda d: d[prep_key].update(state="preparing"),
            lambda d: d[prep_key].update(contract_digest="f" * 64),
            lambda d: d[prep_key]["cases"][1].update(current_job_id=d[prep_key]["cases"][0]["current_job_id"]),
            lambda d: d[prep_key]["cases"].reverse(),
            lambda d: d[resources_key]["resources"].update(source_uris=["s3://other/current.md"]),
            lambda d: d[resources_key].update(observed_at=time.time() - 121),
            lambda d: d[resources_key].update(scope="claimed-aws-audit"),
            lambda d: d[first_key].update(closed=False),
            lambda d: d[first_key].update(current_job_id="other-job"),
            duplicate_observation,
            lambda d: d.update({first_key: httpx.Response(404)}),
            lambda d: d.update({first_key: httpx.Response(302, headers={"Location": "http://unused/"})}),
            lambda d: d.update({first_key: httpx.Response(200, content=b" " * 1048577)}),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                damaged = deepcopy(snapshot)
                mutate(damaged)
                verifier, methods = replay(damaged)
                with self.assertRaises(case_tests.module.EvidenceError):
                    verifier.collect(suite)
                self.assertEqual(set(methods), {"GET"})

        calls = {"build": 0}
        def late_change(request):
            value = deepcopy(snapshot[request.url.path])
            if request.url.path == "/v1/build-info":
                calls["build"] += 1
                if calls["build"] == 2:
                    value["source_digest"] = "f" * 64
            return httpx.Response(200, json=value)
        verifier = module.SuiteVerification(self.root, "http://runner", "http://gateway",
            "runner-verifier", "workflow-verifier", transport=httpx.MockTransport(late_change))
        with self.assertRaises(case_tests.module.EvidenceError):
            verifier.collect(suite)
        self.assertEqual(calls["build"], 2)


if __name__ == "__main__":
    unittest.main()
