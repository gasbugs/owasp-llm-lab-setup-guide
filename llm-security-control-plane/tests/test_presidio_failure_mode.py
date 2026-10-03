"""Run the actual privacy-call function with simulated dependency failures."""
import ast
from pathlib import Path
import unittest
from unittest.mock import patch
import httpx

SOURCE = Path(__file__).parents[1] / "nemo-policy-hub/server.py"
if not SOURCE.exists():
    SOURCE = Path("/app/server.py")
function = next(n for n in ast.parse(SOURCE.read_text()).body
                if isinstance(n, ast.AsyncFunctionDef) and n.name == "analyze_privacy")
namespace = {"httpx": httpx, "CONTROL_PLANE_POLICY": {"execution": {"spoke_read_retry_count": 0}},
             "PRESIDIO_URL": "http://presidio", "PRESIDIO_INTERNAL_TOKEN": "test-token"}
exec(compile(ast.Module(body=[function], type_ignores=[]), str(SOURCE), "exec"), namespace)

class FailureModeTests(unittest.IsolatedAsyncioTestCase):
    async def run_case(self, mode, stage, error, opens):
        namespace["PRESIDIO_FAILURE_MODE"] = mode
        with patch.object(httpx.AsyncClient, "post", side_effect=error):
            if opens:
                result = await namespace["analyze_privacy"](stage, "original", "request-1")
                self.assertTrue(result["inspection_skipped"])
                self.assertEqual(result["sanitized_candidate"], "original")
            else:
                with self.assertRaises(RuntimeError):
                    await namespace["analyze_privacy"](stage, "original", "request-1")

    async def test_transport_and_timeout_switch(self):
        for mode in ("closed", "open"):
            for stage in ("input", "output", "retrieval"):
                for error in (httpx.ConnectError("down"), httpx.ReadTimeout("timeout")):
                    await self.run_case(mode, stage, error, mode == "open" and stage != "retrieval")

    async def test_http_errors_do_not_bypass_authentication(self):
        for status in (401, 403, 422, 500, 503):
            request = httpx.Request("POST", "http://presidio")
            response = httpx.Response(status, request=request)
            error = httpx.HTTPStatusError("error", request=request, response=response)
            await self.run_case("open", "input", error, status >= 500)

    async def test_malformed_response_stays_closed(self):
        await self.run_case("open", "input", ValueError("invalid contract"), False)

if __name__ == "__main__":
    unittest.main()
