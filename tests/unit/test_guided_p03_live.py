"""P03 live publisher cleanup routing; no containers or AWS calls."""
import json
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
with patch.object(sys, "path", [str(ROOT / "tests/e2e"), *sys.path]):
    import check_guided_p03_live as module


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "preparation.json"
        self.proof = {"aws_preflight": {"resources_absent": True}}
        logs = patch.object(module.subprocess, "check_output", return_value="")
        self.addCleanup(logs.stop)
        self.logs = logs.start()

    def test_missing_preparation_never_deletes(self):
        with patch.object(module, "aws_call") as call:
            module.cleanup_aws("project", "000000000000", self.proof, self.path)
        call.assert_not_called()
        self.assertFalse(self.proof["aws_cleanup"]["performed"])

    def test_failed_preparation_preserves_journal_without_deleting(self):
        self.path.write_text(json.dumps({"detail": {"operation_id": "test-operation"}}))
        with patch.object(module, "aws_call") as call, patch.object(module, "rpc",
                return_value=[200, {"state": "error"}]) as rpc:
            module.cleanup_aws("project", "000000000000", self.proof, self.path)
        call.assert_not_called()
        self.assertIn("/preparations/test-operation", rpc.call_args.args[2])
        self.assertEqual(self.proof["aws_preparation_journal"]["journal"]["state"], "error")

    def test_success_uses_strict_existing_cleanup_guard(self):
        prepared = {"state": "ready", "operation_id": "test-operation"}
        self.path.write_text(json.dumps({"preparation": prepared}))
        with patch.object(module, "aws_call", return_value={"resources_absent": True}) as call:
            module.cleanup_aws("project", "000000000000", self.proof, self.path)
        call.assert_called_once_with("project", "cleanup", {"account_id": "000000000000",
            "before": self.proof["aws_preflight"], "prepared": prepared})
        self.assertTrue(self.proof["aws_cleanup"]["resources_absent"])

    def test_cleanup_guard_failure_not_reported_as_absence(self):
        self.path.write_text(json.dumps({"preparation": {"state": "ready"}}))
        with patch.object(module, "aws_call", side_effect=ValueError("guard refused")):
            with self.assertRaises(ValueError):
                module.cleanup_aws("project", "000000000000", self.proof, self.path)
        self.assertNotIn("aws_cleanup", self.proof)

    def test_only_bounded_exception_diagnostic_is_saved(self):
        self.logs.return_value = ("arbitrary private log\n"
            "P03 source preparation failed: operation=list_objects_v2 type=ReadTimeoutError\n"
            "P03 source preparation failed: operation=bad type=Error private-detail\n")
        module.cleanup_aws("project", "000000000000", self.proof, self.path)
        self.assertEqual(self.proof["gateway_preparation_diagnostics"], [
            "P03 source preparation failed: operation=list_objects_v2 type=ReadTimeoutError"])


class MarkdownBuildInputTests(unittest.TestCase):
    def test_markdown_bytes_reach_temporary_build_without_changing_starter(self):
        source = '# 현재 작업을 확인한다.\nasync def search_current(current_job_id, services):\n    pass\n'
        starter = (module.LAB / 'learner.py').read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            document = Path(directory) / 'p03.md'
            output = Path(directory) / 'proof.json'
            document.write_text("## 1. 풀이\n```bash\n"
                "cat > llm-security-control-plane/guided-labs/h03-ingestion-search/learner.py <<'EOF'\n"
                + source + 'EOF\nfalse\n```\n', encoding='utf-8')

            def inspect_build(role, recipe, context, project):
                self.assertEqual(role, 'learner')
                self.assertEqual((recipe.parent / 'learner.py').read_bytes(), source.encode('utf-8'))
                self.assertNotEqual(recipe.parent, module.LAB)
                raise RuntimeError('stop before Docker build')

            with patch.object(sys, 'argv', ['check', '--markdown', str(document), '--output', str(output)]), \
                    patch.object(module, 'build', side_effect=inspect_build) as build, \
                    patch.object(module.subprocess, 'check_output', return_value='') as read, \
                    patch.object(module.subprocess, 'run') as run:
                with self.assertRaisesRegex(RuntimeError, 'stop before Docker build'):
                    module.main()
            build.assert_called_once()
            run.assert_not_called()
            self.assertEqual(read.call_count, 3)
            proof = json.loads(output.read_text())
            self.assertEqual(proof['source_digest'], hashlib.sha256(source.encode('utf-8')).hexdigest())
            self.assertEqual(proof['provider_mode'], 'contract')
            self.assertNotIn('checked', proof)
        self.assertEqual((module.LAB / 'learner.py').read_bytes(), starter)


if __name__ == "__main__":
    unittest.main()
