import importlib.util
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('scaffold_bindings',ROOT/'tools/check_guided_scaffold_digests.py')
checker=importlib.util.module_from_spec(spec);spec.loader.exec_module(checker)
class ScaffoldBindings(unittest.TestCase):
    def test_verifier_pins_current_supplied_source(self):
        self.assertEqual(checker.mismatches(),[])
