import json
import io
import urllib.request
import unittest
from unittest.mock import patch, Mock
from types import SimpleNamespace
from gasstorm_ui import Control

class SupervisionTest(unittest.TestCase):
    def test_pool_rpc_failure_preserves_last_sample_and_recovers(self):
        initial = {"pending":"0x0", "queued":"0x0"}
        recovered = {"pending":"0x2", "queued":"0x1"}
        stack = SimpleNamespace(disabled=False, node_rpc=Mock(side_effect=[initial, AssertionError("RPC overloaded"), recovered]))
        control = Control(stack, SimpleNamespace(url="http://127.0.0.1:1"))
        try:
            output = io.StringIO()
            self.assertFalse(control.sample_pool(output))
            self.assertEqual(control.pool, initial)
            self.assertTrue(control.sample_pool(output))
            self.assertEqual(control.pool, recovered)
            self.assertEqual(json.loads(output.getvalue())["pending"], 2)
        finally:
            control.close()

    def test_block_driver_failure_keeps_control_alive(self):
        stack = SimpleNamespace(node_rpc=lambda *_: {"pending":"0x0","queued":"0x0"}, disabled=False)
        loadgen = SimpleNamespace(url="http://127.0.0.1:1")
        with patch.dict("os.environ", {"OPS_POC_GAS_LIMIT":"200000000"}):
            control = Control(stack, loadgen)
            try:
                control.fail("Block production failed: timed out")
                with urllib.request.urlopen(f"http://127.0.0.1:{control.port}/poc/status") as r:
                    self.assertIn("timed out", json.load(r)["error"])
            finally:
                control.close()

if __name__ == '__main__': unittest.main()
