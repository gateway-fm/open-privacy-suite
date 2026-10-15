"""Offline checks for archived benchmark evidence; no node or Docker required."""
import gzip
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


class VerifierEvidenceTests(unittest.TestCase):
    def test_gasstorm_manifest_is_portable_json(self):
        path = HERE.parent / "reth-signed-approvals/evidence/gasstorm/final/manifest.json"
        value = json.loads(path.read_text())
        self.assertEqual(value["repositories"]["loadgenerator"]["path"],
                         "~/work/software/loadgenerator")

    def module(self):
        spec = importlib.util.spec_from_file_location("verifier_summary", HERE / "summarize_verifier.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_histogram_combines_targets_before_percentiles(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "metrics.txt"
            path.write_text('''privacyproxy_approval_delivery_seconds_count{target="a"} 8
privacyproxy_approval_delivery_seconds_count{target="b"} 2
privacyproxy_approval_delivery_seconds_sum{target="a"} 0.008
privacyproxy_approval_delivery_seconds_sum{target="b"} 0.020
privacyproxy_approval_delivery_seconds_bucket{target="a",le="0.001"} 8
privacyproxy_approval_delivery_seconds_bucket{target="b",le="0.001"} 0
privacyproxy_approval_delivery_seconds_bucket{target="a",le="0.01"} 8
privacyproxy_approval_delivery_seconds_bucket{target="b",le="0.01"} 2
privacyproxy_approval_delivery_seconds_bucket{target="a",le="+Inf"} 8
privacyproxy_approval_delivery_seconds_bucket{target="b",le="+Inf"} 2
''')
            result = module.delivery_latency(module.metrics(path))
            self.assertAlmostEqual(result["mean_ms"], 2.8)
            self.assertEqual(result["percentile_upper_bounds_ms"], {"p50": 1.0, "p95": 10.0, "p99": 10.0})

    def test_counter_reset_is_rejected(self):
        module = self.module()
        key = ("privacyproxy_approval_delivery_seconds_count", ())
        with self.assertRaisesRegex(ValueError, "reset"):
            module.counter_delta({key: 10}, {key: 2})

    def test_other_target_growth_cannot_hide_counter_reset(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as directory:
            before, after = [Path(directory) / name for name in ("before.txt", "after.txt")]
            name = "privacyproxy_approval_delivery_seconds_count"
            before.write_text(f'{name}{{target="a"}} 10\n{name}{{target="b"}} 0\n')
            after.write_text(f'{name}{{target="a"}} 2\n{name}{{target="b"}} 20\n')
            with self.assertRaisesRegex(ValueError, "reset"):
                module.counter_delta(module.metrics(before), module.metrics(after))

    def test_incomplete_run_cannot_produce_summary(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "transactions-report.json").write_text(json.dumps({"error": "node stopped"}))
            with self.assertRaisesRegex(ValueError, "did not complete"):
                module.summarize_case(path)

    def test_reads_compressed_evidence_and_rejects_overwrite(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            with gzip.open(str(path) + ".gz", "wt") as stream:
                json.dump({"receipts": {"successful": 7}}, stream)
            self.assertEqual(module.read_json(path)["receipts"]["successful"], 7)
            output = Path(directory) / "summary.json"
            module.write_summary(output, {"value": 1})
            with self.assertRaises(FileExistsError):
                module.write_summary(output, {"value": 2})
            self.assertEqual(json.loads(output.read_text()), {"value": 1})


if __name__ == "__main__":
    unittest.main()
