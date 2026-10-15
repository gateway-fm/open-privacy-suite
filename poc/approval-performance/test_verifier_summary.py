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

    def summarize_snapshots(self, before, after, gate=True):
        module = self.module()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            files = {
                "transactions-report.json": {"status": {"status": "completed"},
                                             "receipts": {}, "loadgen_sha256": "test"},
                "receipts.json": [], "transactions.json": [], "verifier-config.json": {"gate": gate},
            }
            for name, value in files.items():
                (path / name).write_text(json.dumps(value))
            (path / "metrics-before.txt").write_text(before)
            (path / "metrics-after.txt").write_text(after)
            return module.summarize_case(path)

    def histogram(self, multiplier=1):
        rows = []
        for target, count, total, lower in (("a", 8, .008, 8), ("b", 2, .020, 0)):
            prefix = "privacyproxy_approval_delivery_seconds_"
            rows.extend((f'{prefix}count{{target="{target}"}} {count * multiplier}',
                         f'{prefix}sum{{target="{target}"}} {total * multiplier}'))
            for bound, value in (("0.001", lower), ("0.01", count), ("+Inf", count)):
                rows.append(f'{prefix}bucket{{target="{target}",le="{bound}"}} {value * multiplier}')
        return "\n".join(rows) + "\n"

    def test_complete_snapshots_preserve_weighted_latency(self):
        result = self.summarize_snapshots(self.histogram(), self.histogram(2))
        self.assertAlmostEqual(result["approval_delivery"]["mean_ms"], 2.8)
        self.assertEqual(result["approval_delivery"]["histogram_count"], 10)

    def test_incomplete_histogram_snapshots_are_rejected(self):
        for phase in ("before", "after", "both"):
            for missing in ('sum{target="b"}', '_count', 'le="+Inf"',
                            'target="b",le="0.001"', 'target="b"'):
                with self.subTest(phase=phase, missing=missing):
                    before, after = self.histogram(), self.histogram(2)
                    if phase in ("before", "both"):
                        before = "\n".join(row for row in before.splitlines() if missing not in row)
                    if phase in ("after", "both"):
                        after = "\n".join(row for row in after.splitlines() if missing not in row)
                    # A target absent in both snapshots cannot be distinguished
                    # from a run that was configured with only the other target.
                    if missing == 'target="b"' and phase == "both":
                        continue
                    with self.assertRaisesRegex(ValueError, "delivery histogram"):
                        self.summarize_snapshots(before, after)

    def test_missing_zero_valued_baseline_series_is_rejected(self):
        before = "\n".join(row for row in self.histogram(0).splitlines()
                           if 'sum{target="b"}' not in row)
        with self.assertRaisesRegex(ValueError, "delivery histogram"):
            self.summarize_snapshots(before, self.histogram())

    def test_absent_histogram_is_allowed_only_in_both_snapshots(self):
        self.assertIsNone(self.summarize_snapshots("", "", gate=False)["approval_delivery"])
        with self.assertRaisesRegex(ValueError, "missing delivery histogram"):
            self.summarize_snapshots("", "")
        for before, after in (("", self.histogram()), (self.histogram(0), "")):
            with self.subTest(before=bool(before)), self.assertRaisesRegex(ValueError, "delivery histogram"):
                self.summarize_snapshots(before, after)

    def test_zero_observation_histogram_is_validated(self):
        zeros = self.histogram(0)
        self.assertIsNone(self.summarize_snapshots(zeros, zeros)["approval_delivery"])
        incomplete = "\n".join(row for row in zeros.splitlines() if "_sum" not in row)
        with self.assertRaisesRegex(ValueError, "delivery histogram"):
            self.summarize_snapshots(incomplete, incomplete)

    def test_invalid_targets_cannot_be_hidden_by_aggregation(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "metrics.txt"
            path.write_text(self.histogram())
            complete = module.metrics(path)
        prefix = module.PREFIX
        a_count = (prefix + "count", (("target", "a"),))
        b_count = (prefix + "count", (("target", "b"),))
        a_lower = (prefix + "bucket", (("le", "0.001"), ("target", "a")))
        b_lower = (prefix + "bucket", (("le", "0.001"), ("target", "b")))
        # Each alteration preserves valid aggregate counts/buckets but corrupts
        # individual targets. The same validation also applies to deltas.
        for changes in ({a_count: 7, b_count: 3}, {a_lower: 7, b_lower: 3},
                        {a_lower: 9, b_lower: -1}):
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, "delivery histogram"):
                module.delivery_latency(complete | changes)

    def test_invalid_bucket_bound_and_zero_count_sum_are_rejected(self):
        for invalid in (self.histogram().replace('le="0.001"', 'le="NaN"'),
                        self.histogram().replace('le="0.001"', 'le="-1"'),
                        self.histogram().replace(',le="0.001"', ''),
                        self.histogram(0).replace('sum{target="b"} 0.0', 'sum{target="b"} 1')):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(ValueError, "delivery histogram"):
                self.summarize_snapshots(invalid, invalid)

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
