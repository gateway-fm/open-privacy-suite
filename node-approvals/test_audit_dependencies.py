"""Security reviews must not survive a change to the host whose APIs were assessed."""
import contextlib
import datetime
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import audit_dependencies


class HostReviewTests(unittest.TestCase):
    def run_audit(self, node, *, host_version="26.8.1", archive="reviewed-archive"):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            native = root / "node-approvals"
            (native / "besu/build").mkdir(parents=True)
            (native / "reth").mkdir()
            expected = {"version": "26.8.1", "archive_sha256": "reviewed-archive"}
            (native / "compatibility.json").write_text(json.dumps({
                "besu": {"version": host_version, "archive_sha256": archive},
            }))
            package = "jackson-core" if node == "besu" else "alloy-provider"
            ecosystem = "Maven" if node == "besu" else "crates.io"
            version = "2.21.5" if node == "besu" else "2.3.0"
            (native / "besu/build/dependency-inventory.json").write_text(json.dumps([
                {"name": package, "version": version},
            ]))
            (native / "reth/Cargo.lock").write_text(
                '[[package]]\nname = "alloy-provider"\nversion = "2.3.0"\n'
                'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
            )
            (native / "advisory-review.json").write_text(json.dumps({
                "recheck_by": str(datetime.date.today() + datetime.timedelta(days=1)),
                "required_versions": {"alloy-provider": "2.3.0"},
                "required_compatibility": {"besu": expected},
                "exceptions": [{"ecosystem": ecosystem, "name": package,
                                "version": version, "id": "TEST-ADVISORY",
                                "reason": "Reviewed API is not reachable."}],
            }))
            report = root / "report.json"
            response = {"results": [{"vulns": [{"id": "TEST-ADVISORY"}]}]}
            with patch.object(audit_dependencies, "ROOT", root), \
                    patch.object(audit_dependencies, "query", return_value=response), \
                    patch("sys.argv", ["audit_dependencies.py", node, "--output", str(report)]), \
                    contextlib.redirect_stdout(io.StringIO()), \
                    self.assertRaises(SystemExit) as result:
                audit_dependencies.main()
            return result.exception.code, json.loads(report.read_text())

    def test_review_applies_to_the_pinned_host(self):
        code, report = self.run_audit("besu")
        self.assertEqual(code, 0)
        self.assertTrue(report["review_current"])
        self.assertIsNotNone(report["findings"][0]["advisories"][0]["review"])

    def test_same_library_on_another_host_requires_a_new_review(self):
        code, report = self.run_audit("besu", host_version="26.9.0")
        self.assertEqual(code, 1)
        self.assertFalse(report["review_current"])
        self.assertIsNone(report["findings"][0]["advisories"][0]["review"])

    def test_replaced_host_archive_requires_a_new_review(self):
        code, report = self.run_audit("besu", archive="another-archive")
        self.assertEqual(code, 1)
        self.assertFalse(report["review_current"])
        self.assertIsNone(report["findings"][0]["advisories"][0]["review"])

    def test_besu_pin_does_not_invalidate_an_unchanged_reth_review(self):
        code, report = self.run_audit("reth", host_version="26.9.0")
        self.assertEqual(code, 0)
        self.assertTrue(report["review_current"])


if __name__ == "__main__":
    unittest.main()
