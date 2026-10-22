import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("approval_contract", Path(__file__).resolve().parents[1] / "approval_contract.py")
contract = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(contract)


class ContractPinTests(unittest.TestCase):
    def test_modified_pinned_input_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            path = root / "vector.json"
            path.write_bytes(b"original")
            manifest = {"files": {"source.json": contract.digest(b"original")}, "ops_files": {"source.json": "vector.json"}}
            contract.check_inputs(root, manifest)
            path.write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "differs"):
                contract.check_inputs(root, manifest)

    def test_manifest_cannot_redirect_writes_outside_checkout(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for name in ["../outside", "/etc/hosts"]:
                with self.subTest(name=name), self.assertRaises(ValueError):
                    contract.safe_path(root, name)
            (root / "symlink").symlink_to("/etc/hosts")
            with self.assertRaises(ValueError):
                contract.safe_path(root, "symlink")

    def test_unpinned_upstream_bytes_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "checksum"):
            contract.verify_bytes(b"changed", contract.digest(b"expected"), "manifest")


if __name__ == "__main__":
    unittest.main()
