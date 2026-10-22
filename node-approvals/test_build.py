"""Exercise bundle provenance and links with native compilation stubbed."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import build


LFDT = "LFDT-Permissioned-Privacy-Control/permissioned-privacy-control"
GATEWAY = "gateway-fm/open-privacy-suite"


class BundleSourceTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        self.here = self.root / "node-approvals"
        self.here.mkdir()
        for name in ("VERSION", "compatibility.json", "README.md", "OPERATIONS.md",
                     "alerts.yml", "advisory-review.json"):
            shutil.copy2(build.HERE / name, self.here / name)
        shutil.copy2(build.ROOT / "LICENSE", self.root / "LICENSE")
        artifact = self.here / (
            f"besu/build/libs/ops-besu-approvals-{build.VERSION}"
            f"-besu-{build.COMPAT['besu']['version']}.jar"
        )
        artifact.parent.mkdir(parents=True)
        artifact.write_bytes(b"stub native artifact")
        (self.here / "besu/build/dependency-inventory.json").write_text("[]\n")
        self.git("init", "-q")
        self.git("commit", "-qm", "Independent import root", "--allow-empty")
        self.commit = self.git("rev-parse", "HEAD")
        self.git("remote", "add", "origin", f"https://github.com/{GATEWAY}.git")

    def git(self, *args):
        return subprocess.check_output([
            "git", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
            "-c", "user.name=Bundle Test", "-c", "user.email=bundle@example.invalid",
            *args,
        ], cwd=self.root, text=True).strip()

    def assemble(self, *, ci_repository=None, explicit=None):
        destination = Path(tempfile.mkdtemp(dir=self.root))
        argv = ["build.py", "besu", "--output", str(destination)]
        if explicit is not None:
            argv += ["--repository", explicit]
        environment = dict(os.environ)
        environment.pop("GITHUB_REPOSITORY", None)
        if ci_repository is not None:
            environment["GITHUB_REPOSITORY"] = ci_repository
        real_output = build.output

        def tool_output(*args):
            if args[0] == "java":
                return "stub JDK"
            return real_output(*args)

        with patch.object(build, "ROOT", self.root), \
                patch.object(build, "HERE", self.here), \
                patch.object(build, "run") as native_build, \
                patch.object(build, "output", side_effect=tool_output), \
                patch.dict(os.environ, environment, clear=True), \
                patch("sys.argv", argv), contextlib.redirect_stdout(io.StringIO()):
            try:
                build.main()
            except SystemExit:
                native_build.assert_not_called()
                raise
            native_build.assert_called_once()
        return next(destination.iterdir())

    def assert_bundle_source(self, bundle, repository):
        url = f"https://github.com/{repository}"
        source = f"{url}/blob/{self.commit}"
        readme = (bundle / "README.md").read_text()
        operations = (bundle / "OPERATIONS.md").read_text()
        self.assertIn(f"]({source}/docs/implementation/approvals-wire-contract.md)", readme)
        self.assertIn(f"]({source}/docs/implementation/approvals-wire-contract.md#7-settings)",
                      operations)
        self.assertNotIn("](../", readme + operations)
        self.assertIn("](OPERATIONS.md)", readme)
        if repository == LFDT:
            self.assertNotIn(f"https://github.com/{GATEWAY}/blob/", readme + operations)
        manifest = json.loads((bundle / "build.json").read_text())
        self.assertEqual(manifest["source_repository"], url)
        self.assertEqual(manifest["source_commit"], self.commit)
        for entry in (bundle / "SHA256SUMS").read_text().splitlines():
            digest, name = entry.split("  ", 1)
            self.assertEqual(hashlib.sha256((bundle / name).read_bytes()).hexdigest(), digest)

    def test_lfdt_ci_uses_import_commit_and_ignores_gateway_origin(self):
        self.assert_bundle_source(self.assemble(ci_repository=LFDT), LFDT)

    def test_gateway_ci_remains_valid(self):
        self.git("remote", "set-url", "origin", f"https://github.com/{LFDT}.git")
        self.assert_bundle_source(self.assemble(ci_repository=GATEWAY), GATEWAY)

    def test_local_lfdt_checkout_supports_https_and_ssh(self):
        for remote in (f"https://github.com/{LFDT}.git",
                       f"git@github.com:{LFDT}.git",
                       f"ssh://git@github.com/{LFDT}.git"):
            with self.subTest(remote=remote):
                self.git("remote", "set-url", "origin", remote)
                self.assert_bundle_source(self.assemble(), LFDT)

    def test_explicit_repository_overrides_ci_and_origin(self):
        self.assert_bundle_source(self.assemble(ci_repository=GATEWAY, explicit=LFDT), LFDT)

    def test_explicit_repository_supports_checkout_without_origin(self):
        self.git("remote", "remove", "origin")
        self.assert_bundle_source(self.assemble(explicit=LFDT), LFDT)

    def test_unknown_origin_fails_before_native_build(self):
        self.git("remote", "set-url", "origin", "/local/mirror")
        with contextlib.redirect_stderr(io.StringIO()) as stderr, \
                self.assertRaises(SystemExit) as error:
            self.assemble()
        self.assertEqual(error.exception.code, 2)
        self.assertIn("--repository OWNER/REPO", stderr.getvalue())

    def test_invalid_repository_fails_before_native_build(self):
        for invalid in ("", f"https://github.com/{LFDT}", "owner/repo/extra"):
            with self.subTest(repository=invalid), \
                    contextlib.redirect_stderr(io.StringIO()) as stderr, \
                    self.assertRaises(SystemExit) as error:
                self.assemble(ci_repository=invalid)
            self.assertEqual(error.exception.code, 2)
            self.assertIn("Source repository must be OWNER/REPO", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
