"""Lifecycle regressions: project isolation, scoped cleanup and failure propagation."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.bin = self.directory / 'bin'
        self.bin.mkdir()
        shim = self.bin / 'docker-compose'
        shim.write_text('#!/usr/bin/env python3\n'
                        'import json, os, sys\n'
                        'if os.environ.get("FAIL_LEGACY"): sys.exit(9)\n'
                        'with open(os.environ["CALLS"], "a") as f: f.write(json.dumps(sys.argv[1:])+"\\n")\n'
                        'if "port" in sys.argv: print("127.0.0.1:12345")\n'
                        'if os.environ.get("FAIL_CHECK") and sys.argv[-1]=="check": sys.exit(7)\n')
        shim.chmod(0o755)
        (self.bin / 'docker').write_text('#!/usr/bin/env python3\n'
                                        'import os, sys\n'
                                        'if sys.argv[1:]==["compose", "version"]: sys.exit(0 if os.environ.get("MODERN_COMPOSE") else 1)\n'
                                        'if sys.argv[1:2]==["compose"]:\n'
                                        '    os.environ.pop("FAIL_LEGACY", None)\n'
                                        '    path=os.path.join(os.path.dirname(sys.argv[0]), "docker-compose")\n'
                                        '    os.execv(path, [path, *sys.argv[2:]])\n'
                                        'sys.exit(0)\n')
        (self.bin / 'docker').chmod(0o755)
        self.calls = self.directory / 'calls.jsonl'
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                        CALLS=str(self.calls))
        self.env.pop('RETH_DEMO_PROJECT', None)

    def invoke(self, mode, checkout='a', **env):
        root = self.directory / checkout
        (root / 'scripts').mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / 'scripts/reth-demo.sh', root / 'scripts/reth-demo.sh')
        return subprocess.run(['bash', str(root / 'scripts/reth-demo.sh'), mode],
                              env=dict(self.env, **env), capture_output=True, text=True)

    def commands(self):
        return [json.loads(line) for line in self.calls.read_text().splitlines()] if self.calls.exists() else []

    def test_checkout_projects_are_stable_and_distinct(self):
        for checkout in ('a', 'a', 'b'):
            self.assertEqual(self.invoke('status', checkout).returncode, 0)
        commands = self.commands()
        projects = [args[args.index('-p') + 1] for args in commands]
        self.assertEqual(projects[0], projects[1])
        self.assertNotEqual(projects[0], projects[2])
        for args in commands:
            self.assertEqual(args[args.index('--env-file') + 1], '/dev/null')
            self.assertEqual(args[args.index('-f') + 1], 'docker-compose.reth-demo.yml')

    def test_modern_compose_is_preferred_when_legacy_is_also_installed(self):
        result = self.invoke('status', MODERN_COMPOSE='1', FAIL_LEGACY='1')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.commands()), 1)

    def test_modern_compose_propagates_scenario_failure(self):
        result = self.invoke('check', MODERN_COMPOSE='1', FAIL_CHECK='1')
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertFalse(any(args[-1] == 'block-driver' for args in self.commands()))

    def test_down_retains_data_and_reset_removes_only_scoped_volumes(self):
        self.assertEqual(self.invoke('down').returncode, 0)
        self.assertEqual(self.invoke('reset').returncode, 0)
        down, reset = self.commands()
        self.assertNotIn('--volumes', down)
        self.assertIn('--volumes', reset)
        self.assertEqual(down[down.index('-p') + 1], reset[reset.index('-p') + 1])

    def test_failed_scenario_cannot_report_success_or_start_driver(self):
        result = self.invoke('check', FAIL_CHECK='1')
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertNotIn('All scenarios passed', result.stdout)
        self.assertFalse(any(args[-1] == 'block-driver' for args in self.commands()))

    def test_invalid_mode_or_project_never_touches_docker(self):
        self.assertEqual(self.invoke('typo').returncode, 2)
        self.assertEqual(self.invoke('reset', RETH_DEMO_PROJECT='bad/project').returncode, 2)
        self.assertEqual(self.invoke('reset', RETH_DEMO_PROJECT='-invalid').returncode, 2)
        self.assertEqual(self.invoke('reset', RETH_DEMO_PROJECT='_invalid').returncode, 2)
        self.assertEqual(self.commands(), [])


if __name__ == '__main__':
    unittest.main()
