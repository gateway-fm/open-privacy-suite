#!/usr/bin/env python3
"""Build, test and bundle a supported integration. Does not publish or modify a node install."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
COMPAT = json.loads((HERE / "compatibility.json").read_text())
VERSION = (HERE / "VERSION").read_text().strip()


def run(*args, **kwargs):
    subprocess.run(args, cwd=ROOT, check=True, **kwargs)


def output(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", choices=["besu", "reth"])
    parser.add_argument("--output", type=Path, default=ROOT / ".tmp/approval-release")
    args = parser.parse_args()
    if args.target == "besu":
        run("gradle", "-p", str(HERE / "besu"), "--no-daemon", "check", "assemble", "dependencyInventory")
        artifact = HERE / f"besu/build/libs/ops-besu-approvals-{VERSION}-besu-{COMPAT['besu']['version']}.jar"
        toolchain = output("java", "--version")
        name = artifact.stem
    else:
        source = ROOT / ".tmp/reth"
        source.parent.mkdir(exist_ok=True)
        if not source.exists():
            run("git", "clone", "--depth", "1", "--branch", "v" + COMPAT["reth"]["version"],
                COMPAT["reth"]["repository"], str(source))
        if output("git", "-C", str(source), "rev-parse", "HEAD") != COMPAT["reth"]["commit"]:
            raise SystemExit("Reth checkout differs from compatibility.json")
        if output("git", "-C", str(source), "status", "--porcelain"):
            raise SystemExit("Reth checkout must be unmodified")
        import tomllib
        if tomllib.loads((HERE / "reth/Cargo.toml").read_text())["package"]["version"] != VERSION:
            raise SystemExit("Cargo package version differs from VERSION")
        target = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / ".tmp/approval-target")).resolve()
        env = dict(os.environ, CARGO_TARGET_DIR=str(target))
        for verb in ["test", "build"]:
            run("cargo", verb, "--release", "--locked", "--manifest-path", str(HERE / "reth/Cargo.toml"), env=env)
        artifact = target / "release/ops-reth-approvals"
        toolchain = output("rustc", "--version")
        name = f"ops-reth-approvals-{VERSION}-reth-{COMPAT['reth']['version']}-{platform.system().lower()}-{platform.machine()}"
    destination = args.output.resolve() / name
    # Refuse to mix a previous bundle's files/checksums into a new one.
    destination.mkdir(parents=True, exist_ok=False)
    shutil.copy2(artifact, destination / artifact.name)
    if args.target == "besu":
        shutil.copy2(HERE / "besu/build/dependency-inventory.json", destination / "dependency-inventory.json")
    else:
        shutil.copy2(HERE / "reth/Cargo.lock", destination / "Cargo.lock")
    commit = output("git", "rev-parse", "HEAD")
    for filename in ["VERSION", "compatibility.json", "README.md", "OPERATIONS.md", "alerts.yml", "advisory-review.json"]:
        shutil.copy2(HERE / filename, destination / filename)
        if filename.endswith(".md"):
            # External repository references still work when the bundle is unpacked alone.
            content = (destination / filename).read_text()
            content = re.sub(r"\]\(\.\./([^)]*)\)",
                             lambda match: f"](https://github.com/gateway-fm/open-privacy-suite/blob/{commit}/{match[1]})",
                             content)
            (destination / filename).write_text(content)
    shutil.copy2(ROOT / "LICENSE", destination / "LICENSE")
    manifest = {
        "version": VERSION, "integration": args.target,
        "source_commit": commit,
        "source_dirty": bool(output("git", "status", "--porcelain")),
        "toolchain": toolchain, "platform": platform.system(), "architecture": platform.machine(),
        "compatibility": COMPAT,
    }
    (destination / "build.json").write_text(json.dumps(manifest, indent=2) + "\n")
    checksums = []
    for path in sorted(destination.iterdir()):
        with path.open("rb") as stream:
            checksums.append(hashlib.file_digest(stream, "sha256").hexdigest() + "  " + path.name)
    (destination / "SHA256SUMS").write_text("\n".join(checksums) + "\n")
    print(destination)


if __name__ == "__main__":
    main()
