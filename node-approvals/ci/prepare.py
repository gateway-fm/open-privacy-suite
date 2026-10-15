#!/usr/bin/env python3
"""Prepare checksum-pinned Linux fixture tools in this checkout, never system directories."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
COMPAT = json.loads((ROOT / "node-approvals/compatibility.json").read_text())


def fetch(url, checksum, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url, timeout=60) as response, destination.open("wb") as out:
        shutil.copyfileobj(response, out)
    with destination.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != checksum:
            destination.unlink()
            raise SystemExit("upstream fixture checksum mismatch")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--besu", action="store_true")
    args = parser.parse_args()
    solc = ROOT / ".tmp/approval-tools/solc"
    fetch(COMPAT["fixtures"]["solc_linux_url"], COMPAT["fixtures"]["solc_linux_sha256"], solc)
    solc.chmod(0o755)
    if args.besu:
        archive = ROOT / ".tmp/approval-tools/besu.tar.gz"
        fetch(COMPAT["besu"]["archive_url"], COMPAT["besu"]["archive_sha256"], archive)
        destination = ROOT / ".tmp/besu-dist"
        # A fresh installation avoids accidentally testing against a previous plugin.
        if (destination / ("besu-" + COMPAT["besu"]["version"])).exists():
            raise SystemExit("use a fresh checkout/distribution for compatibility CI")
        with tarfile.open(archive) as package:
            package.extractall(destination, filter="data")


if __name__ == "__main__":
    main()
