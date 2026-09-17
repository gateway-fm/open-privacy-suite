#!/usr/bin/env python3
"""Find or fetch the pinned, unmodified Reth source required by this crate."""

import argparse
import os
from pathlib import Path
import subprocess

COMMIT = "5a6940e351fed80458fe6c9da8581cbe4b8bd036"
TAG = "v2.5.2"
CRATE = Path(__file__).resolve().parents[1]


def git(*args):
    return subprocess.check_output(["git", *args], text=True).strip()


def is_pinned(path):
    return path.is_dir() and git("-C", str(path), "rev-parse", "HEAD") == COMMIT


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=os.environ.get("OPS_RETH_SOURCE"))
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    source = args.source
    if source is None:
        for ancestor in CRATE.parents:
            candidate = ancestor / ".tmp/reth-policy-poc/reth"
            if candidate.is_dir() and is_pinned(candidate):
                source = candidate
                break
    if source is None:
        source = CRATE.parents[1] / ".tmp/reth-policy-source"
        if not source.exists():
            if args.offline:
                parser.error("pinned Reth source is unavailable; set OPS_RETH_SOURCE")
            source.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(
                ["git", "clone", "--depth", "1", "--branch", TAG,
                 "https://github.com/paradigmxyz/reth.git", str(source)], check=True
            )
    source = source.resolve()
    if not is_pinned(source):
        parser.error(f"source must be Reth {TAG}, commit {COMMIT}: {source}")
    # Never repair or change the upstream checkout. Local tracked modifications could
    # change the trusted execution engine even when HEAD still matches the pin.
    if git("-C", str(source), "status", "--porcelain", "--untracked-files=no"):
        parser.error(f"upstream source has tracked modifications: {source}")
    # Keep the link outside this crate's Cargo workspace: a link inside it makes
    # Cargo inherit our workspace metadata for upstream path dependencies.
    link = CRATE.parents[1] / ".tmp/reth"
    link.parent.mkdir(parents=True, exist_ok=True)
    if link.is_symlink():
        if link.resolve() != source:
            parser.error(f"{link} already refers to another checkout")
    elif link.exists():
        parser.error(f"{link} exists and is not a source link")
    else:
        link.symlink_to(source, target_is_directory=True)
    print(f"Reth {TAG} ({COMMIT}) available at {link}")


if __name__ == "__main__":
    main()
