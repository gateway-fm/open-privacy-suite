#!/usr/bin/env python3
"""Verify or synchronize OPS's vendored, commit-pinned approval contract inputs."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
LOCK = Path("integrations/approvals-contract.lock.json")
MANIFEST = Path("integrations/approvals-contract.manifest.json")
REPOSITORY = "gateway-fm/ops-node-integrations"
INPUTS = {
    "proto/ops/approvals/v1/approvals.proto": "proto/ops/approvals/v1/approvals.proto",
    **{f"contract/vectors/{name}.json": f"internal/nodeapproval/testdata/{name}.json"
       for name in ("batch", "call-batch", "call-v3", "fingerprint")},
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify_bytes(data, expected, name):
    if digest(data) != expected:
        raise ValueError(f"checksum differs for {name}")
    return data


def safe_path(root, name):
    relative = Path(name)
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise ValueError(f"unsafe contract path: {name}")
    for index in range(1, len(relative.parts) + 1):
        if (root / Path(*relative.parts[:index])).is_symlink():
            raise ValueError(f"contract path is a symlink: {name}")
    return root / relative


def check_inputs(root, manifest):
    for source, destination in manifest["ops_files"].items():
        path = safe_path(root, destination)
        if not path.is_file():
            raise ValueError(f"missing vendored input: {destination}")
        verify_bytes(path.read_bytes(), manifest["files"][source], destination)


def download(commit, name, expected):
    url = f"https://raw.githubusercontent.com/{REPOSITORY}/{commit}/{name}"
    with urllib.request.urlopen(url, timeout=30) as response:
        data = response.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise ValueError(f"contract input too large: {name}")
    return verify_bytes(data, expected, name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", action="store_true", help="also verify immutable upstream files")
    parser.add_argument("--sync", action="store_true", help="replace vendored inputs from the reviewed pin")
    args = parser.parse_args()
    pin = json.loads(safe_path(ROOT, str(LOCK)).read_text())
    if pin["repository"] != REPOSITORY or not re.fullmatch(r"[0-9a-f]{40}", pin["commit"]):
        raise ValueError("contract requires the integration repository and an exact commit")
    if not re.fullmatch(r"[0-9a-f]{64}", pin["manifest_sha256"]):
        raise ValueError("invalid manifest checksum")
    if args.upstream or args.sync:
        raw = download(pin["commit"], "contract/manifest.json", pin["manifest_sha256"])
    else:
        raw = verify_bytes(safe_path(ROOT, str(MANIFEST)).read_bytes(), pin["manifest_sha256"], str(MANIFEST))
    manifest = json.loads(raw)
    if manifest["version"] != pin["version"] or manifest["ops_files"] != INPUTS:
        raise ValueError("unsupported contract version or input mapping")
    if args.upstream or args.sync:
        fetched = {destination: download(pin["commit"], source, manifest["files"][source])
                   for source, destination in INPUTS.items()}
        if args.sync:
            # Fetch and verify everything before modifying any vendored input.
            destinations = {name: safe_path(ROOT, name) for name in fetched}
            local_manifest = safe_path(ROOT, str(MANIFEST))
            for name, path in destinations.items():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(fetched[name])
            local_manifest.write_bytes(raw)
        else:
            verify_bytes(safe_path(ROOT, str(MANIFEST)).read_bytes(), pin["manifest_sha256"], str(MANIFEST))
    check_inputs(ROOT, manifest)
    print(f"approval contract {pin['version']} at {pin['commit']} verified")


if __name__ == "__main__":
    main()
