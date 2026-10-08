#!/usr/bin/env python3
"""Apply reviewed local patches in disposable clones; leave sibling repos intact."""
import hashlib
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]

def prepare(name, upstream, revision):
    patch = HERE / 'patches' / (name + '-stability.patch')
    digest = hashlib.sha256(patch.read_bytes()).hexdigest()[:16]
    destination = ROOT / '.tmp' / 'gasstorm-patched' / (name + '-' + digest)
    stamp = destination / '.ops-patched'
    if stamp.exists():
        return str(destination)
    if destination.exists():
        raise RuntimeError(f'Incomplete patch checkout: {destination}')
    destination.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(['git', 'clone', '--no-hardlinks', '--no-checkout', str(upstream), str(destination)], check=True, stdout=sys.stderr)
    subprocess.run(['git', '-C', str(destination), 'checkout', '--detach', revision], check=True, stdout=sys.stderr)
    subprocess.run(['git', '-C', str(destination), 'apply', '--check', str(patch)], check=True)
    subprocess.run(['git', '-C', str(destination), 'apply', str(patch)], check=True)
    stamp.write_text(digest)
    return str(destination)

if __name__ == '__main__':
    name, source = sys.argv[1:]
    revisions = {'loadgenerator':'d24667e23b010ded9a1d2e80f4d90741c6ab51f2', 'gasstorm':'c7cb9cb1ca73959fc413632e1bf5a1156ed06e0b'}
    print(prepare(name, Path(source), revisions[name]))
