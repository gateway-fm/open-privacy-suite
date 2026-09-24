#!/usr/bin/env python3
"""Prepare the pinned upstream checkout and build both halves of the PoC."""
import os
from pathlib import Path
import subprocess

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
COMMIT="5a6940e351fed80458fe6c9da8581cbe4b8bd036"

def run(*args,**kw):subprocess.run(args,check=True,**kw)

(ROOT/".tmp").mkdir(exist_ok=True)
source=ROOT/".tmp/reth"
if not source.exists():
    run("git","clone","--depth","1","--branch","v2.5.2","https://github.com/paradigmxyz/reth.git",str(source))
assert subprocess.check_output(["git","-C",str(source),"rev-parse","HEAD"],text=True).strip()==COMMIT
assert not subprocess.check_output(["git","-C",str(source),"status","--porcelain"],text=True).strip()
target=Path(os.environ.get("CARGO_TARGET_DIR",str(ROOT/".tmp/approval-target"))).resolve()
env=dict(os.environ,CARGO_TARGET_DIR=str(target),CARGO_BUILD_JOBS=os.environ.get("CARGO_BUILD_JOBS","6"))
run("cargo","build","--release","--locked","--manifest-path",str(HERE/"Cargo.toml"),env=env)
run("cargo","test","--release","--locked","--manifest-path",str(HERE/"Cargo.toml"),env=env)
run("go","build","-o",str(ROOT/".tmp/approval-client"),"./poc/reth-signed-approvals/client",cwd=ROOT)
run("go","test","-c","-o",str(ROOT/".tmp/server-approval.test"),"./internal/server",cwd=ROOT)
run("go","build","-tags","mockauth","-o",str(ROOT/".tmp/ops-server"),"./cmd/server",cwd=ROOT)
print("OPS_RETH_BINARY="+str(target/"release/ops-reth-approvals-poc"))

