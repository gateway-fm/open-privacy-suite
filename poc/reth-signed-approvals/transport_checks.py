#!/usr/bin/env python3
"""Actual OPS/Reth connection survives >60s idle; no first-transaction dial."""
import contextlib
import json
import time
import harness as h
from demo import Stack

h.prepare()
with contextlib.closing(Stack("transport-idle")) as stack:
    n=stack.node
    first=n.raw(h.ALICE,h.BENCH_VAULT,"put(uint256,uint256)",1,7)
    assert stack.submit(first).get("result")==first["hash"]
    n.make_block([first])
    print("Idle for 65 seconds after first successful transaction",flush=True)
    for _ in range(13):time.sleep(5)
    second=n.raw(h.ALICE,h.BENCH_VAULT,"put(uint256,uint256)",2,7)
    assert stack.submit(second).get("result")==second["hash"]
    n.make_block([second])
    assert n.rpc("eth_getTransactionReceipt",second["hash"])["status"]=="0x1"
log=(h.EVIDENCE/"transport-idle-ops.log").read_text()
assert 'approval connections used" count=1' in log,log[-2000:]
result={"passed":True,"idle_seconds":65,"connections":1,"transactions":[first["hash"],second["hash"]]}
(h.EVIDENCE/"idle.json").write_text(json.dumps(result,indent=2)+"\n")
print("PASS: same connection after 65 seconds idle",flush=True)
