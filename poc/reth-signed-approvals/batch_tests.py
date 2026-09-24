#!/usr/bin/env python3
"""Real node checks for batch authentication, independent execution and late delivery."""
import contextlib
import copy
import time
import harness as h
from run import Client, node, record, timings

def tests():
    with node("batch-full") as n, contextlib.closing(Client(n)) as c:
        txs=[n.raw(h.ALICE,h.BENCH_VAULT,"put(uint256,uint256)",i,7,nonce=i) for i in range(32)]
        batch=c.batch([c.prepare(t) for t in txs])
        c.send(batch)
        for t in txs:n.submit(t)
        n.make_block(txs)
        stats=timings(n)[-1]["approval_stats"]
        assert stats["verified"]==32 and stats["verified_batches"]==1,stats
        assert stats["batch_sizes"][32]==1,stats
        record("one_signature_authorizes_32_independent_transactions",stats=stats)
    with node("batch-mixed") as n, contextlib.closing(Client(n)) as c:
        bad=n.raw(h.ALICE,h.READ_ROUTER,"probe()")
        good=n.raw(h.ADMIN,h.BENCH_VAULT,"put(uint256,uint256)",99,7)
        c.send(c.batch([c.prepare(bad),c.prepare(good)]))
        n.submit(bad);n.submit(good);n.make_block([good],denied=bad)
        assert n.rpc("eth_getTransactionReceipt",bad["hash"]) is None
        assert int(n.rpc("eth_getTransactionCount",h.ALICE,"latest"),16)==0
        record("divergent_member_does_not_cancel_other_batch_member")
    with node("batch-tampered",wait_ms=600) as n, contextlib.closing(Client(n)) as c:
        txs=[n.raw(sender,h.BENCH_VAULT,"put(uint256,uint256)",i,7) for i,sender in enumerate([h.ALICE,h.ADMIN])]
        batch=c.batch([c.prepare(t) for t in txs]); forged=copy.deepcopy(batch)
        forged["approvals"][1]["principal"]=h.ZERO
        c.send(forged)
        for t in txs:n.submit(t)
        time.sleep(.8);n.make_block([])
        stats=timings(n)[-1]["approval_stats"]
        assert stats["verified"]==0 and stats["invalid_envelopes"]==1,stats
        # Deliver after transactions on retry. The node must wait without a caller ACK.
        for t in txs:n.submit(t)
        c.send(batch);n.make_block(txs)
        record("tampering_rejects_entire_batch_then_late_valid_retry_succeeds")

if __name__=="__main__":
    h.prepare();tests()
