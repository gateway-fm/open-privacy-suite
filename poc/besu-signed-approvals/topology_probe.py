#!/usr/bin/env python3
"""Feasibility probe for the target topology: a producer plus a follower RPC node.

The CTO's PoC layout submits transactions through ordinary RPC nodes and lets devp2p carry them
to the single Besu sequencer, while OPS delivers approvals to the sequencer directly. Before the
race is measured on that layout, three things must hold locally: the two nodes peer, a transaction
sent to the follower reaches the producer's pool, and the follower imports the producer's blocks
when driven over its own Engine API (post-merge nodes do not propagate blocks over devp2p).
"""
import contextlib
import json
import subprocess
import sys
import time

import harness as h

from topology import FOLLOWER_KEY, PeeredNode  # the shared two-node harness


def main():
    result = {}
    with contextlib.ExitStack() as stack:
        producer = PeeredNode("topo-producer", plugin=True, node_key=h.KEYS[h.ADMIN])
        stack.callback(producer.close)
        follower = PeeredNode("topo-follower", plugin=False, node_key=FOLLOWER_KEY, static_peers=[producer.enode()])
        stack.callback(follower.close)
        # 1. Peering.
        for _ in range(60):
            peers = int(producer.rpc("net_peerCount"), 16), int(follower.rpc("net_peerCount"), 16)
            if peers == (1, 1):
                break
            time.sleep(0.5)
        result["peers"] = {"producer": peers[0], "follower": peers[1]}
        # 2. A transaction sent to the follower reaches the producer's pool by gossip.
        sender = next(k for k in h.KEYS if k != h.ADMIN)
        raw = h.sign_transfer(sender, h.ADMIN, 1, nonce=0) if hasattr(h, "sign_transfer") else None
        if raw is None:
            # Fall back to cast for the raw transaction, as the harness does.
            raw = subprocess.check_output(["cast", "mktx", "--private-key", h.KEYS[sender], "--chain", str(h.CHAIN_ID),
                                           "--rpc-url", follower.rpc_url, "--nonce", "0", "--gas-limit", "21000",
                                           "--gas-price", "1000000000", "--value", "1", h.ADMIN], text=True).strip()
        sent = time.time()
        tx_hash = follower.rpc("eth_sendRawTransaction", raw)
        arrived = None
        for _ in range(100):
            pooled = producer.rpc("txpool_besuTransactions")
            if any(p["hash"].lower() == tx_hash.lower() for p in pooled):
                arrived = time.time()
                break
            time.sleep(0.05)
        result["gossip"] = {"tx": tx_hash, "reached_producer_pool": arrived is not None,
                            "gossip_ms": round((arrived - sent) * 1000, 1) if arrived else None}
        # 3. The follower imports the producer's block when driven over its own Engine API.
        state = dict.fromkeys(["headBlockHash", "safeBlockHash", "finalizedBlockHash"], producer.head["hash"])
        attrs = {"timestamp": hex(max(int(producer.head["timestamp"], 16) + 1, int(time.time()))),
                 "prevRandao": h.ZERO, "suggestedFeeRecipient": h.ADMIN, "withdrawals": []}
        fcu = producer.engine("engine_forkchoiceUpdatedV2", state, attrs)
        time.sleep(1.5)  # let the candidate rebuild pick up the (unapproved) transaction decision
        payload = producer.engine("engine_getPayloadV2", fcu["payloadId"])["executionPayload"]
        for node in (producer, follower):
            np = node.engine("engine_newPayloadV2", payload)
            fc = node.engine("engine_forkchoiceUpdatedV2", dict.fromkeys(state, payload["blockHash"]), None)
            result.setdefault("import", {})[node.name] = {"newPayload": np["status"], "fcu": fc["payloadStatus"]["status"]}
        result["follower_head"] = int(follower.rpc("eth_getBlockByNumber", "latest", False)["number"], 16)
        result["producer_head"] = int(payload["blockNumber"], 16)
        result["decisions_in_producer_log"] = [
            l.split("OPS_APPROVAL_DECISION ")[1][:60] for l in producer.log_path.read_text(errors="replace").splitlines()
            if "OPS_APPROVAL_DECISION" in l][:3]
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    sys.exit(main())
