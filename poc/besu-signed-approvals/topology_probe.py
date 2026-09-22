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
import os
import subprocess
import sys
import time

import harness as h

# The producer keeps the harness's node key; the follower needs its own or devp2p refuses.
FOLLOWER_KEY = "22" * 32


class PeeredNode(h.Node):
    """harness.Node with devp2p on. Duplicates the argument list on purpose: the harness is being
    reviewed and must not change under the reviewer; fold this back in afterwards."""

    def __init__(self, name, *, plugin, node_key, bootnodes=(), wait_ms=5000):
        self.name, self.plugin, self.fork = name, plugin, "shanghai"
        self.directory = h.SCRATCH / f"{name}-{os.getpid()}-{int(time.time())}"
        self.directory.mkdir(parents=True, exist_ok=True)
        self.rpc_port, self.engine_port, self.approval_port, self.p2p_port = (h.unused_port() for _ in range(4))
        self.rpc_url = f"http://127.0.0.1:{self.rpc_port}"
        self.engine_url = f"http://127.0.0.1:{self.engine_port}"
        self.log_path = self.directory / "node.log"
        self.records, self.connections = [], []
        import threading
        self.local, self.connections_lock = threading.local(), threading.Lock()
        self.secret = bytes.fromhex("11" * 32)
        (self.directory / "jwt.hex").write_text(self.secret.hex())
        (self.directory / "key").write_text("0x" + node_key)
        args = [str(h.BESU_HOME / "bin/besu"), "--data-path", str(self.directory / "data"),
                "--genesis-file", str(h.EVIDENCE / "genesis.json"), "--node-private-key-file", str(self.directory / "key"),
                "--min-gas-price", "0",
                "--rpc-http-enabled", "--rpc-http-host", "127.0.0.1", "--rpc-http-port", str(self.rpc_port),
                "--rpc-http-api", "ETH,NET,WEB3,DEBUG,TXPOOL,ADMIN" + (",OPS" if plugin else ""),
                "--engine-rpc-enabled", "--engine-rpc-port", str(self.engine_port),
                "--engine-jwt-secret", str(self.directory / "jwt.hex"), "--engine-host-allowlist", "*",
                "--rpc-tx-feecap", "0",
                "--p2p-enabled=true", "--discovery-enabled=false", "--p2p-host", "127.0.0.1", "--p2p-port", str(self.p2p_port),
                "--tx-pool-max-future-by-sender", "2000", "--tx-pool-max-prioritized", "20000",
                "--tx-pool-max-prioritized-by-type", "FRONTIER=20000", "--rpc-http-max-active-connections", "4096",
                "--logging", os.environ.get("OPS_BESU_LOG_LEVEL", "INFO")]
        if bootnodes:
            # Discovery is off, so peers are static: Besu refuses --bootnodes without discovery.
            static = self.directory / "static-nodes.json"
            static.write_text(json.dumps([b.split("?")[0] for b in bootnodes]))
            args += ["--static-nodes-file", str(static)]
        if plugin:
            args += ["--plugins", "OpsApprovalPlugin",
                     "--plugin-ops-approval-listen", f"127.0.0.1:{self.approval_port}",
                     "--plugin-ops-approval-public-key", h.APPROVAL_PUBLIC_KEY,
                     "--plugin-ops-approval-chain-id", str(h.CHAIN_ID),
                     "--plugin-ops-approval-wait-ms", str(wait_ms)]
        else:
            args += ["--Xplugins-external-enabled=false"]
        env = dict(os.environ, JAVA_HOME=str(h.JAVA_HOME), PATH=f"{h.JAVA_HOME}/bin:" + os.environ["PATH"], JAVA_OPTS="-Xmx2g")
        self.log = open(self.log_path, "ab")
        self.process = subprocess.Popen(args, stdout=self.log, stderr=subprocess.STDOUT, env=env, cwd=self.directory)
        deadline = time.time() + 90
        while True:
            if self.process.poll() is not None:
                raise RuntimeError(f"{name}: Besu exited early\n" + self.log_path.read_text(errors="replace")[-3000:])
            try:
                self.head = self.rpc("eth_getBlockByNumber", "latest", False)
                break
            except Exception:
                if time.time() > deadline:
                    raise RuntimeError(f"{name}: Besu did not become ready\n" + self.log_path.read_text(errors="replace")[-3000:])
                time.sleep(0.5)

    def enode(self):
        return self.rpc("admin_nodeInfo")["enode"]


def main():
    result = {}
    with contextlib.ExitStack() as stack:
        producer = PeeredNode("topo-producer", plugin=True, node_key=h.KEYS[h.ADMIN])
        stack.callback(producer.close)
        follower = PeeredNode("topo-follower", plugin=False, node_key=FOLLOWER_KEY, bootnodes=[producer.enode()])
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
