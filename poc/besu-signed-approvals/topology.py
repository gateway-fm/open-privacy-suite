#!/usr/bin/env python3
"""Two Besu nodes for the deployment layout: a block producer and a follower RPC node.

Transactions are submitted to the follower and reach the producer by devp2p gossip; approvals go
to the producer directly. The follower also runs the plugin because OPS's preflight
(`ops_prepareApproval`) must execute on a Besu node with the producer's tracer — this is the
"preflight replica" of the production plan. Post-merge nodes do not propagate blocks over devp2p,
so whoever plays the consensus client must feed the producer's payloads to the follower too.
"""
import json
import os
import subprocess
import threading
import time

import harness as h

FOLLOWER_KEY = "22" * 32


class PeeredNode(h.Node):
    """harness.Node with devp2p on. Duplicates the argument list on purpose while the harness is
    under review; fold back into harness.Node afterwards."""

    def __init__(self, name, *, plugin, node_key, static_peers=(), wait_ms=5000):
        self.name, self.plugin, self.fork = name, plugin, "shanghai"
        self.directory = h.SCRATCH / f"{name}-{os.getpid()}-{time.time_ns()}"
        self.directory.mkdir(parents=True, exist_ok=True)
        self.rpc_port, self.engine_port, self.approval_port, self.p2p_port = (h.unused_port() for _ in range(4))
        self.rpc_url = f"http://127.0.0.1:{self.rpc_port}"
        self.engine_url = f"http://127.0.0.1:{self.engine_port}"
        self.log_path = self.directory / "node.log"
        self.records, self.connections = [], []
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
        if static_peers:
            # Discovery is off, so peers are static: Besu refuses --bootnodes without discovery.
            static = self.directory / "static-nodes.json"
            static.write_text(json.dumps([p.split("?")[0] for p in static_peers]))
            args += ["--static-nodes-file", str(static)]
        if plugin:
            args += ["--plugins", "OpsApprovalPlugin", *h.approval_options(self.approval_port, wait_ms)]
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


class Pair:
    """Producer + follower, peered. `node` is the producer (whose decisions the harness reads)."""

    def __init__(self, name, plugin=True, wait_ms=5000):
        self.node = PeeredNode(name + "-producer", plugin=plugin, node_key=h.KEYS[h.ADMIN], wait_ms=wait_ms)
        try:
            self.follower = PeeredNode(name + "-follower", plugin=plugin, node_key=FOLLOWER_KEY,
                                       static_peers=[self.node.enode()], wait_ms=wait_ms)
        except BaseException:
            self.node.close()
            raise
        for _ in range(120):
            if int(self.node.rpc("net_peerCount"), 16) >= 1 and int(self.follower.rpc("net_peerCount"), 16) >= 1:
                break
            time.sleep(0.5)
        else:
            self.close()
            raise RuntimeError("producer and follower did not peer")

    def followers(self):
        return [self.follower]

    def close(self):
        for n in (getattr(self, "follower", None), self.node):
            if n is not None:
                n.close()
