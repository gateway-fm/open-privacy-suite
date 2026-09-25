#!/usr/bin/env python3
"""One fresh OPS/Postgres/Redis/node stack per sustained transaction measurement.

Uses Gasstorm's patched generator and verifies every logged transaction hash on
chain. Both nodes use the same Engine-API build window and block cadence. Reports
offered, submitted and included rates separately; local results are not a fleet SLA.
"""
import argparse
import concurrent.futures
import contextlib
from datetime import datetime
import hashlib
import http.client
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import urllib.request

from delivery import MemorySampler, ROOT


def percentiles(values):
    if not values:
        return None
    values = sorted(values)
    return {label: values[int((len(values)-1)*q)]
            for label, q in [("p50", .50), ("p95", .95), ("p99", .99), ("max", 1)]}


class Miner:
    def __init__(self, node, zero, recipient):
        self.node, self.zero, self.recipient = node, zero, recipient
        self.blocks, self.error = [], None
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        n = self.node
        keys = ["headBlockHash", "safeBlockHash", "finalizedBlockHash"]
        try:
            while not self.stop.is_set():
                started = time.monotonic()
                attrs = {"timestamp": hex(max(int(n.head["timestamp"], 16)+1, int(time.time()))),
                         "prevRandao": self.zero, "suggestedFeeRecipient": self.recipient, "withdrawals": []}
                answer = n.engine("engine_forkchoiceUpdatedV2", dict.fromkeys(keys, n.head["hash"]), attrs)
                assert answer["payloadStatus"]["status"] == "VALID", answer
                if self.stop.wait(.8):
                    break
                payload = n.engine("engine_getPayloadV2", answer["payloadId"])["executionPayload"]
                answer = n.engine("engine_newPayloadV2", payload)
                assert answer["status"] == "VALID", answer
                answer = n.engine("engine_forkchoiceUpdatedV2", dict.fromkeys(keys, payload["blockHash"]), None)
                assert answer["payloadStatus"]["status"] == "VALID", answer
                n.head = n.rpc("eth_getBlockByNumber", payload["blockNumber"], False)
                self.blocks.append({"at_ms": int(time.time()*1000), "hash": n.head["hash"],
                    "transactions": n.head["transactions"], "gas_used": int(payload["gasUsed"], 16),
                    "gas_limit": int(payload["gasLimit"], 16)})
                self.stop.wait(max(0, 1-(time.monotonic()-started)))
        except BaseException as error:
            self.error = error

    def check(self):
        if self.error:
            raise self.error

    def close(self):
        self.stop.set()
        self.thread.join(timeout=35)
        if self.thread.is_alive():
            raise RuntimeError("block driver did not stop")


def read_metrics(stack):
    with urllib.request.urlopen(stack.url + "/metrics", timeout=10) as response:
        return response.read().decode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", choices=("besu", "reth"), required=True)
    parser.add_argument("--rate", type=int, default=5000)
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--no-gate", action="store_true")
    parser.add_argument("--retain", type=int, default=100000)
    parser.add_argument("--verify-workers", type=int, choices=range(1, 33))
    parser.add_argument("--max-requests", type=int, default=5000,
                        help="OPS concurrent request ceiling; independent of the requested TPS")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.rate <= 100000 or not 1 <= args.seconds <= 600:
        parser.error("rate must be 1..100000 and seconds must be 1..600")
    if min(args.retain, args.max_requests) < 1:
        parser.error("retain and max-requests must be positive")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    os.environ.update(OPS_EVIDENCE_DIR=str(output), OPS_POC_KEEPALIVE="1", OPS_POC_GAS_LIMIT="200000000")
    os.environ["OPS_APPROVAL_VERIFY_WORKERS"] = str(args.verify_workers or 2)
    os.environ.setdefault("OPS_RETH_BINARY", str(ROOT / ".tmp/approval-target/release/ops-reth-approvals-poc"))
    os.environ.setdefault("OPS_BESU_HOME", str(ROOT / ".tmp/besu-review-private"))
    sys.path.insert(0, str(ROOT / "poc" / f"{args.node}-signed-approvals"))
    if args.node == "besu":
        import gasstorm as g
    else:
        import gasstorm_compare as g
    h = g.h
    g.prepare()
    genesis = json.loads((output / "genesis.json").read_text())
    genesis["gasLimit"] = hex(200000000)  # avoid a 30M-gas/second ceiling below the requested ETH TPS
    (output / "genesis.json").write_text(json.dumps(genesis) + "\n")
    ops_env = {"OPS_APPROVAL_RETAIN_MAX": str(args.retain), "OPS_APPROVAL_HOPS_FILE": "",
               "MAX_CONCURRENT_REQUESTS": str(args.max_requests)}
    name = "transactions-" + args.node
    report = {"kind": "full-transaction-stack", "node": args.node, "requested_rate": args.rate,
              "seconds": args.seconds, "gate": not args.no_gate, "retain": args.retain,
              "block_interval_seconds": 1, "build_window_seconds": .8,
              "loadgen_sha256": hashlib.sha256(g.LOADGEN_BINARY.read_bytes()).hexdigest()}
    report["verify_workers"] = args.verify_workers or 2
    report["max_concurrent_requests"] = args.max_requests
    node_options = {"extra": ["--plugin-ops-approval-verify-workers", str(args.verify_workers)]} if args.verify_workers else None
    with contextlib.ExitStack() as resources:
        stack = resources.enter_context(contextlib.closing(
            g.LoadStack(name, plugin=not args.no_gate, ops_env=ops_env, node_options=node_options) if args.node == "besu"
            else g.GasstormStack(name, disabled=args.no_gate, ops_env=ops_env)))
        miner = resources.enter_context(contextlib.closing(Miner(stack.node, h.ZERO, h.ADMIN)))
        load = resources.enter_context(contextlib.closing(g.Loadgen(stack)))
        sampler = resources.enter_context(contextlib.closing(MemorySampler(
            {"node": stack.node.process, "ops": stack.ops, "loadgen": load.process})))
        try:
            (output / "metrics-before.txt").write_text(read_metrics(stack))
            config = {"pattern": "constant", "durationSec": args.seconds, "constantRate": args.rate,
                      "numAccounts": 10, "transactionType": "eth-transfer", "privacyMode": True}
            assert g.request(load.url + "/start", "POST", config)["status"] == "started"
            deadline = time.monotonic() + args.seconds + 240
            samples = []
            while True:
                miner.check()
                status = g.request(load.url + "/status")
                samples.append({"at_ms": int(time.time()*1000), **status})
                if status["status"] in ("completed", "error"):
                    break
                if time.monotonic() > deadline:
                    raise TimeoutError("load generator did not complete")
                time.sleep(.5)
            report["status"] = status
            (output / "status-samples.json").write_text(json.dumps(samples) + "\n")
            assert status["status"] == "completed", status
            run = g.request(load.url + "/history?limit=1")["runs"][0]
            report["generator_run"] = run
            logs = []
            deadline = time.monotonic() + 30
            while True:
                page = g.request(load.url + f"/history/{run['id']}/transactions?limit=1000&offset={len(logs)}")
                rows = page.get("transactions") or []
                if not rows and not logs and status["txSent"] and time.monotonic() < deadline:
                    time.sleep(.1)
                    continue
                logs.extend(rows)
                if len(logs) >= page["total"]:
                    break
                assert rows, "transaction pagination stalled"
            (output / "transactions.json").write_text(json.dumps(logs) + "\n")
            # Allow the final block builds to complete, then independently verify receipts.
            time.sleep(3)
            (output / "metrics-after.txt").write_text(read_metrics(stack))
            by_hash = {row["txHash"].lower(): row for row in logs if row.get("txHash")}
            local, connections, lock = threading.local(), [], threading.Lock()

            def receipt(tx_hash):
                if not hasattr(local, "connection"):
                    local.connection = http.client.HTTPConnection(stack.node.rpc_url.removeprefix("http://"), timeout=30)
                    with lock:
                        connections.append(local.connection)
                body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_getTransactionReceipt", "params": [tx_hash]})
                local.connection.request("POST", "/", body, {"Content-Type": "application/json"})
                reply = json.loads(local.connection.getresponse().read())
                assert "error" not in reply, reply
                r = reply["result"]
                return {"hash": tx_hash, "receipt": None if r is None else {
                    k: r[k] for k in ("transactionHash", "blockHash", "blockNumber", "status")}}

            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                    receipts = list(pool.map(receipt, by_hash))
            finally:
                for connection in connections:
                    connection.close()
            miner.check()
            canonical = {b["hash"]: b for b in miner.blocks}
            # Sets keep verification linear in the number of transactions.
            members = {block: set(b["transactions"]) for block, b in canonical.items()}
            good, reverted, missing, latencies, within = 0, 0, 0, [], 0
            start_ms = datetime.fromisoformat(run["startedAt"]).timestamp() * 1000
            for row in receipts:
                r = row["receipt"]
                if r is None:
                    missing += 1
                    continue
                assert r["transactionHash"].lower() == row["hash"]
                block = canonical[r["blockHash"]]
                assert row["hash"] in members[r["blockHash"]]
                if r["status"] != "0x1":
                    reverted += 1
                    continue
                good += 1
                within += start_ms <= block["at_ms"] <= start_ms + args.seconds*1000
                latencies.append(block["at_ms"] - by_hash[row["hash"]]["sentAtMs"])
            report["receipts"] = {"unique_logged_hashes": len(by_hash), "successful": good,
                "reverted": reverted, "missing": missing, "included_during_sending": within,
                "included_during_sending_tps": within/args.seconds,
                "queue_to_commit_ms": percentiles(latencies)}
            (output / "receipts.json").write_text(json.dumps(receipts) + "\n")
            print(json.dumps(report["receipts"]), flush=True)
        except BaseException as error:
            report["error"] = str(error)
            raise
        finally:
            sampler.close()
            report["memory_samples"] = sampler.samples
            report["memory_sampling_error"] = sampler.error
            report["blocks"] = miner.blocks
            (output / "transactions-report.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
