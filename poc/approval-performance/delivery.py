#!/usr/bin/env python3
"""Measure real OPS signing/retention/delivery against an isolated Besu or Reth.

This sends synthetic approval hashes, not transactions. It measures receiver
signature verification and storage, and cannot establish end-to-end transaction TPS.
"""
import argparse
import contextlib
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[2]


def metric(snapshot, name):
    for family in snapshot["metrics"]:
        if family["name"] == "privacyproxy_approval_" + name:
            return sum(m.get("counter", m.get("gauge", {})).get("value", 0)
                       for m in family.get("metric", []))
    return 0


class Driver:
    def __init__(self, node, output, kind, retain, ttl):
        env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "TMPDIR", "LANG")}
        env.update(OPS_APPROVAL_NODE=kind, OPS_APPROVAL_RETAIN_MAX=str(retain), OPS_APPROVAL_TTL=ttl)
        self.log = (output / "sender.log").open("w")
        self.process = subprocess.Popen(
            [str(ROOT / ".tmp/approval-performance-driver"), "-rpc", node.rpc_url,
             "-target", f"127.0.0.1:{node.approval_port}"], env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.log, text=True)
        try:
            self.initial = self.read()
        except BaseException:
            self.close()
            raise

    def read(self, timeout=30):
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            if not selector.select(timeout):
                raise TimeoutError("performance sender did not answer")
        line = self.process.stdout.readline()
        if not line:
            raise RuntimeError(f"performance sender exited: {self.process.poll()}")
        return json.loads(line)

    def send(self, op, **kwargs):
        self.process.stdin.write(json.dumps({"op": op, **kwargs}) + "\n")
        self.process.stdin.flush()

    def command(self, op, **kwargs):
        self.send(op, **kwargs)
        return self.read(timeout=kwargs.get("seconds", kwargs.get("timeout_seconds", 0)) + 30)["result"]

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.process.stdout.close()
        self.log.close()


class MemorySampler:
    """Resident memory for the owned node/driver process trees, including Java children."""
    def __init__(self, processes):
        self.processes = processes
        self.samples = []
        self.error = None
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        try:
            while not self.stop.is_set():
                rows = [list(map(int, line.split())) for line in subprocess.check_output(
                    ["ps", "-axo", "pid=,ppid=,rss="], text=True).splitlines()]
                sample = {"at_unix_ms": int(time.time() * 1000)}
                for name, process in list(self.processes.items()):
                    owned = {process.pid}
                    while True:
                        children = {pid for pid, parent, _ in rows if parent in owned}
                        if children <= owned:
                            break
                        owned.update(children)
                    sample[name + "_rss_bytes"] = sum(rss * 1024 for pid, _, rss in rows if pid in owned)
                self.samples.append(sample)
                self.stop.wait(1)
        except BaseException as error:
            self.error = str(error)

    def close(self):
        self.stop.set()
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise RuntimeError("memory sampler did not stop")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", choices=("besu", "reth"), required=True)
    parser.add_argument("--rate", type=int, default=5000)
    parser.add_argument("--seconds", type=float, default=60)
    parser.add_argument("--capacity", type=int, default=100000)
    parser.add_argument("--retain", type=int, default=100000)
    parser.add_argument("--ttl", default="10m")
    parser.add_argument("--warmup-seconds", type=float, default=10)
    parser.add_argument("--verify-workers", type=int, choices=range(1, 33))
    parser.add_argument("--restart", action="store_true")
    parser.add_argument("--recovery-seconds", type=float, default=20)
    parser.add_argument("--drain-seconds", type=float, default=30)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.rate <= 100000 or not 0 < args.seconds <= 600:
        parser.error("rate must be 1..100000 and seconds must be in (0,600]")
    if not 0 <= args.warmup_seconds <= 600 or not 0 < args.recovery_seconds <= 600:
        parser.error("warmup must be in [0,600] and recovery seconds in (0,600]")
    if not 0 < args.drain_seconds <= 120 or min(args.capacity, args.retain) < 1:
        parser.error("drain seconds must be in (0,120] and capacities must be positive")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    os.environ["OPS_EVIDENCE_DIR"] = str(output)
    os.environ["OPS_APPROVAL_CAPACITY"] = str(args.capacity)
    os.environ["OPS_APPROVAL_VERIFY_WORKERS"] = str(args.verify_workers or 2)
    os.environ.setdefault("OPS_RETH_BINARY", str(ROOT / ".tmp/approval-target/release/ops-reth-approvals-poc"))
    os.environ.setdefault("OPS_BESU_HOME", str(ROOT / ".tmp/besu-review-private"))
    sys.path.insert(0, str(ROOT / "poc" / f"{args.node}-signed-approvals"))
    import harness as h
    h.prepare()
    report = {"kind": "synthetic-approval-delivery", "node": args.node,
              "rate": args.rate, "seconds": args.seconds, "capacity": args.capacity,
              "retain": args.retain, "ttl": args.ttl, "phases": []}
    report["verify_workers"] = args.verify_workers or 2

    def new_node(name, port=None):
        options = {"approval_port": port}
        if args.node == "besu":
            options["capacity"] = args.capacity
            if args.verify_workers is not None:
                options["extra"] = ["--plugin-ops-approval-verify-workers", str(args.verify_workers)]
        return h.Node(name, **options)

    with contextlib.ExitStack() as stack:
        node = new_node("delivery-" + args.node)
        stack.callback(node.close)
        driver = stack.enter_context(contextlib.closing(Driver(node, output, args.node, args.retain, args.ttl)))
        processes = {"node": node.process, "sender": driver.process}
        sampler = stack.enter_context(contextlib.closing(MemorySampler(processes)))
        report["initial"] = driver.initial["snapshot"]
        try:
            if args.warmup_seconds:
                warmup = driver.command("run", rate=min(1000, args.rate), seconds=args.warmup_seconds)
                warm_drain = driver.command("wait", count=warmup["accepted"], timeout_seconds=30)
                report["warmup"] = {"run": warmup, "drain": warm_drain}
                if not warm_drain["reached"]:
                    raise RuntimeError("warmup approvals did not drain")
            before = driver.command("snapshot")
            run = driver.command("run", rate=args.rate, seconds=args.seconds)
            drained = driver.command("wait", count=int(metric(before, "confirmed_total")) + run["accepted"],
                                     timeout_seconds=args.drain_seconds)
            after = driver.command("snapshot")
            report["phases"].append({"name": "steady", "before": before, "run": run,
                                     "drain": drained, "after": after})
            print(json.dumps({"phase": "steady", **run, "drain": drained}), flush=True)
            if args.restart:
                tx = node.raw(h.ALICE, h.ADMIN, "0x", value=1, gas=21000)
                prepared = driver.command("prepare", raw_tx=tx["raw"])
                assert prepared["tx_hash"] == tx["hash"]
                probe_drain = driver.command("wait", count=int(metric(after, "confirmed_total")) + 1,
                                            timeout_seconds=30)
                if not probe_drain["reached"]:
                    raise RuntimeError("the real transaction's approval did not reach the original node")
                after = driver.command("snapshot")
                port = node.approval_port
                stopped = time.monotonic()
                node.close()
                node = new_node("delivery-" + args.node + "-restarted", port)
                stack.callback(node.close)
                processes["node"] = node.process
                restarted = time.monotonic()
                # Fresh traffic competes with recovery through OPS's ordinary priority lanes.
                driver.send("run", rate=args.rate, seconds=args.recovery_seconds)
                submitted_at = time.monotonic()
                assert node.rpc("eth_sendRawTransaction", tx["raw"]) == tx["hash"]
                node.make_block([tx])
                receipt = node.rpc("eth_getTransactionReceipt", tx["hash"])
                assert receipt and receipt["status"] == "0x1", receipt
                probe_seconds = time.monotonic() - submitted_at
                run = driver.read(timeout=args.recovery_seconds + 30)["result"]
                expected = int(metric(after, "confirmed_total") + metric(after, "retained")) + run["accepted"]
                drained = driver.command("wait", count=expected, timeout_seconds=args.drain_seconds)
                report["phases"].append({"name": "restart-with-fresh-traffic", "before": after,
                    "node_restart_seconds": restarted - stopped, "run": run, "drain": drained,
                    "after": driver.command("snapshot"),
                    "pending_probe": {"hash": tx["hash"], "receipt_status": receipt["status"],
                                      "submission_to_receipt_seconds": probe_seconds,
                                      "new_preflight_after_restart": False},
                    "confirmation_caveat": "counts include retries/duplicates; this is not proof of every hash's recovery"})
                print(json.dumps({"phase": "restart", **run, "drain": drained}), flush=True)
        except BaseException as error:
            report["error"] = str(error)
            raise
        finally:
            sampler.close()
            report["memory_samples"] = sampler.samples
            report["memory_sampling_error"] = sampler.error
            (output / "delivery.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
