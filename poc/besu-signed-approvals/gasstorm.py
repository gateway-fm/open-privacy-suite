#!/usr/bin/env python3
"""Sustained load: Gasstorm's load generator -> real OPS -> Besu with the approval gate.

The same A/B the Reth PoC runs: one isolated stack per configuration, a clock-driven block producer
at the chain's cadence, and the generator driving a constant rate through OPS's JSON-RPC route. What
is counted at the end is successful receipts on chain, not what the generator believes it sent.
"""
import argparse
import contextlib
import json
import os
from pathlib import Path
import re
import sqlite3
import statistics
import subprocess
import threading
import time

import harness as h
from demo import Stack, request

LOADGEN_SOURCE = Path(os.environ.get("GASSTORM_LOADGEN_SOURCE", "<loadgenerator>"))
LOADGEN_BINARY = h.ROOT / ".tmp/gasstorm-loadgen"
EVIDENCE = h.EVIDENCE / "gasstorm"
WALLETS = {}


def save(name, value):
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    (EVIDENCE / name).write_text(json.dumps(value, indent=2) + "\n")


def prepare():
    """Fund the generator's ten standard wallets in the genesis and build its binary."""
    h.prepare()
    source = (LOADGEN_SOURCE / "internal/account/account.go").read_text()
    keys = re.findall(r'"([0-9a-f]{64})"', source.split("var TestPrivateKeys", 1)[1].split("}", 1)[0])
    assert len(keys) == 10, f"expected ten test keys, found {len(keys)}"
    for key in keys:
        WALLETS[h.command(["cast", "wallet", "address", "--private-key", key]).lower()] = key
    h.KEYS.update(WALLETS)
    genesis = json.loads((h.EVIDENCE / "genesis.json").read_text())
    for address in WALLETS:
        genesis["alloc"][address] = {"balance": hex(10**24)}
    (h.EVIDENCE / "genesis.json").write_text(json.dumps(genesis, indent=2) + "\n")
    if not LOADGEN_BINARY.is_file():
        subprocess.check_call(["go", "build", "-o", str(LOADGEN_BINARY), "./cmd/loadgen"], cwd=LOADGEN_SOURCE)


class LoadStack(Stack):
    """The demo stack, seeded for ten wallets under one identity and a higher request ceiling."""

    def __init__(self, name, plugin=True):
        self.extra_env = {"MAX_CONCURRENT_REQUESTS": "5000"}
        super().__init__(name, plugin=plugin)

    def seed(self):
        self.org = self.admin("POST", "/orgs", {"slug": "loadtest", "name": "Load test"})["id"]
        self.foreign = self.admin("POST", "/orgs", {"slug": "foreign", "name": "Foreign org"})["id"]
        self.group = self.admin("POST", f"/orgs/{self.org}/groups",
                                {"slug": "loadtest", "name": "Load test"})["id"]
        self.admin("PUT", f"/orgs/{self.org}/groups/{self.group}/access",
                   {"claims": ["deploy"], "allowed_methods": ["*"]})
        did = "did:test:besu-gasstorm"
        self.login(did)
        import urllib.parse
        users = self.admin("GET", "/users?search=" + urllib.parse.quote(did))
        users = users if isinstance(users, list) else users["data"]
        uid = next(u["id"] for u in users if u["external_id"] == did)
        self.admin("PUT", "/users/" + uid, {"kyc": True})
        for membership in self.admin("GET", f"/users/{uid}/memberships"):
            self.admin("DELETE", f"/users/{uid}/memberships/{membership['membership']['id']}")
        self.admin("POST", f"/users/{uid}/memberships", {"group_id": self.group})
        token = self.login(did)
        for address, key in WALLETS.items():
            self.tokens[address] = token
            challenge = request(self.url + "/api/v1/eth/link/challenge", "POST", {}, token)
            signature = h.command(["cast", "wallet", "sign", "--private-key", key, challenge["message"]])
            request(self.url + "/api/v1/eth/link/verify", "POST",
                    {"nonce": challenge["nonce"], "address": address, "signature": signature}, token)
        self.tokens[h.ADMIN] = token
        self.tokens[h.ALICE] = token
        addresses = [h.ROUTER, h.RELAY, h.VAULT_A]
        # The generator deploys its own contracts from its first wallet; reserve those addresses.
        first = next(iter(WALLETS))
        for nonce in range(6):
            addresses.append(
                h.command(["cast", "compute-address", first, "--nonce", str(nonce)]).split()[-1].lower())
        for address in addresses:
            self.admin("POST", f"/orgs/{self.org}/contracts",
                       {"address": address, "name": "Gasstorm " + address[-6:]})
            self.admin("POST", f"/orgs/{self.org}/contracts/{address}/grants", {"group_id": self.group})
        save(self.name + "-configuration.json",
             {"org": self.org, "group": self.group, "did": did, "wallets": list(WALLETS),
              "contracts": addresses, "gate": self.plugin, "rpc_route": self.url + "/rpc/" + self.org})


class Miner:
    """Builds a block every `interval` seconds through the Engine API, like a consensus client."""

    def __init__(self, node, interval=1.0):
        self.node = node
        self.interval = interval
        self.stop = threading.Event()
        self.error = None
        self.blocks = []
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        n = self.node
        try:
            while not self.stop.is_set():
                started = time.monotonic()
                state = dict.fromkeys(
                    ["headBlockHash", "safeBlockHash", "finalizedBlockHash"], n.head["hash"])
                attrs = {"timestamp": hex(max(int(n.head["timestamp"], 16) + 1, int(time.time()))),
                         "prevRandao": h.ZERO, "suggestedFeeRecipient": h.ADMIN, "withdrawals": []}
                answer = n.engine("engine_forkchoiceUpdatedV2", state, attrs)
                assert answer["payloadStatus"]["status"] == "VALID", answer
                if self.stop.wait(max(0.2, self.interval * 0.8)):
                    break
                payload = n.engine("engine_getPayloadV2", answer["payloadId"])["executionPayload"]
                answer = n.engine("engine_newPayloadV2", payload)
                assert answer["status"] == "VALID", answer
                answer = n.engine("engine_forkchoiceUpdatedV2",
                                  dict.fromkeys(state, payload["blockHash"]), None)
                assert answer["payloadStatus"]["status"] == "VALID", answer
                n.head = n.rpc("eth_getBlockByNumber", payload["blockNumber"], False)
                self.blocks.append({"at": time.time(), "number": int(payload["blockNumber"], 16),
                                    "transactions": len(payload["transactions"]),
                                    "gas_used": int(payload["gasUsed"], 16)})
                self.stop.wait(max(0, self.interval - (time.monotonic() - started)))
        except BaseException as error:  # reported by check(), never swallowed
            self.error = error

    def check(self):
        if self.error:
            raise self.error

    def close(self, name):
        self.stop.set()
        self.thread.join(timeout=120)
        assert not self.thread.is_alive(), "the block producer did not stop"
        save(name + "-blocks.json", self.blocks)
        self.check()


class Loadgen:
    """Gasstorm's generator, pointed at OPS: it signs and submits, OPS authorizes, Besu includes."""

    def __init__(self, stack):
        self.stack = stack
        self.url = "http://127.0.0.1:" + str(h.unused_port())
        token = stack.directory / "loadgen-token"
        token.write_text(stack.tokens[next(iter(WALLETS))])
        token.chmod(0o600)
        env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "TMPDIR", "LANG")}
        env.update(PRIVACY_RPC_URL=stack.url, PRIVACY_ORG_ID=stack.org, PRIVACY_ROUTE_ALL="true",
                   PRIVACY_AUTH_TOKEN_FILE=str(token), EXECUTION_LAYER="gravity-reth",
                   PRECONF_WS_URL="", BUILDER_RPC_URL=stack.url + "/rpc/" + stack.org,
                   L2_RPC_URL=stack.url + "/rpc/" + stack.org, GAS_TIP_CAP="1000000",
                   GAS_FEE_CAP="3000000000", BLOCK_TIME_MS="1000", LOG_LEVEL="info")
        self.log = (stack.directory / "loadgen.log").open("w")
        self.database = stack.directory / "loadgen.db"
        self.process = subprocess.Popen(
            [str(LOADGEN_BINARY), "-listen", self.url.removeprefix("http://"), "-chainid", "31337",
             "-gasprice", "2000000000", "-database", str(self.database)],
            cwd=stack.directory, env=env, stdout=self.log, stderr=subprocess.STDOUT)
        for _ in range(300):
            if self.process.poll() is not None:
                raise RuntimeError((stack.directory / "loadgen.log").read_text()[-4000:])
            try:
                request(self.url + "/health")
                break
            except (OSError, RuntimeError):
                time.sleep(0.1)
        else:
            raise RuntimeError("the load generator did not start")

    def run(self, miner, workload, rate, duration, label):
        config = {"pattern": "constant", "durationSec": duration, "constantRate": rate,
                  "numAccounts": len(WALLETS), "transactionType": workload, "privacyMode": True}
        answer = request(self.url + "/start", "POST", config)
        assert answer["status"] == "started", answer
        deadline = time.monotonic() + duration + 300
        previous = None
        while time.monotonic() < deadline:
            miner.check()
            status = request(self.url + "/status")
            if status["status"] != previous:
                print("   ", self.stack.name, label, status["status"],
                      status.get("initProgress", ""), status.get("error", ""), flush=True)
                previous = status["status"]
            if status["status"] in ("completed", "error"):
                break
            time.sleep(0.5)
        else:
            raise AssertionError("the load generator did not finish")
        assert status["status"] == "completed", status
        run = request(self.url + "/history?limit=1")["runs"][0]
        hashes = []
        while True:
            page = request(self.url + f"/history/{run['id']}/transactions?limit=1000&offset={len(hashes)}")
            rows = page.get("transactions", page if isinstance(page, list) else [])
            if not rows:
                break
            hashes.extend(row["txHash"] for row in rows if row.get("txHash"))
            if len(rows) < 1000:
                break
        save(f"{self.stack.name}-{label}-run.json", run)
        return run, hashes

    def close(self):
        self.process.terminate()
        try:
            self.process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.process.kill()
        self.log.close()


def confirmed(node, hashes):
    """Receipts on chain, one per transaction: the strongest evidence the run actually landed."""
    successful = failed = missing = 0
    for tx in hashes:
        receipt = node.receipt(tx)
        if receipt is None:
            missing += 1
        elif receipt["status"] == "0x1":
            successful += 1
        else:
            failed += 1
    return successful, failed, missing


def compare(workload, rates, duration, interval):
    results = []
    for plugin in (False, True):
        name = ("gate-on" if plugin else "gate-off")
        with contextlib.closing(LoadStack(name, plugin=plugin)) as stack:
            miner = Miner(stack.node, interval=interval)
            loadgen = Loadgen(stack)
            try:
                for rate in rates:
                    label = f"{workload}-{rate}"
                    print(f"\n{name}: {workload} at {rate} tx/s for {duration}s", flush=True)
                    started = time.time()
                    run, hashes = loadgen.run(miner, workload, rate, duration, label)
                    # Let the last submissions reach a block, then stop the clock: the receipt scan
                    # that follows is verification, not part of the run.
                    time.sleep(interval * 3)
                    window = time.time() - started
                    ok, failed, missing = confirmed(stack.node, hashes)
                    row = {"gate": plugin, "workload": workload, "requested_rate": rate,
                           "duration_s": duration, "submitted": len(hashes),
                           "confirmed": ok, "reverted": failed, "no_receipt": missing,
                           # Over the whole window, from the first submission to the last block,
                           # not over the nominal duration: the generator often needs longer.
                           "confirmed_tps": round(ok / window, 1),
                           "blocks": len([b for b in miner.blocks if b["at"] >= started]),
                           "generator_report": {k: run.get(k) for k in
                                                ("txSent", "txConfirmed", "txFailed", "txDiscarded",
                                                 "averageTps", "peakTps", "onChainTps", "onChainTxCount")},
                           "window_s": round(window, 1)}
                    if plugin:
                        gate = [t["gate_ns"] for t in stack.node.timings()]
                        row["gate_us_per_tx_median"] = round(statistics.median(gate) / 1000, 1) if gate else None
                    results.append(row)
                    print("RESULT", json.dumps(row), flush=True)
            finally:
                loadgen.close()
                miner.close(name)
    summary = {"machine": subprocess.check_output(["uname", "-sm"], text=True).strip(),
               "block_interval_s": interval, "workload": workload, "rates": rates,
               "duration_s": duration, "results": results,
               "note": "confirmed = successful receipts on chain; the generator, OPS, PostgreSQL, "
                       "Redis and Besu all run on this one machine"}
    save("summary.json", summary)
    print("\nSUMMARY", json.dumps(summary["results"], indent=2), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workload", default="eth-transfer")
    parser.add_argument("--rates", default="100,300", help="comma-separated target rates")
    parser.add_argument("--duration", type=int, default=20)
    parser.add_argument("--block-interval", type=float, default=1.0)
    args = parser.parse_args()
    prepare()
    compare(args.workload, [int(r) for r in args.rates.split(",")], args.duration, args.block_interval)


if __name__ == "__main__":
    main()
