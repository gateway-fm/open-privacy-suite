#!/usr/bin/env python3
"""Headless Gasstorm loadgenerator -> real OPS -> Reth, isolated A/B runs."""
import argparse
import concurrent.futures
import contextlib
from datetime import datetime
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import statistics
import subprocess
import threading
import time
import urllib.parse

import harness as h
from demo import Stack, request
from run import machine_info, timings

LOADGEN_SOURCE = Path(os.environ.get("GASSTORM_LOADGEN_SOURCE", str(Path.home() / "work/software/loadgenerator")))
LOADGEN_BINARY = h.ROOT / ".tmp/gasstorm-loadgen"
WALLETS = {}


def save(name, value):
    (h.EVIDENCE / name).write_text(json.dumps(value, indent=2) + "\n")


def prepare():
    h.prepare()
    source = (LOADGEN_SOURCE / "internal/account/account.go").read_text()
    keys = re.findall(r'"([0-9a-f]{64})"', source.split("var TestPrivateKeys", 1)[1].split("}", 1)[0])
    assert len(keys) == 10
    for key in keys:
        address = h.command(["cast", "wallet", "address", "--private-key", key]).lower()
        WALLETS[address] = key
    h.KEYS.update(WALLETS)
    genesis = json.loads((h.EVIDENCE / "genesis.json").read_text())
    if gas_limit := os.environ.get("OPS_POC_GAS_LIMIT"):
        genesis["gasLimit"] = hex(int(gas_limit))
    for address in WALLETS:
        genesis["alloc"][address] = {"balance": hex(10**24)}
    save("genesis.json", genesis)


class GasstormStack(Stack):
    def __init__(self, name, disabled=False, ops_env=None):
        self.cached_contracts = {}
        self.rpc_local = threading.local()
        self.rpc_connections = []
        self.rpc_connections_lock = threading.Lock()
        super().__init__(name, disabled=disabled, ops_env={"MAX_CONCURRENT_REQUESTS": "5000", **(ops_env or {})})

    def rpc(self, method, params, sender=h.ALICE):
        return self._rpc(self.url + "/rpc/" + self.org, method, params, self.tokens[sender])

    def node_rpc(self, method, params):
        result = self._rpc(self.node.rpc_url, method, params)
        assert "error" not in result, result
        return result["result"]

    def _rpc(self, url, method, params, token=None):
        # Each verifier worker owns a persistent connection. One socket per
        # receipt exhausted macOS ephemeral ports in the initial large run.
        if not hasattr(self.rpc_local, "connections"):
            self.rpc_local.connections = {}
        target = urllib.parse.urlparse(url)
        if target.netloc not in self.rpc_local.connections:
            self.rpc_local.connections[target.netloc] = http.client.HTTPConnection(target.netloc, timeout=30)
            with self.rpc_connections_lock:
                self.rpc_connections.append(self.rpc_local.connections[target.netloc])
        connection = self.rpc_local.connections[target.netloc]
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        for attempt in range(2):
            try:
                connection.request("POST", target.path or "/", body, headers)
                response = connection.getresponse()
                result = json.loads(response.read())
                if response.status != 200:
                    result["http_status"] = response.status
                return result
            except (http.client.RemoteDisconnected, BrokenPipeError, ConnectionResetError):
                connection.close()
                if attempt or method == "eth_sendRawTransaction":
                    raise
            except Exception:
                # A read timeout leaves HTTPConnection in Request-sent state.
                # Drop it before the next independent call; never replay an
                # ambiguous submission merely because its response was lost.
                connection.close()
                del self.rpc_local.connections[target.netloc]
                with self.rpc_connections_lock:
                    self.rpc_connections.remove(connection)
                raise

    def close(self):
        for connection in self.rpc_connections:
            connection.close()
        super().close()

    def prepare_contracts(self, workload):
        """Deploy Gasstorm's own bytecode through OPS, outside measurement."""
        for name, filename, variable in [("ERC20", "erc20.go", "ERC20Bytecode"),
                                         ("GasConsumer", "compute.go", "GasConsumerBytecode"),
                                         ("NFT", "erc721.go", "NFTBytecode")]:
            source = (LOADGEN_SOURCE / "internal/txbuilder" / filename).read_text()
            literal = re.search(r'var ' + variable + r' = common.FromHex\([\s\S]*?"((?:0x)?[0-9a-fA-F]+)"', source)
            assert literal, variable
            bytecode = "0x" + literal[1].removeprefix("0x")
            tx = self.node.raw(h.ADMIN, None, bytecode, gas=3000000)
            assert self.submit(tx).get("result") == tx["hash"]
            self.node.make_block([tx])
            receipt = self.node.rpc("eth_getTransactionReceipt", tx["hash"])
            assert receipt["status"] == "0x1", receipt
            self.cached_contracts[name] = receipt["contractAddress"]
        if workload == "erc20-approve":
            # Initialize each allowance once. The measured approve workload is
            # idempotent, so this measures contract-path overhead without mixing
            # it with deliberately stale prestate approvals from a shared counter.
            for address in WALLETS:
                tx = self.node.raw(address, self.cached_contracts["ERC20"], "approve(address,uint256)", h.ADMIN, 2**256 - 1)
                assert self.submit(tx).get("result") == tx["hash"]
                self.node.make_block([tx])
                assert self.node.rpc("eth_getTransactionReceipt", tx["hash"])["status"] == "0x1"
        save(self.name + "-deployed-contracts.json", self.cached_contracts)

    def seed(self):
        self.org = self.admin("POST", "/orgs", {"slug": "loadtest", "name": "Load test"})["id"]
        self.foreign = self.admin("POST", "/orgs", {"slug": "foreign", "name": "Foreign org"})["id"]
        self.group = self.admin("POST", f"/orgs/{self.org}/groups", {"slug": "loadtest", "name": "Load test"})["id"]
        self.admin("PUT", f"/orgs/{self.org}/groups/{self.group}/access", {"claims": ["deploy"], "allowed_methods": ["*"]})
        did = "did:test:gasstorm-comparison"
        self.login(did)
        users = self.admin("GET", "/users?search=" + urllib.parse.quote(did))
        uid = next(u["id"] for u in users["data"] if u["external_id"] == did)
        self.admin("PUT", "/users/" + uid, {"kyc": True})
        for membership in self.admin("GET", f"/users/{uid}/memberships"):
            self.admin("DELETE", f"/users/{uid}/memberships/{membership['membership']['id']}")
        self.admin("POST", f"/users/{uid}/memberships", {"group_id": self.group})
        token = self.login(did)
        for address, key in WALLETS.items():
            self.tokens[address] = token
            challenge = request(self.url + "/api/v1/eth/link/challenge", "POST", {}, token)
            signature = h.command(["cast", "wallet", "sign", "--private-key", key, challenge["message"]])
            request(self.url + "/api/v1/eth/link/verify", "POST", {"nonce": challenge["nonce"], "address": address, "signature": signature}, token)
        addresses = [h.ROUTER, h.RELAY, h.VAULT_A]
        # Gasstorm deploys from its first standard wallet. Reserve only its
        # deterministic local test destinations, with explicit group grants.
        for nonce in range(6):
            addresses.append(h.command(["cast", "compute-address", h.ADMIN, "--nonce", str(nonce)]).split()[-1].lower())
        for address in addresses:
            self.admin("POST", f"/orgs/{self.org}/contracts", {"address": address, "name": "Gasstorm fixture " + address[-6:]})
            self.admin("POST", f"/orgs/{self.org}/contracts/{address}/grants", {"group_id": self.group})
        self.admin("POST", f"/orgs/{self.foreign}/contracts", {"address": h.VAULT_B, "name": "Foreign vault"})
        save(self.name + "-configuration.json", {"org": self.org, "foreign_org": self.foreign, "group": self.group,
             "DID": did, "wallets": list(WALLETS), "contracts": addresses, "claims": ["deploy"],
             "allowed_methods": ["*"], "RPC_route": self.url + "/rpc/" + self.org, "module": not self.disabled,
             "MAX_CONCURRENT_REQUESTS": 5000, "DB_MAX_OPEN_CONNS": 30})


class Miner:
    """Clock-driven Engine API scheduling; real Reth builds and validates blocks."""
    def __init__(self, node, interval=1.0, realtime=False):
        self.node = node
        self.interval = interval
        self.realtime = realtime
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
                state = dict.fromkeys(["headBlockHash", "safeBlockHash", "finalizedBlockHash"], n.head["hash"])
                timestamp = int(n.head["timestamp"], 16) + 1
                if self.realtime:
                    timestamp = max(timestamp, int(time.time()))
                attrs = {"timestamp": hex(timestamp), "prevRandao": h.ZERO,
                         "suggestedFeeRecipient": h.ADMIN, "withdrawals": []}
                answer = n.engine("engine_forkchoiceUpdatedV2", state, attrs)
                assert answer["payloadStatus"]["status"] == "VALID", answer
                if self.stop.wait(.1):
                    break
                payload = n.engine("engine_getPayloadV2", answer["payloadId"])["executionPayload"]
                answer = n.engine("engine_newPayloadV2", payload)
                assert answer["status"] == "VALID", answer
                answer = n.engine("engine_forkchoiceUpdatedV2", dict.fromkeys(state, payload["blockHash"]), None)
                assert answer["payloadStatus"]["status"] == "VALID", answer
                n.head = n.rpc("eth_getBlockByNumber", payload["blockNumber"], False)
                assert n.head["hash"] == payload["blockHash"]
                self.blocks.append({"at": time.time(), "number": int(payload["blockNumber"], 16), "hash": payload["blockHash"],
                                    "transactions": n.head["transactions"], "gas_used": int(payload["gasUsed"], 16)})
                self.stop.wait(max(0, self.interval - (time.monotonic() - started)))
        except BaseException as error:
            self.error = error

    def restart(self):
        if self.thread.is_alive():
            raise RuntimeError("Block driver has not finished stopping")
        # Reconcile the canonical head after an ambiguous Engine timeout. Do not
        # replay the timed-out mutation; begin a new build from observed state.
        self.node.head = self.node.rpc("eth_getBlockByNumber", "latest", False)
        self.error = None
        self.stop.clear()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def check(self):
        if self.error:
            raise self.error

    def close(self):
        self.stop.set()
        self.thread.join(timeout=35)
        assert not self.thread.is_alive(), "miner did not stop"
        save(self.node.name + "-blocks.json", self.blocks)
        self.check()


class Loadgen:
    def __init__(self, stack):
        self.stack = stack
        self.url = "http://127.0.0.1:" + str(h.unused_port())
        token = stack.directory / "loadgen-token"
        self.token_path = token
        token.write_text(stack.tokens[h.ADMIN]); token.chmod(0o600)
        env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "TMPDIR", "LANG")}
        env.update(PRIVACY_RPC_URL=stack.url, PRIVACY_ORG_ID=stack.org, PRIVACY_ROUTE_ALL="true",
                   PRIVACY_AUTH_TOKEN_FILE=str(token), EXECUTION_LAYER="reth-ext-native", PRECONF_WS_URL="",
                   BUILDER_RPC_URL=stack.url + "/rpc/" + stack.org, L2_RPC_URL=stack.url + "/rpc/" + stack.org,
                   GAS_TIP_CAP="1000000", GAS_FEE_CAP="3000000000", BLOCK_TIME_MS="1000",
                   LOG_LEVEL=os.environ.get("OPS_POC_LOADGEN_LOG_LEVEL", "info"))
        self.log = (stack.directory / "loadgen.log").open("w")
        self.process = subprocess.Popen([str(LOADGEN_BINARY), "-listen", self.url.removeprefix("http://"),
                                        "-chainid", "31337", "-gasprice", "2000000000", "-database", str(stack.directory / "loadgen.db")],
                                       cwd=stack.directory, env=env, stdout=self.log, stderr=subprocess.STDOUT,
                                       start_new_session=os.environ.get("OPS_POC_DETACH_CHILDREN") == "1")
        for _ in range(200):
            if self.process.poll() is not None:
                raise RuntimeError((stack.directory / "loadgen.log").read_text()[-4000:])
            try:
                request(self.url + "/health"); break
            except (OSError, RuntimeError):
                time.sleep(.1)
        else:
            raise RuntimeError("loadgen did not start")
        if stack.cached_contracts:
            # Use Gasstorm's existing contract-cache mechanism, populated only
            # with the real deployments above. Gasstorm rechecks on-chain code.
            with sqlite3.connect(stack.directory / "loadgen.db") as db:
                db.executemany("INSERT OR REPLACE INTO cached_contracts (name,address,chain_id,created_at) VALUES (?,?,31337,CURRENT_TIMESTAMP)",
                               stack.cached_contracts.items())

    def test(self, miner, workload, rate, duration, label):
        config = {"pattern": "constant", "durationSec": duration, "constantRate": rate,
                  "numAccounts": 10, "transactionType": workload, "privacyMode": True}
        before = int(self.stack.node.rpc("eth_blockNumber"), 16)
        start = time.time()
        answer = request(self.url + "/start", "POST", config)
        assert answer["status"] == "started", answer
        samples = []
        deadline = time.monotonic() + duration + 240
        previous = None
        while time.monotonic() < deadline:
            miner.check()
            status = request(self.url + "/status")
            samples.append({"at": time.time(), **status})
            state = status["status"]
            if state != previous:
                print("STATE", self.stack.name, label, state, status.get("initProgress", ""), status.get("error", ""), flush=True)
                previous = state
            if state in ("completed", "error"):
                break
            time.sleep(.5)
        else:
            raise AssertionError("loadgen timed out: " + json.dumps(samples[-1]))
        save(self.stack.name + "-" + label + "-status.json", samples)
        assert status["status"] == "completed", status
        history = request(self.url + "/history?limit=1")
        save(self.stack.name + "-" + label + "-history.json", history)
        run = history["runs"][0]
        assert run["config"] == config, (run["config"], config)
        logs = []
        logs_deadline = time.monotonic() + 30
        while True:
            page = request(self.url + f"/history/{run['id']}/transactions?limit=1000&offset={len(logs)}")
            # Gasstorm sets completed before its asynchronous SQLite log
            # transaction commits. Wait for that atomic commit, not a fixed sleep.
            if not logs and not page.get("transactions") and status["txSent"]:
                assert time.monotonic() < logs_deadline, "Gasstorm completed without persisting transaction logs"
                time.sleep(.1)
                continue
            logs.extend(page.get("transactions") or [])
            if len(logs) >= page["total"]:
                break
            assert page["transactions"], "transaction log pagination stalled"
        save(self.stack.name + "-" + label + "-transactions.json", logs)
        # Verify every generated hash using OPS's normal receipt endpoint.
        # This is outside the timed sending phase and does not trust Gasstorm's
        # confirmed/onChain counters, which use different end-of-test windows.
        by_hash = {tx["txHash"].lower(): tx for tx in logs}
        def receipt(tx_hash):
            response = self.stack.rpc("eth_getTransactionReceipt", [tx_hash], h.ADMIN)
            assert "error" not in response, response
            r = response["result"]
            return {"hash": tx_hash, "receipt": None if r is None else {
                k: r.get(k) for k in ["transactionHash", "status", "blockHash", "blockNumber", "gasUsed", "effectiveGasPrice"]}}
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            receipts = list(pool.map(receipt, by_hash))
        save(self.stack.name + "-" + label + "-receipts.json", receipts)
        committed = [r for r in receipts if r["receipt"] is not None]
        missing = [r["hash"] for r in receipts if r["receipt"] is None]
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            missing_node = list(pool.map(lambda tx: self.stack.node_rpc("eth_getTransactionByHash", [tx]), missing))
        successful = [r for r in committed if r["receipt"]["status"] == "0x1"]
        canonical = {b["hash"].lower(): b for b in miner.blocks}
        for row in committed:
            r = row["receipt"]
            assert r["transactionHash"].lower() == row["hash"]
            assert row["hash"] in canonical[r["blockHash"].lower()]["transactions"], row
        started_at = datetime.fromisoformat(run["startedAt"]).timestamp()
        within_window = sum(canonical[r["receipt"]["blockHash"].lower()]["at"] <= started_at + duration for r in successful)
        # Both timestamps use this host's wall clock. This includes Gasstorm's
        # own local batching, OPS and block scheduling, not just RPC latency.
        latencies = sorted((canonical[r["receipt"]["blockHash"].lower()]["at"] * 1000 - by_hash[r["hash"]]["sentAtMs"]) for r in successful)
        summary = {"logged_hashes": len(by_hash), "gasstorm_sent": status["txSent"], "gasstorm_failed": status["txFailed"],
                   "successful_receipts": len(successful), "reverted_receipts": len(committed) - len(successful),
                   "without_receipt": len(receipts) - len(committed), "settled_successes_per_sending_second": len(successful) / duration,
                   "missing_but_in_pool": sum(tx is not None for tx in missing_node),
                   "missing_and_unknown_to_node": sum(tx is None for tx in missing_node),
                   "committed_during_sending": within_window, "committed_during_sending_tps": within_window / duration,
                   "queue_to_commit_p50_ms": statistics.median(latencies) if latencies else None,
                   "queue_to_commit_p95_ms": latencies[int(.95 * (len(latencies) - 1))] if latencies else None}
        assert len(by_hash) > 0 and len(successful) > 0, summary
        after = int(self.stack.node.rpc("eth_blockNumber"), 16)
        result = {"label": label, "module": not self.stack.disabled, "config": config,
                  "wall_seconds_including_initialization_and_verification": time.time() - start,
                  "first_block_exclusive": before, "last_block": after, "metrics": status,
                  "history": history, "receipt_summary": summary,
                  "canonical_blocks": [b for b in miner.blocks if before < b["number"] <= after]}
        save(self.stack.name + "-" + label + ".json", result)
        print("RESULT", self.stack.name, label, json.dumps(summary), flush=True)
        return result

    def close(self):
        self.process.terminate()
        try:
            self.process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.process.kill(); self.process.wait(timeout=5)
        self.log.close()
        shutil.copy2(self.stack.directory / "loadgen.log", h.EVIDENCE / (self.stack.name + "-loadgen.log"))
        # SQLite WAL contents are part of the DB: copying only the .db file
        # can produce an empty artifact. Backup includes the complete snapshot.
        with sqlite3.connect(self.stack.directory / "loadgen.db") as source:
            with sqlite3.connect(h.EVIDENCE / (self.stack.name + "-loadgen.db")) as destination:
                source.backup(destination)


def safety():
    results = []
    for enabled in (False, True):
        with contextlib.closing(GasstormStack("gasstorm-safety-" + str(int(enabled)), disabled=not enabled)) as s:
            n = s.node
            forbidden = n.raw(h.ALICE, h.ROUTER, "runDelegate(address,uint256)", h.VAULT_B, 7)
            assert "error" in s.submit(forbidden)
            stale = n.raw(h.ALICE, h.ROUTER, "run(uint256)", 9)
            assert s.submit(stale).get("result") == stale["hash"]
            mutation = n.raw(h.ADMIN, h.RELAY, "setTarget(address)", h.VAULT_B, fee=4000000000)
            assert s.submit(mutation).get("result") == mutation["hash"]
            before = n.snapshot()
            n.make_block([mutation] if enabled else [mutation, stale], denied=stale if enabled else None)
            after = n.snapshot()
            receipt = n.rpc("eth_getTransactionReceipt", stale["hash"])
            if enabled:
                assert receipt is None
                for key in ["alice_nonce", "alice_balance", "router", "vault_a", "vault_b"]:
                    assert before[key] == after[key], (key, before, after)
            else:
                assert receipt["status"] == "0x1"
                assert after["alice_nonce"] == before["alice_nonce"] + 1
                assert after["vault_b"] != before["vault_b"]
            results.append({"module": enabled, "preflight_approved": True, "receipt": receipt,
                            "before": before, "after": after, "decisions": n.decisions()})
            save("safety.json", results)
            print("PASS safety", "state divergence excluded" if enabled else "baseline executes stale cross-org approval", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["safety", "pilot", "compare"])
    parser.add_argument("--rates", default="100,500,1000")
    parser.add_argument("--duration", type=int, default=20)
    parser.add_argument("--pairs", type=int, default=2)
    parser.add_argument("--workload", default="eth-transfer")
    parser.add_argument("--resume", action="store_true", help="Keep complete mode/pair groups; repeat an interrupted group")
    args = parser.parse_args()
    prepare()
    if args.mode == "safety":
        safety(); return
    results_file = h.EVIDENCE / "runs.json"
    results = json.loads(results_file.read_text()) if args.resume and results_file.exists() else []
    rates = [20] if args.mode == "pilot" else [int(r) for r in args.rates.split(",")]
    pairs = 1 if args.mode == "pilot" else args.pairs
    duration = 5 if args.mode == "pilot" else args.duration
    for pair in range(pairs):
        for enabled in ((False, True) if pair % 2 == 0 else (True, False)):
            name = f"gasstorm-{args.workload}-{pair}-{int(enabled)}"
            complete = [r for r in results if r["pair"] == pair and r["module"] == enabled]
            if args.resume and {r["config"]["constantRate"] for r in complete} == set(rates):
                assert all(r["config"]["durationSec"] == duration and r["config"]["transactionType"] == args.workload for r in complete)
                print("REUSE complete group", name, flush=True)
                continue
            if args.resume and complete:
                backup = h.EVIDENCE / ("superseded-" + name + "-" + str(time.time_ns()))
                backup.mkdir()
                for old in h.EVIDENCE.glob(name + "-*"):
                    shutil.move(str(old), backup / old.name)
                results = [r for r in results if not (r["pair"] == pair and r["module"] == enabled)]
                save("runs.json", results)
            with contextlib.closing(GasstormStack(name, disabled=not enabled)) as stack:
                if args.workload != "eth-transfer":
                    stack.prepare_contracts(args.workload)
                with contextlib.closing(Miner(stack.node)) as miner:
                    with contextlib.closing(Loadgen(stack)) as loadgen:
                        if args.mode != "pilot":
                            loadgen.test(miner, args.workload, 20, 5, "warmup")
                        for rate in rates:
                            result = loadgen.test(miner, args.workload, rate, duration, str(rate))
                            result["pair"] = pair
                            results.append(result)
                            save("runs.json", results)
                save(name + "-reth-timings.json", timings(stack.node))
    save("manifest.json", {"hardware": machine_info(), "loadgen_source": str(LOADGEN_SOURCE),
                           "loadgen_commit": subprocess.check_output(["git", "-C", str(LOADGEN_SOURCE), "rev-parse", "HEAD"], text=True).strip(),
                           "loadgen_binary_sha256": hashlib.sha256(LOADGEN_BINARY.read_bytes()).hexdigest(),
                           "reth_commit": h.RETH_COMMIT, "runs": len(results), "arguments": vars(args)})


if __name__ == "__main__":
    main()
