#!/usr/bin/env python3
"""Build and exercise a real, isolated Reth node with signed preflight approvals."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / "go.mod").is_file())
SCRATCH = ROOT / ".tmp/approval-runs"
EVIDENCE = Path(os.environ.get("OPS_EVIDENCE_DIR",str(HERE / "evidence"))).resolve()
RETH_COMMIT = "5a6940e351fed80458fe6c9da8581cbe4b8bd036"
BINARY = Path(os.environ["OPS_RETH_BINARY"])
ZERO = "0x" + "00" * 32
ADMIN = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
ALICE = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"
# Public Anvil fixture keys; these accounts must never hold real assets.
KEYS = {
    ADMIN: "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    ALICE: "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
}
ROUTER, RELAY, VAULT_A, VAULT_B, POLICY, RUNNER = [
    "0x" + format(n, "040x") for n in (0x1100, 0x1200, 0x1300, 0x2300, 0x900, 0x901)
]


BENCH_ROUTER, BENCH_RELAY, BENCH_VAULT = ["0x" + format(n,"040x") for n in (0x3100,0x3200,0x3300)]

READ_ROUTER,READ_RELAY=["0x"+format(n,"040x") for n in (0x4100,0x4200)]
VALUE_ROUTER, VALUE_RECEIVER, LIFE_FACTORY, DESTRUCTIBLE = ["0x"+format(n,"040x") for n in (0x6100,0x6200,0x7100,0x7200)]

CALL_HASH_CASES, CALL_HASH_TOKEN = ["0x"+format(n,"040x") for n in (0x9100,0x9200)]

FINGERPRINT_CASES = "0x" + format(0x5100,"040x")

def command(args, **kwargs):
    return subprocess.check_output(args, cwd=HERE, text=True, **kwargs).strip()


def prepare():
    SCRATCH.mkdir(parents=True, exist_ok=True)
    EVIDENCE.mkdir(parents=True,exist_ok=True)
    checkout = ROOT / ".tmp/reth"
    assert command(["git", "-C", str(checkout), "rev-parse", "HEAD"]) == RETH_COMMIT
    assert not command(["git", "-C", str(checkout), "status", "--porcelain"]), "upstream Reth must remain unmodified"
    assert "Version: 0.8.35+" in command(["solc", "--version"])
    compiled = json.loads(command([
        "solc", "--optimize", "--optimize-runs", "200", "--evm-version", "shanghai",
        "--combined-json", "abi,bin,bin-runtime", "contracts/Applications.sol",
    ]))
    (EVIDENCE / "contracts.json").write_text(json.dumps(compiled, indent=2) + "\n")
    codes = {name.split(":")[-1]: "0x" + obj["bin-runtime"]
             for name, obj in compiled["contracts"].items()}
    alloc = {addr: {"balance": hex(10**24)} for addr in (ADMIN, ALICE)}
    for addr, name in [(ROUTER, "Router"), (RELAY, "Relay"), (VAULT_A, "Vault"),
                       (VAULT_B, "Vault"), (BENCH_ROUTER,"BenchRouter"), (BENCH_RELAY,"BenchRelay"), (BENCH_VAULT,"BenchVault"), (READ_ROUTER,"ReadRouter"), (READ_RELAY,"ReadRelay"), (FINGERPRINT_CASES,"FingerprintCases"), (VALUE_ROUTER,"ValueRouter"), (VALUE_RECEIVER,"ValueReceiver"), (LIFE_FACTORY,"LifeFactory"), (DESTRUCTIBLE,"Destructible"), (CALL_HASH_CASES,"CallHashCases"), (CALL_HASH_TOKEN,"CallHashToken")]:
        alloc[addr] = {"balance": "0x0", "nonce": "0x1", "code": codes[name]}
    alloc[RELAY]["storage"] = {ZERO: "0x" + format(int(VAULT_A, 16), "064x")}
    alloc[VALUE_ROUTER]["storage"] = {ZERO: "0x" + format(int(VALUE_RECEIVER,16),"064x")}
    alloc[DESTRUCTIBLE]["balance"] = hex(1000)
    alloc[DESTRUCTIBLE]["storage"] = {ZERO: "0x"+format(7,"064x")}
    genesis = {
        "config": {"chainId": 31337, "homesteadBlock": 0, "eip150Block": 0,
                   "eip155Block": 0, "eip158Block": 0, "byzantiumBlock": 0,
                   "constantinopleBlock": 0, "petersburgBlock": 0, "istanbulBlock": 0,
                   "berlinBlock": 0, "londonBlock": 0, "terminalTotalDifficulty": 0,
                   "terminalTotalDifficultyPassed": True, "shanghaiTime": 0},
        "nonce": "0x0", "timestamp": "0x0", "extraData": "0x", "gasLimit": "0x1c9c380",
        "difficulty": "0x0", "mixHash": ZERO, "coinbase": "0x" + "00" * 20,
        "baseFeePerGas": "0x3b9aca00", "alloc": alloc,
    }
    (EVIDENCE / "genesis.json").write_text(json.dumps(genesis, indent=2) + "\n")


def unused_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class Node:
    def __init__(self, name, disabled=False, wait_ms=5000, reverting_foreign=False, directory=None, fork="shanghai"):
        self.name = name
        self.fork = fork
        self.directory = Path(directory) if directory else Path(tempfile.mkdtemp(prefix=name + "-", dir=SCRATCH))
        self.log_path = self.directory / "node.log"
        self.stdout_path = self.directory / "node-stdout.log"
        self.rpc_url = "http://127.0.0.1:" + str(unused_port())
        self.engine_url = "http://127.0.0.1:" + str(unused_port())
        self.secret = bytes.fromhex("11" * 32)
        jwt_path = self.directory / "jwt.hex"
        jwt_path.write_text(self.secret.hex())
        self.records = []
        self.rpc_local = threading.local()
        self.rpc_connections = []
        self.rpc_connections_lock = threading.Lock()
        genesis_path = EVIDENCE / "genesis.json"
        if fork == "cancun":
            genesis=json.loads(genesis_path.read_text())
            genesis["config"]["cancunTime"]=0
            genesis.update(blobGasUsed="0x0", excessBlobGas="0x0", parentBeaconBlockRoot=ZERO)
            genesis_path=self.directory/"genesis.json"
            genesis_path.write_text(json.dumps(genesis))
        if reverting_foreign:
            genesis=json.loads(genesis_path.read_text())
            genesis["alloc"][VAULT_B]["code"]="0x60006000fd"
            genesis_path=self.directory/"genesis.json"
            genesis_path.write_text(json.dumps(genesis))
        self.log = self.log_path.open("w")
        self.stdout = self.stdout_path.open("w")
        args = [str(BINARY), "node", "--chain", str(genesis_path),
                "--datadir", str(self.directory / "data"), "--http", "--http.addr", "127.0.0.1",
                "--http.port", self.rpc_url.rsplit(":", 1)[1], "--http.api", "eth,debug,web3,net,txpool",
                "--authrpc.addr", "127.0.0.1", "--authrpc.port", self.engine_url.rsplit(":", 1)[1],
                "--authrpc.jwtsecret", str(jwt_path), "--ipcdisable", "--disable-discovery",
                "--addr", "127.0.0.1", "--port", "0", "--max-outbound-peers", "0",
                "--max-inbound-peers", "0", "--txpool.max-account-slots", "1024", "--log.stdout.format", "terminal",
                "--log.file.directory", str(self.directory / "logs")]
        if gas_limit := os.environ.get("OPS_POC_GAS_LIMIT"):
            args.extend(["--builder.gaslimit", str(int(gas_limit))])
        if connections := os.environ.get("OPS_POC_RPC_MAX_CONNECTIONS"):
            args.extend(["--rpc.max-connections", str(int(connections))])
        self.approval_port = unused_port()
        env = dict(os.environ, OPS_APPROVALS="0" if disabled else "1", RUST_LOG="info",
                   OPS_APPROVAL_WAIT_MS=str(wait_ms), OPS_APPROVAL_CHAIN_ID="31337",
                   OPS_APPROVAL_LISTEN=f"127.0.0.1:{self.approval_port}",
                   OPS_APPROVAL_PUBLIC_KEY="ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c")
        if os.environ.get("OPS_TRACE_HOPS")=="1":env["OPS_APPROVAL_HOPS_FILE"]=str(EVIDENCE/(name+"-node-hops.json"))
        # Keep module stderr records separate: Reth stdout can otherwise interleave
        # with JSON formatting and corrupt a timing record during concurrent writes.
        self.process = subprocess.Popen(args, cwd=ROOT, env=env, stdout=self.stdout, stderr=self.log,
                                        start_new_session=os.environ.get("OPS_POC_DETACH_CHILDREN") == "1")
        try:
            # Startup is outside all measured regions; allow slow local disk recovery.
            for _ in range(600):
                if self.process.poll() is not None:
                    raise RuntimeError((self.stdout_path.read_text() + self.log_path.read_text())[-8000:])
                try:
                    self.rpc("web3_clientVersion")
                    break
                except (OSError, urllib.error.URLError):
                    time.sleep(0.1)
            else:
                raise RuntimeError("Reth startup timed out")
            self.head = self.rpc("eth_getBlockByNumber", "latest", False)
            assert int(self.head["number"], 16) == 0
        except BaseException:
            self.close()
            raise

    def request(self, method, params, engine=False):
        headers = {"Content-Type": "application/json"}
        if engine:
            token = b64(b'{"alg":"HS256","typ":"JWT"}') + "." + b64(
                json.dumps({"iat": int(time.time())}).encode())
            headers["Authorization"] = "Bearer " + token + "." + b64(
                hmac.new(self.secret, token.encode(), hashlib.sha256).digest())
        body = json.dumps({"jsonrpc": "2.0", "id": len(self.records) + 1,
                           "method": method, "params": params}).encode()
        target = self.engine_url if engine else self.rpc_url
        if os.environ.get("OPS_POC_KEEPALIVE") == "1":
            if not hasattr(self.rpc_local, "connections"):
                self.rpc_local.connections = {}
            if target not in self.rpc_local.connections:
                connection = http.client.HTTPConnection(target.removeprefix("http://"), timeout=30)
                self.rpc_local.connections[target] = connection
                with self.rpc_connections_lock:
                    self.rpc_connections.append(connection)
            connection = self.rpc_local.connections[target]
            try:
                connection.request("POST", "/", body, headers)
                response = connection.getresponse()
                result = json.loads(response.read())
            except Exception:
                # A failed connect leaves HTTPConnection in Request-sent state.
                # Discard it for the caller's next attempt; never replay an
                # Engine mutation whose response might have been lost.
                connection.close()
                del self.rpc_local.connections[target]
                with self.rpc_connections_lock:
                    self.rpc_connections.remove(connection)
                raise
        else:
            req = urllib.request.Request(target, body, headers)
            with urllib.request.urlopen(req, timeout=30) as response:
                result = json.load(response)
        if os.environ.get("OPS_RECORD_RPC") == "1":
            self.records.append({"method": method, "params": params, "response": result})
        if "error" in result:
            raise RuntimeError(f"{method}: {result['error']}")
        return result["result"]

    def rpc(self, method, *params):
        return self.request(method, list(params))

    def engine(self, method, *params):
        return self.request(method, list(params), engine=True)

    def raw(self, sender, to, sig, *args, fee=2_000_000_000, nonce=None, gas=200000, legacy=True, value=0):
        if nonce is None:
            nonce = int(self.rpc("eth_getTransactionCount", sender, "latest"), 16)
        positional = [to, sig, *map(str,args)] if to else []
        raw = command(["cast", "mktx", *positional, "--value", str(value), "--private-key", KEYS[sender],
                       "--chain-id", "31337", "--nonce", str(nonce), "--gas-limit", str(gas),
                       *( ["--legacy"] if legacy else ["--priority-gas-price","1000000000"] ), "--gas-price", str(fee), "--rpc-url", self.rpc_url, *([] if to else ["--create",sig])])
        tx_hash = command(["cast", "keccak", raw])
        return {"hash": tx_hash, "sender": sender, "nonce": nonce, "raw": raw}

    def submit(self, tx):
        assert self.rpc("eth_sendRawTransaction", tx["raw"]) == tx["hash"]
        return tx

    def decisions(self):
        result = []
        for line in self.log_path.read_text().splitlines():
            if "OPS_APPROVAL_DECISION " in line:
                result.append(json.loads(line.split("OPS_APPROVAL_DECISION ", 1)[1]))
        return result

    def make_block(self, expected, denied=None, fee_recipient=ADMIN):
        number = int(self.head["number"], 16) + 1
        state = {"headBlockHash": self.head["hash"], "safeBlockHash": self.head["hash"],
                 "finalizedBlockHash": self.head["hash"]}
        attrs = {"timestamp": hex(int(self.head["timestamp"], 16) + 12), "prevRandao": ZERO,
                 "suggestedFeeRecipient": fee_recipient, "withdrawals": []}
        version = "V3" if self.fork == "cancun" else "V2"
        if self.fork == "cancun": attrs["parentBeaconBlockRoot"] = ZERO
        start = self.engine("engine_forkchoiceUpdated"+version, state, attrs)
        assert start["payloadStatus"]["status"] == "VALID", start
        payload_id = start["payloadId"]
        for _ in range(100):
            time.sleep(0.1)
            envelope = self.engine("engine_getPayload"+version, payload_id)
            payload = envelope["executionPayload"]
            includes = all(tx["raw"].lower() in [raw.lower() for raw in payload["transactions"]]
                           for tx in expected)
            veto_seen = denied is None or any(
                d["decision"] == "deny" and d["tx_hash"] == denied["hash"] for d in self.decisions())
            if includes and veto_seen:
                break
        else:
            raise AssertionError({"message": "candidate construction timed out", "payload": payload,
                                  "decisions": self.decisions()})
        assert len(payload["transactions"]) == len(expected), payload
        result = self.engine("engine_newPayload"+version, payload, *([[],ZERO] if self.fork == "cancun" else []))
        assert result["status"] == "VALID", result
        state = dict.fromkeys(state, payload["blockHash"])
        result = self.engine("engine_forkchoiceUpdated"+version, state, None)
        assert result["payloadStatus"]["status"] == "VALID", result
        for _ in range(100):
            self.head = self.rpc("eth_getBlockByNumber", "latest", False)
            if self.head["hash"] == payload["blockHash"]:
                break
            time.sleep(0.05)
        else:
            raise AssertionError("block did not become canonical")
        hashes = self.head["transactions"]
        assert hashes == [tx["hash"] for tx in expected], (hashes, expected)
        return payload

    def snapshot(self):
        return {
            "alice_nonce": int(self.rpc("eth_getTransactionCount", ALICE, "latest"), 16),
            "alice_balance": self.rpc("eth_getBalance", ALICE, "latest"),
            "router": [self.rpc("eth_getStorageAt", ROUTER, hex(i), "latest") for i in range(3)],
            "relay": [self.rpc("eth_getStorageAt", RELAY, hex(i), "latest") for i in range(3)],
            "vault_a": self.rpc("eth_getStorageAt", VAULT_A, "0x0", "latest"),
            "vault_b": self.rpc("eth_getStorageAt", VAULT_B, "0x0", "latest"),
        }

    def close(self):
        for connection in self.rpc_connections:
            connection.close()
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.log.close()
        self.stdout.close()
        shutil.copy2(self.log_path, EVIDENCE / (self.name + ".log"))
        shutil.copy2(self.stdout_path, EVIDENCE / (self.name + ".stdout.log"))
        (EVIDENCE / (self.name + "-rpc.json")).write_text(json.dumps(self.records, indent=2) + "\n")
