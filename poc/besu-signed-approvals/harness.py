#!/usr/bin/env python3
"""Run a real, isolated Besu 26.8.1 producer with the OPS approval plugin.

Besu 26.x has no Clique block production: the node runs as a post-merge execution client and this
harness plays the consensus client over the Engine API, as Maru does in Lineth.
"""
import base64
import contextlib
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / "go.mod").is_file())
EVIDENCE = Path(os.environ.get("OPS_EVIDENCE_DIR", str(HERE / "evidence"))).resolve()
SCRATCH = ROOT / ".tmp/besu-approval-runs"
BESU_HOME = Path(os.environ.get("OPS_BESU_HOME", str(ROOT / ".tmp/besu-dist/besu-26.8.1")))
# The Lineth distribution (linea-besu-package v2.2.0): its own Besu build plus the Linea plugins.
LINEA_HOME = Path(os.environ.get("OPS_LINEA_BESU_HOME", str(ROOT / ".tmp/linea-pkg/linea-besu/package/linea-besu/besu")))
# Lineth plugin names: the pool validator works on any chain, the sequencer's selector additionally
# needs its ZK line-counting tracer, which only supports the Osaka fork.
LINEA_POOL_PLUGIN = "LineaTransactionPoolValidatorPlugin"
LINEA_SELECTOR_PLUGIN = "LineaTransactionSelectorPlugin"
LINEA_SELECTOR_OPTIONS = [
    "--plugin-linea-deny-list-path", str(LINEA_HOME.parent / "config/denylist.sepolia.txt"),
    "--plugin-linea-module-limit-file-path", str(LINEA_HOME.parent / "config/trace-limits.sepolia.toml"),
    "--plugin-linea-l1l2-bridge-contract", "0x33bf916373159A8c1b54b025202517BfDbB7863D",
    "--plugin-linea-l1l2-bridge-topic", "e856c2b8bd4eb0027ce32eeaf595c21b0b6b4644b326e5b7bd80a1cf8db72e6c",
    "--plugin-linea-fixed-gas-cost-wei", "0",
    "--plugin-linea-variable-gas-cost-wei", "0",
    "--plugin-linea-min-margin", "0.0",
]
JAVA_HOME = Path(os.environ.get("OPS_JAVA_HOME", str(next(iter(sorted((ROOT / ".tmp/jdk25").glob("jdk-25*"))), Path("/nonexistent")) / "Contents/Home")))
PLUGIN_JAR = HERE / "build/libs/ops-besu-approvals.jar"
CLIENT = ROOT / ".tmp/besu-approval-client"
CHAIN_ID = 31337
ZERO = "0x" + "00" * 32
ADMIN = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
ALICE = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"
# Public Anvil fixture keys; these accounts must never hold real assets.
KEYS = {
    ADMIN: "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    ALICE: "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
}
# ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)) — the Go client's fixture signer.
APPROVAL_PUBLIC_KEY = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"
ROUTER, RELAY, VAULT_A, VAULT_B = ["0x" + format(n, "040x") for n in (0x1100, 0x1200, 0x1300, 0x2300)]
CALL_HASH_CASES, CALL_HASH_TOKEN = ["0x" + format(n, "040x") for n in (0x9100, 0x9200)]
LIFE_FACTORY, DESTRUCTIBLE = ["0x" + format(n, "040x") for n in (0x7100, 0x7200)]
VALUE_ROUTER, VALUE_RECEIVER = ["0x" + format(n, "040x") for n in (0x6100, 0x6200)]


def command(args, **kwargs):
    return subprocess.check_output(args, cwd=HERE, text=True, **kwargs).strip()


CREATION_CODE = {}


def osaka_genesis():
    """Our fixtures on an Osaka chain: Lineth's ZK line-counting tracer supports no earlier fork.

    The fork config and the Prague/Osaka system contracts come from Besu's own Osaka
    acceptance-test genesis (evidence/besu-osaka-reference-genesis.json, taken from the pinned Besu
    commit); only osakaTime moves to 0 so the chain is Osaka from the first block.
    """
    reference = json.loads((EVIDENCE / "besu-osaka-reference-genesis.json").read_text())
    genesis = json.loads((EVIDENCE / "genesis.json").read_text())
    genesis["config"] = {**genesis["config"], **reference["config"], "osakaTime": 0, "chainId": CHAIN_ID}
    for address, account in reference.get("alloc", {}).items():
        if account.get("code"):  # system contracts only; the reference test's funded EOAs stay out
            genesis["alloc"][address] = account
    genesis.update(blobGasUsed="0x0", excessBlobGas="0x0", parentBeaconBlockRoot=ZERO)
    path = EVIDENCE / "genesis-osaka.json"
    path.write_text(json.dumps(genesis, indent=2) + "\n")
    return path


def unused_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def prepare():
    """Compile fixtures, write the post-merge genesis, build the Go client. Idempotent."""
    SCRATCH.mkdir(parents=True, exist_ok=True)
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    assert BESU_HOME.joinpath("bin/besu").is_file(), f"Besu 26.8.1 distribution missing at {BESU_HOME}"
    assert JAVA_HOME.joinpath("bin/java").is_file(), f"JDK 25 missing at {JAVA_HOME}"
    assert PLUGIN_JAR.is_file(), "build the plugin first: gradle build"
    assert "Version: 0.8.35+" in command(["solc", "--version"])
    compiled = json.loads(command([
        "solc", "--optimize", "--optimize-runs", "200", "--evm-version", "shanghai",
        "--combined-json", "abi,bin,bin-runtime", "contracts/Applications.sol",
    ]))
    (EVIDENCE / "contracts.json").write_text(json.dumps(compiled, indent=2) + "\n")
    global CREATION_CODE
    CREATION_CODE = {name.split(":")[-1]: "0x" + obj["bin"] for name, obj in compiled["contracts"].items()}
    codes = {name.split(":")[-1]: "0x" + obj["bin-runtime"] for name, obj in compiled["contracts"].items()}
    alloc = {addr: {"balance": hex(10**24)} for addr in (ADMIN, ALICE)}
    for addr, name in [(ROUTER, "Router"), (RELAY, "Relay"), (VAULT_A, "Vault"), (VAULT_B, "Vault"),
                       (CALL_HASH_CASES, "CallHashCases"), (CALL_HASH_TOKEN, "CallHashToken"),
                       (LIFE_FACTORY, "LifeFactory"), (DESTRUCTIBLE, "Destructible"),
                       (VALUE_ROUTER, "ValueRouter"), (VALUE_RECEIVER, "ValueReceiver")]:
        alloc[addr] = {"balance": "0x0", "nonce": "0x1", "code": codes[name]}
    alloc[RELAY]["storage"] = {ZERO: "0x" + format(int(VAULT_A, 16), "064x")}
    alloc[VALUE_ROUTER]["storage"] = {ZERO: "0x" + format(int(VALUE_RECEIVER, 16), "064x")}
    alloc[DESTRUCTIBLE]["balance"] = hex(1000)
    genesis = {
        "config": {"chainId": CHAIN_ID, "homesteadBlock": 0, "eip150Block": 0, "eip155Block": 0,
                   "eip158Block": 0, "byzantiumBlock": 0, "constantinopleBlock": 0, "petersburgBlock": 0,
                   "istanbulBlock": 0, "berlinBlock": 0, "londonBlock": 0, "shanghaiTime": 0,
                   "terminalTotalDifficulty": 0},
        "nonce": "0x0", "timestamp": "0x0", "extraData": "0x",
        "gasLimit": "0x1c9c380", "difficulty": "0x1", "mixHash": ZERO, "coinbase": "0x" + "00" * 20,
        "baseFeePerGas": "0x3b9aca00", "alloc": alloc,
    }
    (EVIDENCE / "genesis.json").write_text(json.dumps(genesis, indent=2) + "\n")
    subprocess.check_call(["go", "build", "-o", str(CLIENT), "./poc/besu-signed-approvals/client"], cwd=ROOT)
    for home in (BESU_HOME, LINEA_HOME):
        if home.joinpath("bin/besu").is_file():
            plugins = home / "plugins"
            plugins.mkdir(exist_ok=True)
            shutil.copy(PLUGIN_JAR, plugins / PLUGIN_JAR.name)


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class Node:
    """Besu as a post-merge execution client; the harness plays the consensus client (Engine API)."""

    def __init__(self, name, plugin=True, configured=True, wait_ms=5000, directory=None, extra=(),
                 expect_exit=False, besu_home=None, linea_plugins=(), log_level=None, genesis=None,
                 fork="shanghai"):
        self.name = name
        self.plugin = plugin
        self.fork = fork
        genesis = genesis or (osaka_genesis() if fork == "osaka" else EVIDENCE / "genesis.json")
        # The Linea plugin JARs are copied into the stock 26.8.1 distribution (the Besu commit the
        # Lineth monorepo pins on main); the packaged 26.8.0 build rejects our Engine API driving.
        besu_home = Path(besu_home) if besu_home else BESU_HOME
        self.directory = Path(directory) if directory else Path(SCRATCH / f"{name}-{os.getpid()}-{int(time.time())}")
        self.directory.mkdir(parents=True, exist_ok=True)
        self.rpc_port = unused_port()
        self.engine_port = unused_port()
        self.approval_port = unused_port()
        self.rpc_url = f"http://127.0.0.1:{self.rpc_port}"
        self.engine_url = f"http://127.0.0.1:{self.engine_port}"
        self.log_path = self.directory / "node.log"
        self.records = []
        self.local = threading.local()
        self.connections = []
        self.connections_lock = threading.Lock()
        self.secret = bytes.fromhex("11" * 32)
        jwt_path = self.directory / "jwt.hex"
        jwt_path.write_text(self.secret.hex())
        key_file = self.directory / "key"
        key_file.write_text("0x" + KEYS[ADMIN])
        args = [str(besu_home / "bin/besu"), "--data-path", str(self.directory / "data"),
                "--genesis-file", str(genesis or (EVIDENCE / "genesis.json")), "--node-private-key-file", str(key_file),
                "--min-gas-price", "0",
                "--rpc-http-enabled", "--rpc-http-host", "127.0.0.1", "--rpc-http-port", str(self.rpc_port),
                "--rpc-http-api", "ETH,NET,WEB3,DEBUG,TXPOOL,ADMIN" + (",OPS" if plugin else ""),
                "--engine-rpc-enabled", "--engine-rpc-port", str(self.engine_port),
                "--engine-jwt-secret", str(jwt_path), "--engine-host-allowlist", "*",
                "--rpc-tx-feecap", "0", "--p2p-enabled=false", "--discovery-enabled=false",
                # A benchmark submits a long run of future nonces from one sender before the block.
                "--tx-pool-max-future-by-sender", "2000", "--tx-pool-max-prioritized", "2000",
                "--logging", log_level or os.environ.get("OPS_BESU_LOG_LEVEL", "INFO")]
        if plugin:
            # One --plugins list: Besu refuses to start if any named plugin is missing.
            args += ["--plugins", ",".join(["OpsApprovalPlugin", *linea_plugins])]
        if linea_plugins:
            args += LINEA_SELECTOR_OPTIONS
        if plugin and configured:
            args += ["--plugin-ops-approval-listen", f"127.0.0.1:{self.approval_port}",
                     "--plugin-ops-approval-public-key", APPROVAL_PUBLIC_KEY,
                     "--plugin-ops-approval-chain-id", str(CHAIN_ID),
                     "--plugin-ops-approval-wait-ms", str(wait_ms)]
        if not plugin:
            args += ["--Xplugins-external-enabled=false"]
        args += list(extra)
        env = dict(os.environ, JAVA_HOME=str(JAVA_HOME), PATH=f"{JAVA_HOME}/bin:" + os.environ["PATH"],
                   JAVA_OPTS="-Xmx2g")
        self.log = open(self.log_path, "ab")
        self.process = subprocess.Popen(args, stdout=self.log, stderr=subprocess.STDOUT, env=env, cwd=self.directory)
        if expect_exit:
            return
        try:
            deadline = time.time() + 120
            while time.time() < deadline:
                if self.process.poll() is not None:
                    raise RuntimeError(f"{name}: Besu exited early\n" + self.log_path.read_text(errors="replace")[-4000:])
                try:
                    if int(self.rpc("eth_chainId"), 16) == CHAIN_ID:
                        self.head = self.rpc("eth_getBlockByNumber", "latest", False)
                        return
                except Exception:
                    time.sleep(0.5)
            raise RuntimeError(f"{name}: Besu did not become ready\n" + self.log_path.read_text(errors="replace")[-4000:])
        except BaseException:
            self.close()  # never leave an orphaned Besu behind a failed scenario
            raise

    def engine(self, method, *params):
        return self.request(method, list(params), engine=True)

    def make_block(self, expected, denied=None, timeout=15):
        """Build one block through the Engine API.

        Besu rebuilds the candidate every ~500 ms until engine_getPayload, which *finalizes* the
        proposal, so getPayload may only be called once. The selector's decision log tells us when
        a candidate containing every expected transaction (and the expected denial) has been built.
        """
        state = {"headBlockHash": self.head["hash"], "safeBlockHash": self.head["hash"],
                 "finalizedBlockHash": self.head["hash"]}
        attrs = {"timestamp": hex(int(self.head["timestamp"], 16) + 1), "prevRandao": ZERO,
                 "suggestedFeeRecipient": ADMIN, "withdrawals": []}
        fcu, get_payload, new_payload = "V2", "V2", "V2"
        if self.fork == "osaka":
            attrs["parentBeaconBlockRoot"] = ZERO
            fcu, get_payload, new_payload = "V3", "V5", "V4"
        start = self.engine("engine_forkchoiceUpdated" + fcu, state, attrs)
        assert start["payloadStatus"]["status"] == "VALID", start
        payload_id = start["payloadId"]
        deadline = time.time() + timeout
        while True:
            if self.plugin:
                decisions = self.decisions()
                allowed = all(any(f"allow tx={tx['hash']}" in d for d in decisions) for tx in expected)
                vetoed = denied is None or any(f"deny tx={denied['hash']}" in d for d in decisions)
                ready = allowed and vetoed
                detail = {"expected": [tx["hash"] for tx in expected], "decisions": decisions}
            else:
                # No gate to report progress: wait until the pool holds every expected transaction.
                pooled = {t["hash"].lower() for t in self.rpc("txpool_besuTransactions")}
                ready = all(tx["hash"].lower() in pooled for tx in expected)
                detail = {"expected": [tx["hash"] for tx in expected], "pooled": sorted(pooled)}
            if ready:
                break
            assert time.time() < deadline, detail
            time.sleep(0.2)
        time.sleep(1.2 if not expected else 0.8)  # let the candidate holding those decisions be stored
        envelope = self.engine("engine_getPayload" + get_payload, payload_id)
        payload = envelope["executionPayload"]
        assert len(payload["transactions"]) == len(expected), (payload["transactions"], expected)
        if self.fork == "osaka":
            result = self.engine("engine_newPayload" + new_payload, payload, [], ZERO,
                                 envelope.get("executionRequests", []))
        else:
            result = self.engine("engine_newPayload" + new_payload, payload)
        assert result["status"] == "VALID", result
        result = self.engine("engine_forkchoiceUpdated" + fcu, dict.fromkeys(state, payload["blockHash"]), None)
        assert result["payloadStatus"]["status"] == "VALID", result
        for _ in range(100):
            self.head = self.rpc("eth_getBlockByNumber", "latest", False)
            if self.head["hash"] == payload["blockHash"]:
                break
            time.sleep(0.05)
        else:
            raise AssertionError("block did not become canonical")
        assert self.head["transactions"] == [tx["hash"] for tx in expected], (self.head["transactions"], expected)
        return payload

    def request(self, method, params, engine=False):
        headers = {"Content-Type": "application/json"}
        if engine:
            token = b64(b'{"alg":"HS256","typ":"JWT"}') + "." + b64(json.dumps({"iat": int(time.time())}).encode())
            headers["Authorization"] = "Bearer " + token + "." + b64(hmac.new(self.secret, token.encode(), hashlib.sha256).digest())
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
        # One kept-alive connection per thread: opening a socket per call exhausts Besu's
        # connection limit under load, which shows up as connections reset mid-benchmark.
        for attempt in range(4):
            connection = self._connection(engine)
            try:
                connection.request("POST", "/", body, headers)
                response = connection.getresponse()
                payload = response.read()
                if response.status >= 400:
                    raise RuntimeError(f"{method}: HTTP {response.status} {payload[:300]!r}")
                result = json.loads(payload)
                break
            except (OSError, http.client.HTTPException) as e:
                self._drop_connection(engine)
                if attempt == 3:
                    raise RuntimeError(f"{method}: {type(e).__name__} {e}") from None
                time.sleep(0.2)
        if method not in ("eth_blockNumber", "eth_chainId", "txpool_besuTransactions", "eth_getTransactionReceipt", "engine_getPayloadV2", "engine_getPayloadV5"):
            self.records.append({"method": method, "params": params, "response": result})
        if "error" in result:
            raise RuntimeError(f"{method}: {result['error']}")
        return result["result"]

    def _connection(self, engine):
        if not hasattr(self.local, "connections"):
            self.local.connections = {}
        key = "engine" if engine else "rpc"
        if key not in self.local.connections:
            host = (self.engine_url if engine else self.rpc_url).removeprefix("http://")
            connection = http.client.HTTPConnection(host, timeout=30)
            self.local.connections[key] = connection
            with self.connections_lock:
                self.connections.append(connection)
        return self.local.connections[key]

    def _drop_connection(self, engine):
        key = "engine" if engine else "rpc"
        connection = self.local.connections.pop(key, None)
        if connection is not None:
            with contextlib.suppress(Exception):
                connection.close()
            with self.connections_lock:
                if connection in self.connections:
                    self.connections.remove(connection)

    def rpc(self, method, *params):
        return self.request(method, list(params))

    def raw(self, sender, to, sig, *args, fee=2_000_000_000, nonce=None, gas=200000, legacy=True, value=0):
        if nonce is None:
            nonce = int(self.rpc("eth_getTransactionCount", sender, "latest"), 16)
        positional = ([to, sig, *map(str, args)] if sig else [to]) if to else []
        raw = command(["cast", "mktx", *positional, "--value", str(value), "--private-key", KEYS[sender],
                       "--chain-id", str(CHAIN_ID), "--nonce", str(nonce), "--gas-limit", str(gas),
                       *(["--legacy"] if legacy else ["--priority-gas-price", "1000000000"]),
                       "--gas-price", str(fee), "--rpc-url", self.rpc_url, *([] if to else ["--create", sig])])
        tx_hash = command(["cast", "keccak", raw])
        return {"hash": tx_hash, "sender": sender, "nonce": nonce, "raw": raw}

    def submit(self, tx):
        assert self.rpc("eth_sendRawTransaction", tx["raw"]) == tx["hash"]
        return tx

    def in_pool(self, tx_hash):
        return any(t["hash"].lower() == tx_hash.lower() for t in self.rpc("txpool_besuTransactions"))

    def receipt(self, tx_hash):
        return self.rpc("eth_getTransactionReceipt", tx_hash)

    def storage(self, address, slot="0x0"):
        return int(self.rpc("eth_getStorageAt", address, slot, "latest"), 16)

    def nonce(self, address):
        return int(self.rpc("eth_getTransactionCount", address, "latest"), 16)

    def balance(self, address):
        return int(self.rpc("eth_getBalance", address, "latest"), 16)

    def snapshot(self):
        """The state the demo asserts is untouched when a transaction is excluded."""
        return {
            "alice_nonce": self.nonce(ALICE),
            "alice_balance": self.rpc("eth_getBalance", ALICE, "latest"),
            "router": [self.rpc("eth_getStorageAt", ROUTER, hex(i), "latest") for i in range(3)],
            "relay": [self.rpc("eth_getStorageAt", RELAY, hex(i), "latest") for i in range(3)],
            "vault_a": self.rpc("eth_getStorageAt", VAULT_A, "0x0", "latest"),
            "vault_b": self.rpc("eth_getStorageAt", VAULT_B, "0x0", "latest"),
        }

    def timings(self):
        """Per-transaction gate cost, as the plugin reports it."""
        out = []
        for line in self.log_path.read_text(errors="replace").splitlines():
            if "OPS_APPROVAL_TIMING " in line:
                out.append(json.loads(line.split("OPS_APPROVAL_TIMING ", 1)[1]))
        return out

    def decisions(self):
        out = []
        for line in self.log_path.read_text(errors="replace").splitlines():
            if "OPS_APPROVAL_DECISION " in line:
                out.append(line.split("OPS_APPROVAL_DECISION ", 1)[1])
        return out

    def stop(self):
        with self.connections_lock:
            for connection in self.connections:
                with contextlib.suppress(Exception):
                    connection.close()
            self.connections.clear()
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.process.kill()
        self.log.close()

    def close(self):
        self.stop()
        (EVIDENCE / f"{self.name}.log").write_bytes(self.log_path.read_bytes())
        (EVIDENCE / f"{self.name}-rpc.json").write_text(json.dumps(self.records, indent=1) + "\n")
