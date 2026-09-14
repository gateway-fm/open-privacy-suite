#!/usr/bin/env python3
"""The whole stack: real OPS HTTP service, PostgreSQL, Redis and Besu with the approval plugin.

Nothing about authorization is stubbed here — OPS runs its own RBAC over its own database, signs the
approval only after its gates pass, and delivers it to the plugin, which decides inclusion. The
fixtures are the test identities and wallets, the development login, and this script standing in for
a consensus client (Engine API) and an identity provider.
"""
import argparse
import concurrent.futures
import contextlib
import http.client
import json
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

import harness as h


def request(url, method="GET", body=None, token=None, admin=False, allow_error=False):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Admin-Token" if admin else "Authorization"] = token if admin else "Bearer " + token
    req = urllib.request.Request(
        url, None if body is None else json.dumps(body).encode(), headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            data = response.read()
            return json.loads(data) if data else None
    except urllib.error.HTTPError as e:
        if allow_error:
            return {**json.loads(e.read()), "http_status": e.code}
        raise RuntimeError(f"{method} {url}: {e.code} {e.read().decode()}") from e


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True).strip()


class Stack:
    """PostgreSQL + Redis + Besu (with the plugin) + the OPS server, all disposable."""

    ADMIN_TOKEN = "ops-besu-local-demo-only"

    def __init__(self, name, plugin=True, linea=False):
        self.name = name
        self.plugin = plugin
        self.containers = []
        self.node = None
        self.ops = None
        self.tokens = {}
        self.directory = h.SCRATCH / f"{name}-{time.time_ns()}"
        self.directory.mkdir(parents=True)
        try:
            prefix = "ops-besu-" + str(time.time_ns())
            pg = docker(
                "run", "-d", "--rm", "--name", prefix + "-pg", "--label", "ops-besu-demo=true",
                "-e", "POSTGRES_PASSWORD=postgres", "-e", "POSTGRES_DB=ops_approvals_demo",
                "-e", "AUDIT_APP_PASSWORD=audit-demo-only", "-p", "127.0.0.1::5432",
                "-v", str(h.ROOT / "scripts/init-audit-db.sh") + ":/docker-entrypoint-initdb.d/10-audit.sh:ro",
                "postgres:15-alpine")
            self.containers.append(pg)
            pgport = docker("port", pg, "5432/tcp").rsplit(":", 1)[1]
            for _ in range(300):
                if subprocess.run(["docker", "exec", pg, "pg_isready", "-U", "postgres"],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError("PostgreSQL did not start")
            redis = docker(
                "run", "-d", "--rm", "--name", prefix + "-redis", "--label", "ops-besu-demo=true",
                "-p", "127.0.0.1::6379", "redis:7-alpine", "redis-server", "--requirepass", "redis-demo-only")
            self.containers.append(redis)
            redisport = docker("port", redis, "6379/tcp").rsplit(":", 1)[1]

            self.node = h.Node(name, plugin=plugin, wait_ms=5000,
                               linea_plugins=[h.LINEA_POOL_PLUGIN] if linea else ())
            port = h.unused_port()
            self.url = f"http://127.0.0.1:{port}"
            seed = self.directory / "approval-seed.hex"
            seed.write_text("07" * 32)
            seed.chmod(0o600)
            # A clean environment: never inherit a developer's .env or local configuration.
            env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "TMPDIR", "LANG")}
            env.update(
                ENVIRONMENT="development", GIN_MODE="release", PORT=str(port), BASE_URL=self.url,
                NODE_URL=self.node.rpc_url,
                DATABASE_URL=f"postgres://postgres:postgres@127.0.0.1:{pgport}/ops_approvals_demo?sslmode=disable",
                AUDIT_DATABASE_URL=f"postgres://privacy_proxy_app:audit-demo-only@127.0.0.1:{pgport}/ops_approvals_demo_audit?sslmode=disable",
                REDIS_URL=f"redis://:redis-demo-only@127.0.0.1:{redisport}/0",
                JWT_SECRET="ops-besu-demo-access-secret-at-least-32-bytes",
                JWT_REFRESH_SECRET="ops-besu-demo-refresh-secret-at-least-32-bytes",
                ADMIN_API_TOKEN=self.ADMIN_TOKEN, ALLOW_MOCK_LOGIN="true", MOCK_SIGNATURES="false",
                ENABLE_TRAVEL_RULE="true", VERIFIER_ID="did:privado:verifier:dev-0000000000000000",
                DISABLE_COINGECKO="true", MAX_CONCURRENT_REQUESTS="128", EXPLORER_DATABASE_URL="",
                TRACE_TIERED_VALIDATION="false", AUDIT_BUFFER_DIR=str(self.directory / "audit-buffer"),
                DB_MAX_OPEN_CONNS="30")
            env.update(getattr(self, "extra_env", {}))
            if plugin:
                env.update(OPS_APPROVAL_NODE="besu", OPS_APPROVAL_TARGET=f"127.0.0.1:{self.node.approval_port}",
                           OPS_APPROVAL_SEED_FILE=str(seed), OPS_APPROVAL_MAX_BATCH="32")
            self.opslog = (self.directory / "ops.log").open("w")
            assert (h.ROOT / ".tmp/ops-server").is_file(), "build it first: go build -tags mockauth -o .tmp/ops-server ./cmd/server"
            self.ops = subprocess.Popen([str(h.ROOT / ".tmp/ops-server")], cwd=self.directory, env=env,
                                        stdout=self.opslog, stderr=subprocess.STDOUT)
            for _ in range(400):
                if self.ops.poll() is not None:
                    raise RuntimeError((self.directory / "ops.log").read_text()[-7000:])
                try:
                    request(self.url + "/health")
                    break
                except (OSError, RuntimeError):
                    time.sleep(0.1)
            else:
                raise RuntimeError("OPS did not start")
            self.seed()
        except BaseException:
            self.close()
            raise

    def admin(self, method, path, body=None):
        return request(self.url + "/api/v1/admin" + path, method, body, self.ADMIN_TOKEN, True)

    def login(self, did):
        session = request(self.url + "/auth/request", "POST", {})["session_id"]
        return request(self.url + "/auth/verify", "POST",
                       {"session_id": session, "jwz_token": "mock." + did})["access_token"]

    def seed(self):
        """Two organizations, one group with the deploy claim, two linked wallets, granted contracts."""
        self.org = self.admin("POST", "/orgs", {"slug": "bank-a", "name": "Bank A"})["id"]
        self.foreign = self.admin("POST", "/orgs", {"slug": "bank-b", "name": "Bank B"})["id"]
        group = self.admin("POST", f"/orgs/{self.org}/groups", {"slug": "payments", "name": "Payments"})["id"]
        self.group = group
        self.admin("PUT", f"/orgs/{self.org}/groups/{group}/access",
                   {"claims": ["deploy"], "allowed_methods": ["*"]})
        for name, address in [("alice", h.ALICE), ("operator", h.ADMIN)]:
            did = "did:test:besu-demo-" + name
            self.login(did)
            users = self.admin("GET", "/users?search=" + urllib.parse.quote(did))
            users = users if isinstance(users, list) else users["data"]
            uid = next(u["id"] for u in users if u["external_id"] == did)
            self.admin("PUT", "/users/" + uid, {"kyc": True, "note": name + " (Besu demo)"})
            for membership in self.admin("GET", f"/users/{uid}/memberships"):
                self.admin("DELETE", f"/users/{uid}/memberships/{membership['membership']['id']}")
            self.admin("POST", f"/users/{uid}/memberships", {"group_id": group})
            token = self.login(did)
            self.tokens[address] = token
            challenge = request(self.url + "/api/v1/eth/link/challenge", "POST", {}, token)
            signature = h.command(["cast", "wallet", "sign", "--private-key", h.KEYS[address],
                                   challenge["message"]])
            request(self.url + "/api/v1/eth/link/verify", "POST",
                    {"nonce": challenge["nonce"], "address": address, "signature": signature}, token)
        for address in [h.ROUTER, h.RELAY, h.VAULT_A, h.CALL_HASH_CASES, h.LIFE_FACTORY, h.DESTRUCTIBLE]:
            self.admin("POST", f"/orgs/{self.org}/contracts", {"address": address, "name": "Bank A " + address[-4:]})
            self.admin("POST", f"/orgs/{self.org}/contracts/{address}/grants", {"group_id": group})
        self.admin("POST", f"/orgs/{self.foreign}/contracts", {"address": h.VAULT_B, "name": "Bank B vault"})

    def rpc(self, method, params, sender=h.ALICE):
        return request(self.url + "/rpc/" + self.org, "POST",
                       {"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
                       self.tokens[sender], allow_error=True)

    def submit(self, tx):
        return self.rpc("eth_sendRawTransaction", [tx["raw"]], tx["sender"])

    def contracts(self):
        """Contract addresses registered to the demo organization, whatever shape the API returns."""
        result = self.admin("GET", f"/orgs/{self.org}/contracts")
        rows = result if isinstance(result, list) else result.get("data", result.get("contracts", []))
        return [(row["address"] if isinstance(row, dict) else row).lower() for row in rows]

    def close(self):
        if self.ops is not None:
            self.ops.terminate()
            try:
                self.ops.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.ops.kill()
                self.ops.wait(timeout=5)
            self.opslog.close()
            shutil.copy2(self.directory / "ops.log", h.EVIDENCE / (self.name + "-ops.log"))
        if self.node is not None:
            self.node.close()
        for container in reversed(self.containers):
            subprocess.run(["docker", "stop", "-t", "3", container],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def announce(text, pause):
    print("\n" + text, flush=True)
    if pause:
        input("Press Enter to run this step... ")


def story(stack, pause=False):
    n = stack.node
    out = {"ops": stack.url, "besu": n.rpc_url, "checks": []}

    announce("1. Alice calls Bank A: Router -> Relay -> Bank A vault.\n"
             "   OPS checks its own database policy, signs an approval, and Besu commits.", pause)
    tx = n.raw(h.ALICE, h.ROUTER, "run(uint256)", 7)
    result = stack.submit(tx)
    assert result.get("result") == tx["hash"], result
    n.make_block([tx])
    assert n.receipt(tx["hash"])["status"] == "0x1"
    assert n.storage(h.VAULT_A) == 7
    out["checks"].append({"name": "same_org_executes", "tx": tx["hash"]})
    print("PASS - included, vault A = 7:", tx["hash"], flush=True)

    announce("2. Alice tries to reach Bank B's vault.\n"
             "   OPS rejects it from the real organization boundary in its database - nothing is sent.", pause)
    foreign = n.raw(h.ALICE, h.ROUTER, "runDelegate(address,uint256)", h.VAULT_B, 7)
    result = stack.submit(foreign)
    assert "error" in result, result
    assert n.rpc("eth_getTransactionByHash", foreign["hash"]) is None
    out["checks"].append({"name": "ops_rejects_cross_org", "response": result})
    print("PASS - OPS rejected:", json.dumps(result["error"])[:160], flush=True)

    announce("3. OPS approves Alice's Bank A call. Before it executes, a higher-fee transaction\n"
             "   redirects the relay to Bank B. The approval no longer describes the execution.", pause)
    stale = n.raw(h.ALICE, h.ROUTER, "run(uint256)", 9)
    assert stack.submit(stale).get("result") == stale["hash"]
    mutation = n.raw(h.ADMIN, h.RELAY, "setTarget(address)", h.VAULT_B, fee=4_000_000_000)
    assert stack.submit(mutation).get("result") == mutation["hash"]
    before = n.snapshot()
    n.make_block([mutation], denied=stale)
    after = n.snapshot()
    for field in ("alice_nonce", "alice_balance", "router", "vault_a", "vault_b"):
        assert before[field] == after[field], (field, before, after)
    assert n.receipt(stale["hash"]) is None
    out["checks"].append({"name": "besu_excludes_divergent_execution", "tx": stale["hash"],
                          "decisions": [d for d in n.decisions() if stale["hash"] in d][-1:]})
    print("PASS - excluded. Alice's nonce, balance and every application write are unchanged.", flush=True)
    print("       The hash her client received meant admission, not execution.", flush=True)

    announce("4. Alice deploys a contract. Creation is bound by the stricter fingerprint,\n"
             "   and OPS registers the new contract to her organization.", pause)
    deployment = n.raw(h.ALICE, None, h.CREATION_CODE["Vault"])
    result = stack.submit(deployment)
    assert result.get("result") == deployment["hash"], result
    n.make_block([deployment])
    receipt = n.receipt(deployment["hash"])
    assert receipt["status"] == "0x1", receipt
    created = receipt["contractAddress"].lower()
    assert n.rpc("eth_getCode", created, "latest") != "0x"
    # OPS finalises a deployment when it sees the receipt, a moment after the block.
    deadline = time.time() + 60
    while created not in stack.contracts() and time.time() < deadline:
        time.sleep(1)
    registered = stack.contracts()
    assert created in registered, (created, registered)
    out["checks"].append({"name": "deployment_included_and_registered", "address": created})
    print("PASS - deployed and registered to Bank A:", created, flush=True)

    (h.EVIDENCE / "demo.json").write_text(json.dumps(out, indent=2) + "\n")
    print("\nAll four steps passed. Evidence: poc/besu-signed-approvals/evidence/demo.json", flush=True)


def bench(count=128, samples=3, concurrency=16):
    """The same load with and without the gate, submitted concurrently.

    Transactions are built and signed before the clock starts; every timed request still passes all
    of OPS's gates. Each worker keeps one HTTP connection, as a real SDK would.
    """
    rows = []
    for plugin in (False, True):
        with contextlib.closing(Stack("bench-" + ("on" if plugin else "off"), plugin=plugin)) as stack:
            n = stack.node
            nonce = n.nonce(h.ADMIN)
            for sample in range(samples + 1):  # the first sample warms the JIT and the pools
                txs = [n.raw(h.ADMIN, h.CALL_HASH_CASES, "setAmount(uint256)", 1000 + sample * count + i,
                             nonce=nonce + i) for i in range(count)]
                def submit_all(part):
                    connection = http.client.HTTPConnection(
                        urllib.parse.urlparse(stack.url).netloc, timeout=30)
                    taken = []
                    try:
                        for tx in part:
                            body = json.dumps({"jsonrpc": "2.0", "id": 1,
                                               "method": "eth_sendRawTransaction", "params": [tx["raw"]]})
                            sent = time.perf_counter_ns()
                            connection.request("POST", "/rpc/" + stack.org, body,
                                               {"Content-Type": "application/json",
                                                "Authorization": "Bearer " + stack.tokens[h.ADMIN]})
                            response = connection.getresponse()
                            result = json.loads(response.read())
                            taken.append((time.perf_counter_ns() - sent) / 1e6)
                            assert response.status == 200 and result.get("result") == tx["hash"], (
                                result, {"nonce": tx["nonce"], "sender_nonce": n.nonce(h.ADMIN)})
                    finally:
                        connection.close()
                    return taken

                start = time.perf_counter()
                with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
                    latencies = sum(pool.map(submit_all, [txs[i::concurrency] for i in range(concurrency)]), [])
                submission_s = time.perf_counter() - start
                gates_before = len(n.timings())
                block_start = time.perf_counter()
                n.make_block(txs)
                block_s = time.perf_counter() - block_start
                for tx in txs:
                    assert n.receipt(tx["hash"])["status"] == "0x1"
                gate_ns = [t["gate_ns"] for t in n.timings()[gates_before:]]
                row = {"gate": plugin, "sample": sample, "warmup": sample == 0, "count": count,
                       "concurrency": concurrency,
                       "submission_s": round(submission_s, 3),
                       "submission_tps": round(count / submission_s, 1),
                       "ops_request_median_ms": round(statistics.median(latencies), 2),
                       "ops_request_p95_ms": round(sorted(latencies)[int(0.95 * (len(latencies) - 1))], 2),
                       # Wall clock around the harness's block step. It contains a fixed wait and
                       # Besu's repeated candidate rebuilds, so it is not a producer benchmark.
                       "harness_block_wall_s": round(block_s, 3),
                       "gate_us_per_tx": round(statistics.median(gate_ns) / 1000, 1) if gate_ns else None}
                rows.append(row)
                nonce += count
                print("BENCH", json.dumps(row), flush=True)
    measured = [r for r in rows if not r["warmup"]]
    summary = {}
    for gate in (False, True):
        part = [r for r in measured if r["gate"] == gate]
        summary["gate_on" if gate else "gate_off"] = {
            "submission_tps": round(statistics.median(r["submission_tps"] for r in part), 1),
            "ops_request_median_ms": round(statistics.median(r["ops_request_median_ms"] for r in part), 2),
            "harness_block_wall_s": round(statistics.median(r["harness_block_wall_s"] for r in part), 3),
            "gate_us_per_tx": part[0]["gate_us_per_tx"],
        }
    summary["machine"] = subprocess.check_output(["uname", "-sm"], text=True).strip()
    summary["transactions_per_block"] = count
    summary["concurrency"] = concurrency
    summary["note"] = ("submission figures are end-to-end through the OPS HTTP API with "
                       f"{concurrency} concurrent clients on one local machine; gate_us_per_tx is "
                       "the plugin's own pre+post work per transaction; harness_block_wall_s includes "
                       "a fixed wait and repeated candidate rebuilds and is not a producer benchmark")
    (h.EVIDENCE / "benchmark.json").write_text(json.dumps({"summary": summary, "samples": rows}, indent=2) + "\n")
    print("\nSUMMARY", json.dumps(summary, indent=2), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", nargs="?", default="story", choices=["story", "bench"])
    parser.add_argument("--pause", action="store_true", help="wait for Enter between story steps")
    parser.add_argument("--linea", action="store_true", help="also load Lineth's transaction-pool plugin")
    parser.add_argument("--count", type=int, default=128)
    parser.add_argument("--concurrency", type=int, default=16)
    args = parser.parse_args()
    h.prepare()
    if args.mode == "bench":
        bench(count=args.count, concurrency=args.concurrency)
        return
    with contextlib.closing(Stack("demo", linea=args.linea)) as stack:
        print(f"OPS {stack.url}   Besu {stack.node.rpc_url}   organization {stack.org}", flush=True)
        story(stack, pause=args.pause)


if __name__ == "__main__":
    main()
