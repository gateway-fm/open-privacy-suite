#!/usr/bin/env python3
"""Real Besu 26.8.1 + OPS approval plugin: the signed-approval scenario matrix."""
import argparse
import contextlib
import json
import os
import subprocess
import time
import harness as h

RESULTS = []


class Client:
    """Plays OPS against the node through the Go fixture client: internal/nodeapproval's preflight
    (Besu mode) and batch signing, and delivery over the gRPC contract (ApprovalDelivery) — one
    Deliver per batch, whose status is the confirmation."""

    def __init__(self, node):
        self.node = node
        self.last = None
        self.process = subprocess.Popen([str(h.CLIENT), node.rpc_url, f"127.0.0.1:{node.approval_port}"],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        text=True, env=dict(os.environ, OPS_APPROVAL_NODE="besu"))
        # OPS calls Status whenever its connection becomes ready; the receiver's wait window after
        # boot counts from that first call.
        self.boot_id = self.status()["boot_id"]

    def _ask(self, query):
        self.process.stdin.write(json.dumps(query) + "\n")
        self.process.stdin.flush()
        return json.loads(self.process.stdout.readline())

    def prepare(self, tx):
        result = self._ask({"raw": tx["raw"]})
        assert "error" not in result, result
        self.last = result
        return result["Approval"]

    def try_prepare(self, tx):
        return self._ask({"raw": tx["raw"]})

    def batch(self, approvals, **signing):
        """The signed envelope: now with OPS's default TTL, or per `ttl_ms`, `issued_at`,
        `expires_at`, `key_id`, `seed`."""
        result = self._ask({"approvals": approvals if isinstance(approvals, list) else [approvals], **signing})
        assert "error" not in result, result
        return bytes.fromhex(result["envelope"])

    def go_fingerprint(self, calls, pre):
        return self._ask({"fingerprint": {"calls": calls, "pre": pre}})

    def deliver(self, envelope):
        """One Deliver call: {'code': 'OK', 'boot_id', 'stored'} or {'code', 'message', 'reason'}."""
        return self._ask({"deliver": envelope.hex()})

    def status(self, wait_ms=0):
        result = self._ask({"status": True, "wait_ms": wait_ms})
        assert result["code"] == "OK", result
        return result

    def send(self, approvals, expect="OK", **signing):
        result = self.deliver(self.batch(approvals, **signing))
        assert result["code"] == expect, result
        return result

    def approve(self, tx):
        a = self.prepare(tx)
        self.send(a)
        return a

    def close(self):
        self.process.stdin.close()
        self.process.wait(timeout=5)
        self.process.stdout.close()


@contextlib.contextmanager
def node(name, **kwargs):
    n = h.Node(name, **kwargs)
    try:
        yield n
    finally:
        n.close()


def record(name, **details):
    RESULTS.append({"test": name, "passed": True, **details})
    print("PASS", name, details, flush=True)
    (h.EVIDENCE / "tests.json").write_text(json.dumps(RESULTS, indent=2) + "\n")


def approval_first():
    with node("approval-first") as n, contextlib.closing(Client(n)) as c:
        tx = n.raw(h.ALICE, h.ROUTER, "run(uint256)", 7)
        a = c.approve(tx)
        time.sleep(0.2)
        n.submit(tx)
        n.make_block([tx])
        r = n.receipt(tx["hash"])
        assert r and r["status"] == "0x1", r
        assert n.storage(h.VAULT_A) == 7
        assert any(f"allow tx={tx['hash']}" in d for d in n.decisions())
        record("approval_before_transaction_included", hash=tx["hash"], fingerprint=a["fingerprint"])
        # Parity cross-check: Go encoder over Besu's own callTracer/prestateTracer output.
        tx2 = n.raw(h.ALICE, h.ROUTER, "run(uint256)", 5)
        plugin = n.rpc("ops_prepareApproval", tx2["raw"])
        calldata = h.command(["cast", "calldata", "run(uint256)", "5"])
        args = {"from": h.ALICE, "to": h.ROUTER, "input": calldata, "gas": hex(200000), "nonce": hex(tx2["nonce"]), "gasPrice": hex(2_000_000_000)}
        calls = n.rpc("debug_traceCall", args, "latest", {"tracer": "callTracer"})
        # Besu 26.8.1 answers "Internal error" to debug_traceCall+prestateTracer here; the Go encoder
        # only needs each callee's code, which eth_getCode supplies equivalently.
        pre = {}
        stack = [calls]
        while stack:
            call = stack.pop()
            pre[call["to"].lower()] = {"code": n.rpc("eth_getCode", call["to"], "latest")}
            stack.extend(call.get("calls", []))
        go = c.go_fingerprint(calls, pre)
        assert go.get("fingerprint") == plugin["fingerprint"], (go, plugin["fingerprint"])
        record("go_fingerprint_over_besu_calltracer_matches_plugin", plugin=plugin["fingerprint"], go=go)


def transaction_first():
    with node("transaction-first") as n, contextlib.closing(Client(n)) as c:
        tx = n.raw(h.ALICE, h.ROUTER, "run(uint256)", 7)
        n.submit(tx)
        n.make_block([])  # candidate built while the approval is missing: tx waits, stays in pool
        assert n.in_pool(tx["hash"]) and n.receipt(tx["hash"]) is None
        waits = [d for d in n.decisions() if f"wait tx={tx['hash']}" in d]
        assert waits, n.decisions()
        c.approve(tx)
        n.make_block([tx])
        assert n.receipt(tx["hash"])["status"] == "0x1" and n.storage(h.VAULT_A) == 7
        record("transaction_before_approval_waits_then_included", wait_rounds=len(waits))


def no_approval_timeout():
    # OPS is connected (its Status call starts the wait windows after boot) but never approves.
    with node("timeout", wait_ms=2000) as n, contextlib.closing(Client(n)):
        tx = n.raw(h.ALICE, h.ROUTER, "run(uint256)", 7)
        before = n.nonce(h.ALICE), n.balance(h.ALICE)
        n.submit(tx)
        n.make_block([])
        assert n.in_pool(tx["hash"]), "must wait, not drop, before the deadline"
        time.sleep(2.5)
        n.make_block([])
        for _ in range(40):  # pool removal is scheduled asynchronously by Besu
            if not n.in_pool(tx["hash"]):
                break
            time.sleep(0.25)
        assert not n.in_pool(tx["hash"]), "timed-out transaction must leave the pool"
        assert (n.nonce(h.ALICE), n.balance(h.ALICE)) == before and n.storage(h.VAULT_A) == 0
        assert any(f"drop tx={tx['hash']}" in d for d in n.decisions())
        record("unapproved_transaction_dropped_after_wait", hash=tx["hash"])


def same_block_target_change():
    with node("target-change") as n, contextlib.closing(Client(n)) as c:
        run = n.raw(h.ALICE, h.ROUTER, "run(uint256)", 7)
        c.approve(run)  # approved while the relay still targets vault A
        switch = n.raw(h.ADMIN, h.RELAY, "setTarget(address)", h.VAULT_B, fee=3_000_000_000)
        c.approve(switch)
        before = n.nonce(h.ALICE), n.balance(h.ALICE)
        n.submit(switch)
        n.submit(run)
        n.make_block([switch], denied=run)  # higher fee: the switch executes first
        assert n.storage(h.RELAY) == int(h.VAULT_B, 16)
        assert n.storage(h.VAULT_A) == 0 and n.storage(h.VAULT_B) == 0 and n.storage(h.ROUTER) == 0
        assert (n.nonce(h.ALICE), n.balance(h.ALICE)) == before
        for _ in range(40):
            if not n.in_pool(run["hash"]):
                break
            time.sleep(0.25)
        assert not n.in_pool(run["hash"]) and n.receipt(run["hash"]) is None
        denial = [d for d in n.decisions() if f"deny tx={run['hash']}" in d]
        record("same_block_target_change_excludes_stale_approval", denial=denial[-1][:160])


def caught_inner_failure():
    with node("caught") as n, contextlib.closing(Client(n)) as c:
        run = n.raw(h.ALICE, h.ROUTER, "runCatch(uint256)", 7)
        c.approve(run)
        switch = n.raw(h.ADMIN, h.RELAY, "setTarget(address)", h.VAULT_B, fee=3_000_000_000)
        c.approve(switch)
        n.submit(switch)
        n.submit(run)
        n.make_block([switch], denied=run)
        assert n.storage(h.VAULT_B) == 0 and n.receipt(run["hash"]) is None
        record("redirected_call_excluded_even_when_application_catches")


def delegatecall_path():
    with node("delegate") as n, contextlib.closing(Client(n)) as c:
        tx = n.raw(h.ALICE, h.ROUTER, "runDelegate(address,uint256)", h.VAULT_A, 3)
        plugin = n.rpc("ops_prepareApproval", tx["raw"])
        inner = plugin["calls"]["calls"][0]
        assert inner["type"] == "DELEGATECALL" and inner["to"].lower() == h.VAULT_A and inner["from"].lower() == h.ROUTER, inner
        c.approve(tx)
        n.submit(tx)
        n.make_block([tx])
        assert n.receipt(tx["hash"])["status"] == "0x1"
        assert n.storage(h.VAULT_A) == 0, "delegatecall must write the router's storage, not the vault's"
        assert n.storage(h.ROUTER) == 1 + 3
        record("delegatecall_bound_to_caller_storage", inner=inner)


def wrong_fingerprint():
    with node("wrong-fingerprint") as n, contextlib.closing(Client(n)) as c:
        tx = n.raw(h.ALICE, h.ROUTER, "run(uint256)", 7)
        a = c.prepare(tx)
        forged = dict(a, fingerprint="0x" + "ab" * 32)
        c.send(forged)  # correctly signed by OPS's key, but for a different execution
        before = n.nonce(h.ALICE)
        n.submit(tx)
        n.make_block([], denied=tx)
        assert n.storage(h.VAULT_A) == 0 and n.nonce(h.ALICE) == before
        for _ in range(40):
            if not n.in_pool(tx["hash"]):
                break
            time.sleep(0.25)
        assert not n.in_pool(tx["hash"])
        record("mismatching_fingerprint_excluded_and_dropped")


def bad_deliveries():
    """Every refusal of the delivery contract (§3), answered by the real node with its status code,
    and none of them stores anything; duplicates and redelivery are harmless. The plugin's metrics
    count each batch by status through Besu's own metrics endpoint."""
    capacity = 3
    with node("bad-deliveries", capacity=capacity) as n, contextlib.closing(Client(n)) as c:
        tx = n.raw(h.ALICE, h.ROUTER, "run(uint256)", 7)
        a = c.prepare(tx)
        now = int(time.time() * 1000)
        flipped = bytearray(c.batch(a))
        flipped[-1] ^= 1
        refused = {
            "garbage": c.deliver(bytes(200)),
            "untrusted key id": c.deliver(c.batch(a, key_id="rotated-out")),
            "flipped signature byte": c.deliver(bytes(flipped)),
            "another key under a trusted id": c.deliver(c.batch(a, seed=9)),
            "approval for chain 1": c.deliver(c.batch(dict(a, chain_id=1))),
            "TTL of 2 h, maximum 1 h": c.deliver(c.batch(a, ttl_ms=2 * 3_600_000)),
            "issued 60 s ahead": c.deliver(c.batch(a, issued_at=now + 60_000)),
            "expired": c.deliver(c.batch(a, issued_at=now - 20_000, expires_at=now - 10_000)),
            # One more approval than the store holds: all or nothing, so `a` is not stored either.
            "store full": c.deliver(c.batch([a] + [dict(a, tx_hash="0x" + format(i, "064x")) for i in range(1, capacity + 1)])),
        }
        codes = {what: answer["code"] for what, answer in refused.items()}
        assert codes == {
            "garbage": "INVALID_ARGUMENT",
            "untrusted key id": "PERMISSION_DENIED",
            "flipped signature byte": "UNAUTHENTICATED",
            "another key under a trusted id": "UNAUTHENTICATED",
            "approval for chain 1": "INVALID_ARGUMENT",
            "TTL of 2 h, maximum 1 h": "INVALID_ARGUMENT",
            "issued 60 s ahead": "FAILED_PRECONDITION",
            "expired": "FAILED_PRECONDITION",
            "store full": "UNAVAILABLE",
        }, refused
        assert refused["store full"].get("reason") == "store-full", refused["store full"]
        n.submit(tx)
        n.make_block([])
        assert n.in_pool(tx["hash"]), "no refused batch may unblock the transaction"
        duplicates = c.send([a, a])  # duplicates within one batch and a re-delivery are harmless
        assert duplicates["stored"] == 2 and duplicates["boot_id"] == c.boot_id, duplicates
        c.send(a)
        n.make_block([tx])
        assert n.receipt(tx["hash"])["status"] == "0x1"
        batches = {code: n.metric("ops_approval_batches_total", status=code)
                   for code in ("OK", "INVALID_ARGUMENT", "PERMISSION_DENIED", "UNAUTHENTICATED", "FAILED_PRECONDITION", "UNAVAILABLE")}
        assert batches == {"OK": 2, "INVALID_ARGUMENT": 3, "PERMISSION_DENIED": 1, "UNAUTHENTICATED": 2,
                           "FAILED_PRECONDITION": 2, "UNAVAILABLE": 1}, batches
        assert n.metric("ops_approval_approvals_stored_total") == 3
        # Every candidate rebuild (~500 ms) decides again, so a transaction is counted once per build.
        decisions = {d: n.metric("ops_approval_decisions_total", decision=d) for d in ("allow", "wait", "drop", "deny")}
        assert decisions["allow"] >= 1 and decisions["wait"] >= 1 and decisions["drop"] == decisions["deny"] == 0, decisions
        assert n.metric("ops_approval_store_size") == 1 and n.metric("ops_approval_connections") == 1
        record("refused_deliveries_answer_their_status_codes_and_store_nothing_duplicates_idempotent",
               codes=codes, batches=batches)


def shared_counter():
    with node("shared-counter") as n, contextlib.closing(Client(n)) as c:
        base = n.nonce(h.ALICE)
        txs = [n.raw(h.ALICE, h.CALL_HASH_CASES, "tick()", nonce=base + i) for i in range(8)]
        approvals = [c.prepare(tx) for tx in txs]  # all against the same pre-state
        c.send(approvals)
        for tx in txs:
            n.submit(tx)
        n.make_block(txs)
        assert all(n.receipt(tx["hash"])["status"] == "0x1" for tx in txs)
        assert n.storage(h.CALL_HASH_CASES) == 8
        record("eight_counter_increments_approved_against_one_state_all_included")


def deployment_included():
    """A plain deployment: refused before strict mode existed, now approved and included."""
    with node("deployment") as n, contextlib.closing(Client(n)) as c:
        tx = n.raw(h.ALICE, None, h.CREATION_CODE["Vault"])  # a real contract deployment
        approval = c.approve(tx)
        created = h.command(["cast", "compute-address", h.ALICE, "--nonce", str(tx["nonce"])]).split()[-1]
        n.submit(tx)
        n.make_block([tx])
        receipt = n.receipt(tx["hash"])
        assert receipt["status"] == "0x1", receipt
        assert receipt["contractAddress"].lower() == created.lower(), (receipt, created)
        assert n.rpc("eth_getCode", created, "latest") != "0x", "deployed code must persist"
        assert "hash_mode" not in approval, approval  # strict is mode 0, omitted from the JSON
        # OPS registers the contract from the same snapshot the approval binds.
        assert [a.lower() for a in c.last["surviving"]] == [created.lower()], c.last
        assert [a.lower() for a in c.last["fresh"]] == [created.lower()], c.last
        record("deployment_approved_and_included", created=created.lower())


def snapshot_matches_the_node_state():
    """What the plugin reports as state must be what the node holds afterwards."""
    with node("snapshot-check") as n, contextlib.closing(Client(n)) as c:
        tx = n.raw(h.ALICE, h.LIFE_FACTORY, "create(uint256,address)", 7, h.VAULT_A)
        plugin = n.rpc("ops_prepareApproval", tx["raw"])
        assert plugin["hashMode"] == 0, plugin
        c.approve(tx)
        n.submit(tx)
        n.make_block([tx])
        assert n.receipt(tx["hash"])["status"] == "0x1"
        checked = 0
        for address, account in plugin["diff"]["post"].items():
            if "code" in account:
                assert n.rpc("eth_getCode", address, "latest") == account["code"], address
                checked += 1
            if "nonce" in account:
                assert int(n.rpc("eth_getTransactionCount", address, "latest"), 16) == int(account["nonce"], 16), address
                checked += 1
            for slot, value in account.get("storage", {}).items():
                live = n.rpc("eth_getStorageAt", address, slot, "latest")
                assert int(live, 16) == int(value, 16), (address, slot, live, value)
                checked += 1
            if "balance" in account and address.lower() != h.ALICE.lower():
                # The sender's balance also carries the gas fee, which the snapshot excludes.
                assert int(n.rpc("eth_getBalance", address, "latest"), 16) == int(account["balance"], 16), address
                checked += 1
        assert checked >= 3, plugin["diff"]
        record("plugin_state_snapshot_matches_the_mined_state", checked=checked)


def runtime_lifecycle_included():
    """Runtime CREATE/CREATE2 and SELFDESTRUCT inside a call, with their denial controls."""
    with node("lifecycle") as n, contextlib.closing(Client(n)) as c:
        create = n.raw(h.ALICE, h.LIFE_FACTORY, "create(uint256,address)", 7, h.VAULT_A)
        c.approve(create)
        n.submit(create)
        n.make_block([create])
        assert n.receipt(create["hash"])["status"] == "0x1"
        assert n.storage(h.VAULT_A) == 7, "the constructor's nested call must have run"

        create2 = n.raw(h.ALICE, h.LIFE_FACTORY, "create2(bytes32,uint256)", "0x" + "11" * 32, 9)
        c.approve(create2)
        n.submit(create2)
        n.make_block([create2])
        assert n.receipt(create2["hash"])["status"] == "0x1"

        before = n.balance(h.ADMIN)
        destroy = n.raw(h.ALICE, h.DESTRUCTIBLE, "destroy(address)", h.ADMIN)
        c.approve(destroy)
        n.submit(destroy)
        n.make_block([destroy])
        assert n.receipt(destroy["hash"])["status"] == "0x1"
        assert n.balance(h.DESTRUCTIBLE) == 0 and n.balance(h.ADMIN) > before, "balance must be swept"
        record("runtime_create_create2_and_selfdestruct_included")


def strict_mode_binds_state():
    """Strict approvals are state-exact: a concurrent write to a slot the deployment touched denies."""
    with node("strict-state") as n, contextlib.closing(Client(n)) as c:
        # Positive control: the same transaction, alone in the block, is included.
        create = n.raw(h.ALICE, h.LIFE_FACTORY, "create(uint256,address)", 7, h.VAULT_A)
        c.approve(create)
        n.submit(create)
        n.make_block([create])
        assert n.receipt(create["hash"])["status"] == "0x1"

        # Now approve one, then let a higher-fee transaction change the factory's counter first.
        again = n.raw(h.ALICE, h.LIFE_FACTORY, "create(uint256,address)", 7, h.VAULT_A)
        c.approve(again)
        bump = n.raw(h.ADMIN, h.LIFE_FACTORY, "create(uint256,address)", 3, h.VAULT_A, fee=3_000_000_000)
        c.approve(bump)
        alice_nonce = n.nonce(h.ALICE)
        n.submit(bump)
        n.submit(again)
        n.make_block([bump], denied=again)
        assert n.receipt(again["hash"]) is None and n.nonce(h.ALICE) == alice_nonce
        denial = [d for d in n.decisions() if f"deny tx={again['hash']}" in d][-1]
        assert "MISMATCH" in denial, denial
        record("strict_approval_denied_when_touched_state_changed", denial=denial[:140])


def state_change_turns_call_into_lifecycle():
    with node("late-lifecycle") as n, contextlib.closing(Client(n)) as c:
        call = n.raw(h.ALICE, h.CALL_HASH_CASES, "maybeCreate()")
        c.approve(call)  # approved while extra == false: plain counter increment
        flip = n.raw(h.ADMIN, h.CALL_HASH_CASES, "setExtra(bool)", "true", fee=3_000_000_000)
        c.approve(flip)
        n.submit(flip)
        n.submit(call)
        n.make_block([flip], denied=call)  # flip lands first: maybeCreate now runs CREATE
        denial = [d for d in n.decisions() if f"deny tx={call['hash']}" in d][-1]
        assert "execution requires 0" in denial, denial  # calls approval, strict execution
        assert n.receipt(call["hash"]) is None
        record("approved_call_that_gains_a_create_is_denied_by_the_producer", denial=denial[:160])


def resubmission_after_mismatch():
    with node("resubmit") as n, contextlib.closing(Client(n)) as c:
        run = n.raw(h.ALICE, h.ROUTER, "run(uint256)", 7)
        c.approve(run)
        switch = n.raw(h.ADMIN, h.RELAY, "setTarget(address)", h.VAULT_B, fee=3_000_000_000)
        c.approve(switch)
        n.submit(switch)
        n.submit(run)
        n.make_block([switch], denied=run)
        for _ in range(40):
            if not n.in_pool(run["hash"]):
                break
            time.sleep(0.25)
        assert not n.in_pool(run["hash"])
        # The user resubmits the same signed bytes after OPS runs a fresh preflight on the new state.
        c.approve(run)
        n.submit(run)
        n.make_block([run])
        assert n.receipt(run["hash"])["status"] == "0x1" and n.storage(h.VAULT_B) == 7
        record("same_signed_transaction_included_after_new_preflight_following_a_mismatch")


def restart_loses_approvals():
    with node("restart-a", wait_ms=1500) as n, contextlib.closing(Client(n)) as c:
        tx = n.raw(h.ALICE, h.ROUTER, "run(uint256)", 7)
        c.approve(tx)
        directory = n.directory
    with node("restart-b", wait_ms=1500, directory=directory) as n, contextlib.closing(Client(n)) as c:
        n.submit(tx)
        time.sleep(1.7)
        n.make_block([])
        for _ in range(40):
            if not n.in_pool(tx["hash"]):
                break
            time.sleep(0.25)
        assert not n.in_pool(tx["hash"]), "approvals must not survive a restart"
        c.approve(tx)  # a fresh preflight + delivery makes the same signed bytes eligible again
        n.submit(tx)
        n.make_block([tx])
        assert n.receipt(tx["hash"])["status"] == "0x1"
        record("restart_drops_approvals_resubmission_after_new_preflight_included")


def coexists_with_lineth_plugins():
    """Our gate next to Lineth's own plugins, using the JARs from the linea-besu-package release."""
    if not (h.BESU_HOME / "plugins" / "linea-sequencer-linea-8bb72b4.jar").is_file():
        print("SKIP coexists_with_lineth_plugins: Lineth plugin JARs not installed in", h.BESU_HOME / "plugins")
        return

    def wait_for(node, markers, timeout=60):
        deadline = time.time() + timeout
        while True:
            log = node.log_path.read_text(errors="replace")
            missing = [m for m in markers if m not in log]
            if not missing:
                return log
            assert time.time() < deadline, missing
            time.sleep(0.5)

    # Lineth's transaction-pool validator runs in the same node as our gate, on every submission.
    with node("lineth-pool", linea_plugins=[h.LINEA_POOL_PLUGIN], wait_ms=2000) as n, contextlib.closing(Client(n)) as c:
        wait_for(n, ["Starting Linea plugin lineth.sequencer.txpoolvalidation.LineaTransactionPoolValidatorPlugin",
                     "OPS approval gate active"])
        besu = n.rpc("web3_clientVersion")
        tx = n.raw(h.ALICE, h.ROUTER, "run(uint256)", 7)
        c.approve(tx)
        time.sleep(0.2)
        n.submit(tx)
        n.make_block([tx])
        assert n.receipt(tx["hash"])["status"] == "0x1" and n.storage(h.VAULT_A) == 7
        blocked = n.raw(h.ALICE, h.ROUTER, "run(uint256)", 5)
        before = n.nonce(h.ALICE)
        n.submit(blocked)
        time.sleep(2.3)
        n.make_block([])
        for _ in range(40):
            if not n.in_pool(blocked["hash"]):
                break
            time.sleep(0.25)
        assert not n.in_pool(blocked["hash"]) and n.nonce(h.ALICE) == before
        record("gate_works_beside_lineth_transaction_pool_validator", besu=besu)

    # The full sequencer selector, ZK line-counting tracer included, on an Osaka fixture chain.
    with node("lineth-selector-osaka", linea_plugins=[h.LINEA_SELECTOR_PLUGIN], wait_ms=2000,
              fork="osaka") as n, contextlib.closing(Client(n)) as c:
        wait_for(n, ["Starting Linea plugin lineth.sequencer.txselection.LineaTransactionSelectorPlugin",
                     "OPS approval gate active"])
        tx = n.raw(h.ALICE, h.ROUTER, "run(uint256)", 7, legacy=False)
        c.approve(tx)
        time.sleep(0.2)
        n.submit(tx)
        n.make_block([tx])
        assert n.receipt(tx["hash"])["status"] == "0x1" and n.storage(h.VAULT_A) == 7
        log = n.log_path.read_text(errors="replace")
        assert "ZkTracer" in log, "Lineth's ZK tracer must have run beside ours"
        # Our gate still decides on its own: no approval, no inclusion, even though Lineth's
        # selector would have accepted the transaction.
        blocked = n.raw(h.ALICE, h.ROUTER, "run(uint256)", 5, legacy=False)
        before = n.nonce(h.ALICE)
        n.submit(blocked)
        time.sleep(2.3)
        n.make_block([])
        for _ in range(40):
            if not n.in_pool(blocked["hash"]):
                break
            time.sleep(0.25)
        assert not n.in_pool(blocked["hash"]) and n.nonce(h.ALICE) == before and n.storage(h.VAULT_A) == 7
        record("gate_works_beside_lineth_sequencer_selector_on_osaka")

    # On a pre-Osaka chain the same plugin loads and starts, but its tracer refuses the fork.
    # DEBUG: at INFO Besu reports only "Block creation failed unexpectedly" without the cause.
    with node("lineth-selector", linea_plugins=[h.LINEA_SELECTOR_PLUGIN], wait_ms=2000, log_level="DEBUG") as n, contextlib.closing(Client(n)) as c:
        wait_for(n, ["Starting Linea plugin lineth.sequencer.txselection.LineaTransactionSelectorPlugin",
                     "OPS approval gate active"])
        tx = n.raw(h.ALICE, h.ROUTER, "run(uint256)", 7)
        c.approve(tx)
        time.sleep(0.2)
        n.submit(tx)
        try:
            n.make_block([tx])
            outcome = "included"
        except RuntimeError as e:
            outcome = str(e)
        log = wait_for(n, ["Fork no more supported by the tracer"], timeout=30)
        assert "lineth.sequencer.txselection.selectors.TraceLineLimitTransactionSelector" in log
        record("lineth_sequencer_selector_loads_but_needs_an_osaka_chain", outcome=outcome[:120])


def fail_closed_startup():
    plugin_jar = h.BESU_HOME / "plugins" / h.PLUGIN_JAR.name
    hidden = plugin_jar.with_suffix(".jar.hidden")
    plugin_jar.rename(hidden)
    try:
        n = h.Node("no-jar", expect_exit=True)
        try:
            assert n.process.wait(timeout=90) != 0
            log = n.log_path.read_text(errors="replace")
            assert "requested plugins were not found: OpsApprovalPlugin" in log, log[-2000:]
        finally:
            n.close()
    finally:
        hidden.rename(plugin_jar)
    n = h.Node("no-options", expect_exit=True, configured=False)
    try:
        assert n.process.wait(timeout=90) != 0
        log = n.log_path.read_text(errors="replace")
        assert "Halting Besu: OPS approval plugin failed to start" in log, log[-2000:]
    finally:
        n.close()
    record("missing_plugin_or_configuration_refuses_to_start")


def precompile_and_value_paths():
    with node("precompile-value") as n, contextlib.closing(Client(n)) as c:
        tx = n.raw(h.ALICE, h.CALL_HASH_CASES, "identity()")
        plugin = n.rpc("ops_prepareApproval", tx["raw"])
        inner = plugin["calls"]["calls"][0]
        assert inner["type"] == "STATICCALL" and int(inner["to"], 16) == 4, inner
        c.approve(tx)
        n.submit(tx)
        n.make_block([tx])
        assert n.receipt(tx["hash"])["status"] == "0x1"
        transfer = n.raw(h.ALICE, h.ADMIN, "", value=1)
        prepared = c.prepare(transfer)
        c.send(prepared)
        n.submit(transfer)
        n.make_block([transfer])
        assert n.receipt(transfer["hash"])["status"] == "0x1"
        record("precompile_staticcall_and_plain_value_transfer_included", precompile=inner["to"])


def reorg_keeps_approvals():
    """A block that is added is not final. When the chain reorganises past it, its transactions go
    back to the pool — and they must still find their approvals there, or they wait out the
    timeout for an approval OPS will never resend. Finality lags one block so the head can be
    replaced, as it can on any real network."""
    with node("reorg") as n, contextlib.closing(Client(n)) as c:
        # Explicit nonces: both are built before either is submitted, and raw() reads the nonce from
        # the chain — with the default both would carry nonce 0 and the second would replace the first.
        txs = [n.raw(h.ALICE, h.ROUTER, "run(uint256)", 7, nonce=0), n.raw(h.ALICE, h.ROUTER, "run(uint256)", 8, nonce=1)]
        for tx in txs:
            c.approve(tx)
        time.sleep(0.2)
        for tx in txs:
            n.submit(tx)
        n.make_block(txs, finality_lag=1)  # included at height N, not final
        included_at = int(n.head["number"], 16)
        assert n.storage(h.VAULT_A) == 15  # the vault accumulates: 7 + 8
        orphaned = n.reorg_to_rival(finality_lag=1)  # rival at height N with no transactions
        assert orphaned["transactions"] == [tx["hash"] for tx in txs]
        assert n.storage(h.VAULT_A) == 0, "the reorganised block's writes must be gone"
        # Besu re-adds a reorganised block's transactions to its pool, but on 26.8.1 not reliably
        # for a sender's whole sequence (observed: nonce 1 back, nonce 0 dropped). What this
        # scenario promises is ours: the approvals are still there, so whatever returns to the pool
        # — by Besu or by the client resubmitting — is included with no new approval from OPS.
        time.sleep(1.0)
        readded = [tx["hash"] for tx in txs if n.in_pool(tx["hash"])]
        for tx in txs:
            if tx["hash"] not in readded:
                n.submit(tx)  # the same signed transaction; the Client sends nothing new
        n.make_block(txs, finality_lag=1)
        assert int(n.head["number"], 16) == included_at + 1
        assert n.storage(h.VAULT_A) == 15
        allows = {tx["hash"]: sum(1 for d in n.decisions() if f"allow tx={tx['hash']}" in d) for tx in txs}
        assert all(count >= 2 for count in allows.values()), allows  # once before the reorg, once after
        record("reorg_returns_transactions_to_the_pool_with_their_approvals_intact",
               orphaned=orphaned["hash"], reincluded_at=n.head["hash"], readded_by_besu=readded,
               resubmitted=[tx["hash"] for tx in txs if tx["hash"] not in readded])


def expired_approval_not_included():
    """An approval is usable while now < expires_at (wire contract §6): one that expires before its
    transaction is built counts as absent, so the transaction waits, is dropped when the wait window
    ends, and nothing of it reaches the chain. The store evicts the expired approval, and the same
    batch delivered again is refused as too late."""
    with node("expired", wait_ms=2000) as n, contextlib.closing(Client(n)) as c:
        tx = n.raw(h.ALICE, h.ROUTER, "run(uint256)", 7)
        envelope = c.batch(c.prepare(tx), ttl_ms=2_000)
        confirmed = c.deliver(envelope)
        assert confirmed["code"] == "OK" and confirmed["stored"] == 1, confirmed
        assert n.metric("ops_approval_store_size") == 1
        time.sleep(3.2)  # expired after 2 s; the store sweeps every second
        assert n.metric("ops_approval_store_size") == 0, "the store must evict an expired approval"
        before = n.nonce(h.ALICE), n.balance(h.ALICE)
        n.submit(tx)
        n.make_block([])
        assert n.in_pool(tx["hash"]) and n.receipt(tx["hash"]) is None, "waits within its window"
        time.sleep(2.2)
        n.make_block([])
        for _ in range(40):
            if not n.in_pool(tx["hash"]):
                break
            time.sleep(0.25)
        assert not n.in_pool(tx["hash"]) and n.receipt(tx["hash"]) is None
        assert (n.nonce(h.ALICE), n.balance(h.ALICE)) == before and n.storage(h.VAULT_A) == 0
        assert any(f"drop tx={tx['hash']}" in d for d in n.decisions()), n.decisions()
        late = c.deliver(envelope)
        assert late["code"] == "FAILED_PRECONDITION", late
        # Positive control: the same signed transaction with a fresh approval is included.
        c.approve(tx)
        n.submit(tx)
        n.make_block([tx])
        assert n.receipt(tx["hash"])["status"] == "0x1" and n.storage(h.VAULT_A) == 7
        record("expired_approval_counts_as_absent_transaction_dropped_not_included", late=late["message"])


def restart_resend_restores_inclusion():
    """The store is memory only, so a restart loses approvals OPS already had confirmed; the boot id
    tells OPS (wire contract §4). The transaction is re-announced to the restarted producer before
    OPS reconnects: it keeps waiting, because after boot the wait counts from OPS's first Status
    call; that call shows the new boot id, and resending the retained batch — the same bytes, no new
    preflight — restores inclusion."""
    with node("resend-a", wait_ms=1500) as n:
        c = Client(n)  # one OPS lane, kept across the producer's restart
        try:
            tx = n.raw(h.ALICE, h.ROUTER, "run(uint256)", 7)
            envelope = c.batch(c.prepare(tx))
            confirmed = c.deliver(envelope)
            assert confirmed["code"] == "OK" and confirmed["boot_id"] == c.boot_id, confirmed
            directory, port = n.directory, n.approval_port
        except BaseException:
            c.close()
            raise
    with contextlib.closing(c), node("resend-b", wait_ms=1500, directory=directory, approval_port=port) as n:
        n.submit(tx)  # an RPC node re-announces it at once
        time.sleep(2.0)  # past the ordinary 1.5 s window
        n.make_block([])
        assert n.in_pool(tx["hash"]), "no Status call since boot: the transaction must keep waiting"
        assert not any(f"drop tx={tx['hash']}" in d for d in n.decisions())
        status = c.status(wait_ms=15_000)  # the lane reconnects to the same address
        assert status["boot_id"] != confirmed["boot_id"], (status, confirmed)
        resent = c.deliver(envelope)
        assert resent["code"] == "OK" and resent["boot_id"] == status["boot_id"], resent
        n.make_block([tx])
        assert n.receipt(tx["hash"])["status"] == "0x1" and n.storage(h.VAULT_A) == 7
        record("restart_new_boot_id_resend_of_the_retained_batch_restores_inclusion",
               boot_before=confirmed["boot_id"], boot_after=status["boot_id"])


SCENARIOS = {f.__name__: f for f in (
    approval_first, transaction_first, no_approval_timeout, same_block_target_change, caught_inner_failure,
    delegatecall_path, wrong_fingerprint, bad_deliveries, shared_counter, deployment_included,
    runtime_lifecycle_included, snapshot_matches_the_node_state, strict_mode_binds_state, state_change_turns_call_into_lifecycle,
    resubmission_after_mismatch,
    restart_loses_approvals, reorg_keeps_approvals, coexists_with_lineth_plugins, fail_closed_startup,
    precompile_and_value_paths, expired_approval_not_included, restart_resend_restores_inclusion)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("names", nargs="*")
    args = parser.parse_args()
    h.prepare()
    for name in args.names or SCENARIOS:
        SCENARIOS[name]()
    print("ALL PASSED", len(RESULTS))


if __name__ == "__main__":
    main()
