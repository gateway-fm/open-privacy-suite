#!/usr/bin/env python3
"""Real Besu 26.8.1 + OPS approval plugin: the signed-approval scenario matrix."""
import argparse
import contextlib
import json
import os
import socket
import struct
import subprocess
import time
import harness as h

RESULTS = []


class Client:
    """Drives internal/nodeapproval (Besu mode) through the Go fixture client."""

    def __init__(self, node, connect=True):
        self.node = node
        self.process = subprocess.Popen([str(h.CLIENT), node.rpc_url], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        text=True, env=dict(os.environ, OPS_APPROVAL_NODE="besu"))
        self.socket = socket.create_connection(("127.0.0.1", node.approval_port)) if connect else None

    def _ask(self, query):
        self.process.stdin.write(json.dumps(query) + "\n")
        self.process.stdin.flush()
        return json.loads(self.process.stdout.readline())

    def prepare(self, tx, principal="did:fixture:org-a"):
        result = self._ask({"raw": tx["raw"], "principal": principal})
        assert "error" not in result, result
        return result["Approval"]

    def try_prepare(self, tx):
        return self._ask({"raw": tx["raw"], "principal": "did:fixture:org-a"})

    def batch(self, approvals):
        result = self._ask({"approvals": approvals})
        assert "error" not in result, result
        return bytes.fromhex(result["frame"])

    def go_fingerprint(self, calls, pre):
        return self._ask({"fingerprint": {"calls": calls, "pre": pre}})

    def send_frame(self, frame):
        self.socket.sendall(frame)

    def send(self, approvals):
        self.send_frame(self.batch(approvals if isinstance(approvals, list) else [approvals]))

    def approve(self, tx):
        a = self.prepare(tx)
        self.send(a)
        return a

    def close(self):
        if self.socket:
            self.socket.close()
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
    with node("timeout", wait_ms=2000) as n:
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
    with node("bad-deliveries") as n, contextlib.closing(Client(n)) as c:
        tx = n.raw(h.ALICE, h.ROUTER, "run(uint256)", 7)
        a = c.prepare(tx)
        frame = bytearray(c.batch([a]))
        frame[-1] ^= 1
        c.send_frame(bytes(frame))  # bad signature
        c.send(dict(a, chain_id=1))  # wrong chain, validly signed
        n.submit(tx)
        n.make_block([])
        assert n.in_pool(tx["hash"]), "neither a bad signature nor a foreign-chain approval may unblock"
        log = n.log_path.read_text(errors="replace")
        assert "batch rejected: bad signature" in log and "approval for chain 1 ignored" in log, log[-3000:]
        c.send([a, a])  # duplicates within one batch and a re-delivery are harmless
        c.send(a)
        n.make_block([tx])
        assert n.receipt(tx["hash"])["status"] == "0x1"
        record("bad_signature_wrong_chain_ignored_duplicates_idempotent")


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


def deployment_refused():
    with node("deployment", wait_ms=1500) as n, contextlib.closing(Client(n)) as c:
        tx = n.raw(h.ALICE, None, "0x600160005500")  # init code: SSTORE(0,1); STOP
        result = c.try_prepare(tx)
        assert "error" in result and "unsupported" in result["error"], result
        n.submit(tx)
        time.sleep(1.7)
        n.make_block([])
        for _ in range(40):
            if not n.in_pool(tx["hash"]):
                break
            time.sleep(0.25)
        assert not n.in_pool(tx["hash"])
        record("deployment_refused_at_preflight_and_dropped_by_producer", error=result["error"])


def lifecycle_refused():
    with node("lifecycle", wait_ms=1500) as n, contextlib.closing(Client(n)) as c:
        create = n.raw(h.ALICE, h.LIFE_FACTORY, "create(uint256,address)", 7, h.ADMIN)
        result = c.try_prepare(create)
        assert "error" in result and "contract creation" in result["error"], result
        destroy = n.raw(h.ALICE, h.DESTRUCTIBLE, "destroy(address)", h.ADMIN)
        result = c.try_prepare(destroy)
        assert "error" in result and "selfdestruct" in result["error"], result
        n.submit(destroy)
        time.sleep(1.7)
        n.make_block([])
        for _ in range(40):
            if not n.in_pool(destroy["hash"]):
                break
            time.sleep(0.25)
        assert not n.in_pool(destroy["hash"]) and n.balance(h.DESTRUCTIBLE) == 1000
        record("runtime_create_and_selfdestruct_refused_at_preflight_and_dropped")


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
        assert "contract creation" in denial, denial
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


SCENARIOS = {f.__name__: f for f in (
    approval_first, transaction_first, no_approval_timeout, same_block_target_change, caught_inner_failure,
    delegatecall_path, wrong_fingerprint, bad_deliveries, shared_counter, deployment_refused,
    lifecycle_refused, state_change_turns_call_into_lifecycle, resubmission_after_mismatch,
    restart_loses_approvals, fail_closed_startup, precompile_and_value_paths)}


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
