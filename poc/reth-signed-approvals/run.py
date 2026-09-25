#!/usr/bin/env python3
"""Real Reth integration tests and paired, internal payload-builder benchmark."""
import argparse
import contextlib
import json
import os
import platform
from pathlib import Path
import statistics
import subprocess
import time
import threading
import harness as h

RESULTS=[]

class Client:
    """Real OPS preflight and persistent sender lanes; raw delivery is only for invalid fixtures."""
    def __init__(self,node,connect=True,hash_mode=None,stderr=None):
        self.node=node
        target=[f"127.0.0.1:{node.approval_port}"] if connect else []
        self.process=subprocess.Popen([str(h.ROOT/".tmp/approval-client"),node.rpc_url,*target],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=stderr,text=True,env=dict(os.environ, **({"OPS_APPROVAL_HASH_MODE":hash_mode} if hash_mode else {})))
    def call(self,request):
        self.process.stdin.write(json.dumps(request)+"\n");self.process.stdin.flush()
        line=self.process.stdout.readline();assert line,"approval client exited"
        return json.loads(line)
    def prepare(self,tx):
        result=self.call({"raw":tx["raw"]});assert "error" not in result,result
        return result["Approval"]
    def send(self,item,wait=True):
        """Use OPS's asynchronous sender; fixture setup can await its confirmed-member metric.
        The barrier keeps delivery outside payload measurements and avoids fetching/finalizing
        a cached empty payload while its approvals are still in flight."""
        approvals=item if isinstance(item,list) else [item]
        assert all("approvals" not in a for a in approvals),"signed batches require an explicit invalid fixture"
        confirmed="privacyproxy_approval_confirmed_total"
        before=self.metrics().get(confirmed,0) if wait else 0
        reply=self.call({"enqueue":approvals});assert reply.get("code")=="QUEUED",reply
        assert reply["queued"]==len(approvals),reply
        if wait:self.wait_metrics({confirmed:before+len(approvals)})
        return reply
    def fixture_batch(self,approvals,**times):
        """Create an authentication/expiry boundary fixture that OPS would never normally sign."""
        result=self.call({"fixture_approvals":approvals,**times});assert "error" not in result,result
        return result
    def send_fixture(self,batch,expect="OK"):
        reply=self.call({"fixture_deliver":batch});assert reply.get("code")==expect,(reply,expect)
        return reply
    def send_fixture_envelope(self,envelope,expect):
        reply=self.call({"fixture_envelope":envelope});assert reply.get("code")==expect,(reply,expect)
        return reply
    def metrics(self):
        reply=self.call({"metrics":True});assert "error" not in reply,reply
        return reply
    def wait_metrics(self,expected,seconds=10):
        deadline=time.monotonic()+seconds
        while True:
            metrics=self.metrics()
            if all(metrics.get(k,0)>=v for k,v in expected.items()):return metrics
            assert time.monotonic()<deadline,(expected,metrics)
            time.sleep(.05)
    def approve(self,tx):
        a=self.prepare(tx);self.send(a);return a
    def close(self):
        try:
            with contextlib.suppress(BrokenPipeError):self.process.stdin.close()
            try:self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill();self.process.wait(timeout=5)
        finally:
            self.process.stdout.close()

def with_member_domain(envelope,index,domain):
    """The envelope with one approval's 16-byte domain replaced (layout: contract §2)."""
    b=bytearray.fromhex(envelope);at=43+b[22]+120*index;b[at:at+16]=domain;return b.hex()

def gone_from_pool(n,tx,seconds=3):
    deadline=time.monotonic()+seconds
    while n.rpc("eth_getTransactionByHash",tx["hash"]) is not None:
        assert time.monotonic()<deadline,"transaction still pooled: "+tx["hash"]
        time.sleep(.05)

@contextlib.contextmanager
def node(name,**kwargs):
    n=h.Node(name,**kwargs)
    try:yield n
    finally:n.close()

def record(name,**details):
    RESULTS.append({"test":name,"passed":True,**details});print("PASS",name,details,flush=True)
    (h.EVIDENCE/"tests.json").write_text(json.dumps(RESULTS,indent=2)+"\n")

def ordinary():
    with node("allow") as n,contextlib.closing(Client(n)) as c:
        tx=n.raw(h.ALICE,h.ROUTER,"run(uint256)",7);c.approve(tx);n.submit(tx);n.make_block([tx])
        assert int(n.rpc("eth_getStorageAt",h.VAULT_A,"0x0","latest"),16)==7
        assert n.rpc("eth_getTransactionReceipt",tx["hash"])["status"]=="0x1"
        record("same_org_nested_call_executes",hash=tx["hash"])
        tx=n.raw(h.ALICE,h.ROUTER,"runDelegate(address,uint256)",h.VAULT_A,3)
        c.approve(tx);n.submit(tx);n.make_block([tx])
        assert int(n.rpc("eth_getStorageAt",h.VAULT_A,"0x0","latest"),16)==7
        record("delegatecall_uses_caller_storage")
        tx=n.raw(h.ALICE,h.BENCH_VAULT,"put(uint256,uint256)",77,7,legacy=False)
        c.approve(tx);n.submit(tx);n.make_block([tx]);record("EIP1559_signed_transaction")

def divergence(name,catch=False,storage_only=False,disabled=False):
    with node(name,disabled=disabled,reverting_foreign=catch) as n:
        c=None if disabled else Client(n,hash_mode="strict" if storage_only else None)
        try:
            tx=n.raw(h.ALICE,h.ROUTER,"runCatch(uint256)" if catch else "run(uint256)",7)
            mut=n.raw(h.ADMIN,h.VAULT_A if storage_only else h.RELAY,"note(uint256)" if storage_only else "setTarget(address)",1 if storage_only else h.VAULT_B,fee=4_000_000_000)
            if c:c.approve(tx);c.approve(mut)
            n.submit(tx);n.submit(mut);before=n.snapshot()
            n.make_block([mut,tx] if disabled else [mut],denied=None if disabled else tx)
            if not disabled:
                after=n.snapshot();assert before["alice_nonce"]==after["alice_nonce"];assert before["alice_balance"]==after["alice_balance"]
                assert before["router"]==after["router"];assert before["vault_b"]==after["vault_b"]
                assert n.rpc("eth_getTransactionReceipt",tx["hash"]) is None
            else:assert int(n.rpc("eth_getStorageAt",h.VAULT_B,"0x0","latest"),16)==7
            record(name,hash=tx["hash"])
        finally:
            if c:c.close()

def read_only():
    with node("read-only-cross-org") as n,contextlib.closing(Client(n)) as c:
        tx=n.raw(h.ALICE,h.READ_ROUTER,"probe()")
        c.approve(tx);n.submit(tx);before=n.snapshot();n.make_block([],denied=tx)
        assert n.snapshot()==before
        record("no_write_cross_org_call_denied_despite_identical_return_and_storage")

def fingerprint_cases():
    with node("fingerprint-cases") as n,contextlib.closing(Client(n)) as c:
        for value in [7,0,0]:
            tx=n.raw(h.ALICE,h.BENCH_VAULT,"put(uint256,uint256)",991,value)
            c.approve(tx);n.submit(tx);n.make_block([tx])
            assert n.rpc("eth_getTransactionReceipt",tx["hash"])["status"]=="0x1"
        tx=n.raw(h.ALICE,h.BENCH_VAULT,"values(uint256)",991)
        c.approve(tx);n.submit(tx);n.make_block([tx])
        record("fingerprint_zero_deletion_unchanged_write_and_read")
        tx=n.raw(h.ALICE,h.FINGERPRINT_CASES,"mixed()")
        c.approve(tx);n.submit(tx);n.make_block([tx])
        receipt=n.rpc("eth_getTransactionReceipt",tx["hash"])
        assert receipt["status"]=="0x1" and len(receipt["logs"])==3
        record("fingerprint_log_positions_dynamic_output_and_caught_revert")

def waits():
    with node("waiting",wait_ms=1200) as n,contextlib.closing(Client(n)) as c:
        waiting=n.raw(h.ALICE,h.BENCH_VAULT,"put(uint256,uint256)",1,7)
        ready=n.raw(h.ADMIN,h.BENCH_VAULT,"put(uint256,uint256)",2,7)
        approval=c.prepare(waiting);c.approve(ready)
        n.submit(waiting);n.submit(ready);start=time.monotonic();n.make_block([ready]);elapsed=time.monotonic()-start
        assert elapsed<1.2,elapsed
        c.send(approval);n.make_block([waiting]);record("waiting_tx_does_not_block_ready_sender",ready_block_wall_ms=round(elapsed*1000,2))
        missing=n.raw(h.ALICE,h.BENCH_VAULT,"put(uint256,uint256)",3,7);a=c.prepare(missing);n.submit(missing)
        gone_from_pool(n,missing)
        c.send(a);n.submit(missing);n.make_block([missing]);record("timeout_then_client_retry_same_signed_tx")

def waiting_load():
    with node("waiting-load",wait_ms=2000) as n,contextlib.closing(Client(n)) as c:
        pending=[n.raw(h.ALICE,h.BENCH_VAULT,"put(uint256,uint256)",i,7,nonce=i) for i in range(128)]
        ready=n.raw(h.ADMIN,h.BENCH_VAULT,"put(uint256,uint256)",1000,7);c.approve(ready)
        for tx in pending:n.submit(tx)
        n.submit(ready);start=time.monotonic();n.make_block([ready]);elapsed=time.monotonic()-start
        assert elapsed<2,elapsed
        record("128_missing_approvals_do_not_block_ready_sender",ready_block_wall_ms=elapsed*1000)

def invalid():
    with node("invalid",wait_ms=400) as n,contextlib.closing(Client(n)) as c:
        tx=n.raw(h.ALICE,h.BENCH_VAULT,"put(uint256,uint256)",5,7);batch=c.fixture_batch([c.prepare(tx)])
        refused=c.send_fixture(dict(batch,signature="00"*64),expect="UNAUTHENTICATED")
        n.submit(tx);time.sleep(.6);n.make_block([])
        assert n.rpc("eth_getTransactionReceipt",tx["hash"]) is None
        c.send(batch["approvals"]);n.submit(tx);n.make_block([tx]);record("forged_signature_denied_then_valid_retry",refusal=refused)

def expiry():
    """Contract §6: an approval is usable while now < expires_at; an expired one counts as absent.
    §3 checks 5-7: late, over-long and future-dated batches are refused and store nothing."""
    with node("expiry",wait_ms=3000) as n,contextlib.closing(Client(n)) as c:
        pooled=n.raw(h.ALICE,h.BENCH_VAULT,"put(uint256,uint256)",11,7)
        late=n.raw(h.ADMIN,h.BENCH_VAULT,"put(uint256,uint256)",12,7)
        a,b=c.prepare(pooled),c.prepare(late)
        # Stored and pooled in time, but no block is built before the approval expires.
        c.send_fixture(c.fixture_batch([a],ttl_ms=800));n.submit(pooled)
        time.sleep(1.2);n.make_block([])
        assert n.rpc("eth_getTransactionByHash",pooled["hash"]) is not None,"dropped before its wait window ended"
        # A fresh approval (later issued_at) replaces the expired one within the window.
        c.send(a);n.make_block([pooled])
        record("expired_approval_is_absent_at_the_gate_then_fresh_approval_is_used",hash=pooled["hash"])
        # Delivered in time, expired before the transaction arrives: it waits and is dropped.
        c.send_fixture(c.fixture_batch([b],ttl_ms=300));time.sleep(.5);n.submit(late)
        gone_from_pool(n,late,seconds=5);n.make_block([])
        assert n.rpc("eth_getTransactionReceipt",late["hash"]) is None
        now=int(time.time()*1000);hour=3_600_000
        refusals={
            "expired":c.send_fixture(c.fixture_batch([b],issued_at=now-2000,expires_at=now-1000),expect="FAILED_PRECONDITION"),
            "lifetime_above_max_ttl":c.send_fixture(c.fixture_batch([b],issued_at=now,expires_at=now+hour+1),expect="INVALID_ARGUMENT"),
            "issued_ahead_of_clock":c.send_fixture(c.fixture_batch([b],issued_at=now+60_000,expires_at=now+120_000),expect="FAILED_PRECONDITION"),
        }
        n.submit(late);time.sleep(.3);n.make_block([])
        stats=timings(n)[-1]["approval_stats"]
        assert stats["expired_approvals"]>=2 and stats["invalid_envelopes"]==3,stats
        c.send(b);n.make_block([late])
        record("approval_expiring_before_arrival_drops_the_transaction_and_refused_batches_store_nothing",refusals=refusals,stats=stats)

def real_ops():
    with node("real-ops") as n:
        tx=n.raw(h.ALICE,h.ROUTER,"run(uint256)",7)
        foreign=n.raw(h.ALICE,h.VAULT_B,"note(uint256)",7)
        nested=n.raw(h.ALICE,h.ROUTER,"runDelegate(address,uint256)",h.VAULT_B,7)
        path=h.EVIDENCE/"ops-inputs.json";path.write_text(json.dumps({"allow":tx["raw"],"foreign":foreign["raw"],"nested_foreign":nested["raw"]}))
        env=dict(os.environ,OPS_TEST_RETH_URL=n.rpc_url,OPS_TEST_APPROVAL_TARGET=f"127.0.0.1:{n.approval_port}",OPS_TEST_TX_FILE=str(path))
        with (h.EVIDENCE/"ops-integration.log").open("w") as log:
            result=subprocess.run([str(h.ROOT/".tmp/server-approval.test"),"-test.run","^TestNodeApprovalsRealReth$","-test.v"],env=env,cwd=h.ROOT/"internal/server",stdout=log,stderr=subprocess.STDOUT)
        assert result.returncode==0,(h.EVIDENCE/"ops-integration.log").read_text()[-7000:]
        n.make_block([tx]);record("real_OPS_DB_RBAC_trace_signature_forwarding_and_Reth_commit",hash=tx["hash"])

def restart():
    with node("restart-before",wait_ms=500) as n,contextlib.closing(Client(n)) as c:
        tx=n.raw(h.ALICE,h.ROUTER,"run(uint256)",7);c.approve(tx);n.submit(tx)
        directory=n.directory
    with node("restart-after",wait_ms=500,directory=directory) as n,contextlib.closing(Client(n)) as c:
        # The store lived in memory; with nothing redelivered the restored transaction times out.
        gone_from_pool(n,tx)
        n.make_block([])
        assert n.rpc("eth_getTransactionReceipt",tx["hash"]) is None
        # User sends the same signed tx; OPS does a fresh preflight and delivers approval.
        c.approve(tx);n.submit(tx);n.make_block([tx]);record("actual_restart_loses_approval_then_client_retry_succeeds")

def restart_resend():
    """Keep the real OPS sender alive while Reth restarts: its lane alone detects the new boot
    id and redelivers retained signed bytes. No new preflight, enqueue, Deliver or tx submission."""
    with contextlib.ExitStack() as cleanup:
        sender_log=cleanup.enter_context((h.EVIDENCE/"restart-recovery-sender.log").open("w"))
        with node("resend-before",wait_ms=500) as n:
            c=Client(n,stderr=sender_log)
            cleanup.callback(c.close)
            tx=n.raw(h.ALICE,h.ROUTER,"run(uint256)",9)
            c.approve(tx)
            before=c.wait_metrics({"privacyproxy_approval_batches_total/OK":1,"privacyproxy_approval_retained":1})
            assert before["privacyproxy_approval_redeliveries_total"]==0,before
            n.submit(tx)
            directory,port=n.directory,n.approval_port
        time.sleep(1.5)
        with node("resend-after",wait_ms=500,directory=directory,approval_port=port) as n:
            after=c.wait_metrics({"privacyproxy_approval_redeliveries_total":1,"privacyproxy_approval_batches_total/OK":2})
            assert c.process.poll() is None,"OPS sender must survive the producer restart"
            n.make_block([tx])
            assert n.rpc("eth_getTransactionReceipt",tx["hash"])["status"]=="0x1"
            stats=timings(n)[-1]["approval_stats"]
            assert stats["verified"]==1,stats
            record("persistent_OPS_sender_automatically_redelivers_after_Reth_restart",
                   redeliveries=after["privacyproxy_approval_redeliveries_total"],
                   delivered_batches=after["privacyproxy_approval_batches_total/OK"],
                   receiver_verified=stats["verified"])

def reorg():
    """Contract §6: an approval stays until the block that included its transaction is final, so a
    transaction a reorganisation returns to the pool is included again with no new approval."""
    with node("reorg-producer") as n,node("reorg-rival",disabled=True) as rival,contextlib.closing(Client(n)) as c:
        genesis=n.head["hash"]
        tx=n.raw(h.ALICE,h.ROUTER,"run(uint256)",7);c.approve(tx);n.submit(tx)
        n.make_block([tx],finalized=genesis)
        # Past the store's 1 s pool re-check: the approval must outlive the transaction's pool stay.
        time.sleep(2)
        # Another producer's block at the same height, without the transaction, becomes canonical.
        other=rival.make_block([],fee_recipient=h.ALICE)
        assert n.engine("engine_newPayloadV2",other)["status"]=="VALID"
        state={"headBlockHash":other["blockHash"],"safeBlockHash":genesis,"finalizedBlockHash":genesis}
        assert n.engine("engine_forkchoiceUpdatedV2",state,None)["payloadStatus"]["status"]=="VALID"
        n.head=n.rpc("eth_getBlockByNumber","latest",False);assert n.head["hash"]==other["blockHash"]
        deadline=time.monotonic()+5
        while (n.rpc("eth_getTransactionByHash",tx["hash"]) or {}).get("blockHash") is not None:
            assert time.monotonic()<deadline,"reorganised transaction did not return to the pool"
            time.sleep(.05)
        n.make_block([tx])
        stats=timings(n)[-1]["approval_stats"]
        assert stats["verified"]==1,stats
        assert n.rpc("eth_getTransactionReceipt",tx["hash"])["status"]=="0x1"
        record("reorg_returns_the_transaction_and_its_kept_approval_includes_it_again",block=n.head["hash"],stats={k:stats[k] for k in ("verified","released_on_finality")})

def history():
    with node("history-producer") as producer,contextlib.closing(Client(producer)) as c:
        tx=producer.raw(h.ALICE,h.ROUTER,"run(uint256)",7);c.approve(tx);producer.submit(tx);payload=producer.make_block([tx])
    with node("history-importer") as importer:
        # Fresh module with no approvals must replay a valid block through the stock executor.
        result=importer.engine("engine_newPayloadV2",payload);assert result["status"]=="VALID",result
        record("historical_import_without_approvals",block=payload["blockHash"])

def timings(n):
    return [json.loads(line.split("OPS_BUILD_TIMING ",1)[1]) for line in n.log_path.read_text().splitlines() if "OPS_BUILD_TIMING " in line]

def bench(samples=9,batch=32):
    measurements=[]
    # Alternate execution order across pairs to reduce temperature/order bias.
    for workload,count in [("single_storage_write",0),("three_calls",1),("eighteen_calls",16)]:
        for pair in range(3):
            for enabled in ([False,True] if pair%2==0 else [True,False]):
                with node(f"bench-{workload}-{pair}-{int(enabled)}",disabled=not enabled) as n:
                    c=Client(n,connect=enabled)
                    try:
                        for sample in range(samples//3+1):
                            txs=[]; approvals=[]
                            for i in range(batch):
                                key=(sample*batch+i)*32
                                if count:tx=n.raw(h.ALICE,h.BENCH_ROUTER,"run(uint256,uint256)",key,count,nonce=sample*batch+i,gas=600000)
                                else:tx=n.raw(h.ALICE,h.BENCH_VAULT,"put(uint256,uint256)",key,7,nonce=sample*batch+i,gas=100000)
                                approval=c.prepare(tx)
                                approvals.append(approval)
                                txs.append(tx)
                            if enabled:c.send(approvals)
                            # Delivery, and its OK, is outside the timed region.
                            for tx in txs:n.submit(tx)
                            before=len(timings(n));payload=n.make_block(txs)
                            matches=[t for t in timings(n)[before:] if t["block_hash"]==payload["blockHash"] and t["transactions"]==batch]
                            assert matches, "missing in-process timing"
                            if sample:measurements.append({"workload":workload,"pair":pair,"module":enabled,"sample":sample,**matches[0]})
                            print("BENCH",workload,enabled,pair,sample,matches[0]["elapsed_ns"],flush=True)
                    finally:
                        if c:c.close()
    write_benchmark_report(measurements,batch)

def machine_info():
    info={"os":platform.platform(),"architecture":platform.machine(),"logical_cpus":os.cpu_count()}
    if platform.system()=="Darwin":
        for name,key in [("machdep.cpu.brand_string","cpu"),("hw.memsize","memory_bytes")]:
            value=subprocess.check_output(["sysctl","-n",name],text=True).strip()
            info[key]=int(value) if key=="memory_bytes" else value
    return info

def write_benchmark_report(measurements,batch):
    summary=[]
    for workload in sorted({x["workload"] for x in measurements}):
        rows={enabled:[x["elapsed_ns"]/batch/1000 for x in measurements if x["workload"]==workload and x["module"]==enabled] for enabled in [False,True]}
        pairs={x["pair"] for x in measurements if x["workload"]==workload}
        final_stats=[]
        for pair in pairs:
            enabled=[x for x in measurements if x["workload"]==workload and x["pair"]==pair and x["module"]]
            final_stats.append(max(enabled,key=lambda x:x["sample"])["approval_stats"])
            for x in enabled:
                control=next(y for y in measurements if y["workload"]==workload and y["pair"]==pair and y["sample"]==x["sample"] and not y["module"])
                assert control["block_hash"]==x["block_hash"], "control and module produced different blocks"
        b,m=statistics.median(rows[False]),statistics.median(rows[True])
        summary.append({"workload":workload,"batch":batch,"samples_per_mode":len(rows[False]),"baseline_us_per_tx":b,"module_us_per_tx":m,"extra_us_per_tx":m-b,"time_increase_percent":(m/b-1)*100,"throughput_decrease_percent":(1-b/m)*100,"baseline_range_us":[min(rows[False]),max(rows[False])],"module_range_us":[min(rows[True]),max(rows[True])],"signature_verification_mean_us":sum(x["verification_ns"] for x in final_stats)/sum(x["verified"] for x in final_stats)/1000,"ready_on_first_seen":sum(x["ready_on_first_seen"] for x in final_stats),"waiting_on_first_seen":sum(x["waiting_on_first_seen"] for x in final_stats)})
    report={"method":"Instant around real Reth default_ethereum_payload including execution and state/receipt roots; divided by included tx count. Identical preflight warming in BOTH modes. Excludes RPC/preflight/approval delivery/wait and engine import. Same block hashes asserted for every control/module pair.","hardware":machine_info(),"build":{"rustc":subprocess.check_output(["rustc","--version"],text=True).strip(),"profile":"release opt-level=3 lto=false codegen-units=16","reth_commit":h.RETH_COMMIT},"raw":measurements,"summary":summary}
    (h.EVIDENCE/"benchmark.json").write_text(json.dumps(report,indent=2)+"\n");print(json.dumps(summary,indent=2),flush=True)

def node_scenarios():
    """Everything that needs only the node and the fixture client, not an OPS server."""
    divergence("same_block_cross_org_divergence");divergence("caught_call_cannot_bypass",catch=True);divergence("same_org_storage_divergence",storage_only=True);divergence("stock_control_executes_cross_org",disabled=True)
    read_only();fingerprint_cases();waits();waiting_load();invalid();expiry();restart();restart_resend();reorg();history()

if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("mode",choices=["smoke","node","test","bench","all"]);args=parser.parse_args();h.prepare()
    if args.mode in ["smoke","node","test","all"]:ordinary()
    if args.mode in ["node","test","all"]:node_scenarios()
    if args.mode in ["test","all"]:real_ops()
    if args.mode in ["bench","all"]:bench()
