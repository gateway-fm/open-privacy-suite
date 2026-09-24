#!/usr/bin/env python3
"""Real Reth integration tests and paired, internal payload-builder benchmark."""
import argparse
import contextlib
import json
import os
import platform
from pathlib import Path
import socket
import statistics
import struct
import subprocess
import time
import threading
import harness as h

RESULTS=[]

class Client:
    def __init__(self,node,connect=True,hash_mode=None):
        self.node=node
        self.process=subprocess.Popen([str(h.ROOT/".tmp/approval-client"),node.rpc_url],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True,env=dict(os.environ, **({"OPS_APPROVAL_HASH_MODE":hash_mode} if hash_mode else {})))
        self.socket=socket.create_connection(("127.0.0.1",node.approval_port)) if connect else None
    def prepare(self,tx):
        self.process.stdin.write(json.dumps({"raw":tx["raw"],"principal":"did:fixture:org-a"})+"\n");self.process.stdin.flush()
        result=json.loads(self.process.stdout.readline());assert "error" not in result,result
        return result["Approval"]
    def send(self,approval):
        data=json.dumps(approval).encode();self.socket.sendall(struct.pack(">I",len(data))+data)
    def batch(self,approvals):
        self.process.stdin.write(json.dumps({"approvals":approvals})+"\n");self.process.stdin.flush()
        result=json.loads(self.process.stdout.readline());assert "error" not in result,result
        return result
    def approve(self,tx):
        a=self.prepare(tx);self.send(a);return a
    def close(self):
        if self.socket:self.socket.close()
        self.process.stdin.close();self.process.wait(timeout=5);self.process.stdout.close()

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
        deadline=time.monotonic()+3
        while time.monotonic()<deadline:
            if n.rpc("eth_getTransactionByHash",missing["hash"]) is None:break
            time.sleep(.05)
        else:raise AssertionError("missing approval not dropped")
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
        tx=n.raw(h.ALICE,h.BENCH_VAULT,"put(uint256,uint256)",5,7);a=c.prepare(tx)
        bad=dict(a,signature="00"*64);c.send(bad);n.submit(tx);time.sleep(.6);n.make_block([])
        assert n.rpc("eth_getTransactionReceipt",tx["hash"]) is None
        c.send(a);n.submit(tx);n.make_block([tx]);record("forged_signature_denied_then_valid_retry")

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
        time.sleep(.7)
        n.make_block([])
        assert n.rpc("eth_getTransactionReceipt",tx["hash"]) is None
        # User sends the same signed tx; OPS does a fresh preflight and delivers approval.
        c.approve(tx);n.submit(tx);n.make_block([tx]);record("actual_restart_loses_approval_then_client_retry_succeeds")

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
                            if enabled:c.send(c.batch(approvals))
                            # Network delivery is outside the timed region. No module ACK is used.
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

if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("mode",choices=["smoke","test","bench","all"]);args=parser.parse_args();h.prepare()
    if args.mode in ["smoke","test","all"]:ordinary()
    if args.mode in ["test","all"]:
        divergence("same_block_cross_org_divergence");divergence("caught_call_cannot_bypass",catch=True);divergence("same_org_storage_divergence",storage_only=True);divergence("stock_control_executes_cross_org",disabled=True)
        read_only();fingerprint_cases();waits();waiting_load();invalid();real_ops();restart();history()
    if args.mode in ["bench","all"]:bench()
