#!/usr/bin/env python3
"""Isolated real OPS HTTP service + PostgreSQL + Redis + Reth. No Python policy stub.

The Engine API driver and application/identity fixtures replace a consensus client
and external identity provider. All authorization, tracing and approval crypto are real.
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
import urllib.parse
import urllib.request
import urllib.error

import harness as h
from run import timings, machine_info

def request(url, method="GET", body=None, token=None, admin=False, allow_error=False):
    headers={"Content-Type":"application/json"}
    if token:headers["X-Admin-Token" if admin else "Authorization"]=token if admin else "Bearer "+token
    req=urllib.request.Request(url, None if body is None else json.dumps(body).encode(), headers, method=method)
    try:
        with urllib.request.urlopen(req,timeout=30) as r: data=r.read();return json.loads(data) if data else None
    except urllib.error.HTTPError as e:
        if allow_error:return {**json.loads(e.read()),"http_status":e.code}
        raise RuntimeError(f"{method} {url}: {e.code} {e.read().decode()}") from e

def docker(*args):
    return subprocess.check_output(["docker",*args],text=True).strip()

class Stack:
    def __init__(self,name,disabled=False,fork="shanghai",ops_env=None):
        self.name=name;self.disabled=disabled;self.containers=[];self.node=None;self.ops=None
        self.hash_mode=(ops_env or {}).get("OPS_APPROVAL_HASH_MODE",os.environ.get("OPS_APPROVAL_HASH_MODE","calls"))
        self.directory=h.SCRATCH / (name+"-"+str(time.time_ns()));self.directory.mkdir(parents=True)
        self.admin_token="ops-reth-local-demo-only";self.tokens={}
        try:
            prefix="ops-approvals-"+str(time.time_ns())
            pg=docker("run","-d","--rm","--name",prefix+"-pg","--label","ops-approvals-demo=true",
                "-e","POSTGRES_PASSWORD=postgres","-e","POSTGRES_DB=ops_approvals_demo",
                "-e","AUDIT_APP_PASSWORD=audit-demo-only","-p","127.0.0.1::5432",
                "-v",str(h.ROOT/"scripts/init-audit-db.sh")+":/docker-entrypoint-initdb.d/10-audit.sh:ro",
                "postgres:15-alpine")
            self.containers.append(pg)
            pgport=docker("port",pg,"5432/tcp").rsplit(":",1)[1]
            for _ in range(200):
                r=subprocess.run(["docker","exec",pg,"pg_isready","-U","postgres"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                if r.returncode==0:break
                time.sleep(.1)
            else:raise RuntimeError("Postgres startup failed")
            redis=docker("run","-d","--rm","--name",prefix+"-redis","--label","ops-approvals-demo=true",
                "-p","127.0.0.1::6379","redis:7-alpine","redis-server","--requirepass","redis-demo-only")
            self.containers.append(redis);redisport=docker("port",redis,"6379/tcp").rsplit(":",1)[1]
            self.node=h.Node(name,disabled=disabled,fork=fork)
            self.url="http://127.0.0.1:"+str(h.unused_port())
            seed=self.directory/"approval-seed.hex";seed.write_text("07"*32);seed.chmod(0o600)
            # Dedicated working directory avoids loading a developer's .env/config.
            env={k:v for k,v in os.environ.items() if k in ("PATH","HOME","TMPDIR","LANG")}
            env.update(ENVIRONMENT="development",GIN_MODE="release",PORT=self.url.rsplit(":",1)[1],BASE_URL=self.url,
                NODE_URL=self.node.rpc_url,DATABASE_URL=f"postgres://postgres:postgres@127.0.0.1:{pgport}/ops_approvals_demo?sslmode=disable",
                AUDIT_DATABASE_URL=f"postgres://privacy_proxy_app:audit-demo-only@127.0.0.1:{pgport}/ops_approvals_demo_audit?sslmode=disable",
                REDIS_URL=f"redis://:redis-demo-only@127.0.0.1:{redisport}/0",
                JWT_SECRET="ops-reth-demo-access-secret-at-least-32-bytes",JWT_REFRESH_SECRET="ops-reth-demo-refresh-secret-at-least-32-bytes",
                ADMIN_API_TOKEN=self.admin_token,ALLOW_MOCK_LOGIN="true",MOCK_SIGNATURES="false",ENABLE_TRAVEL_RULE="true",
                VERIFIER_ID="did:privado:verifier:dev-0000000000000000",DISABLE_COINGECKO="true",
                MAX_CONCURRENT_REQUESTS="128",EXPLORER_DATABASE_URL="",TRACE_TIERED_VALIDATION="false",
                AUDIT_BUFFER_DIR=str(self.directory/"audit-buffer"),DB_MAX_OPEN_CONNS="30")
            if ops_env:env.update(ops_env)
            if not disabled:env.update(OPS_APPROVAL_TARGETS=f"127.0.0.1:{self.node.approval_port}",OPS_APPROVAL_SEED_FILE=str(seed),OPS_APPROVAL_MAX_BATCH="32",OPS_APPROVAL_HASH_MODE=self.hash_mode,OPS_APPROVAL_PREFLIGHT_RATE="100000",OPS_APPROVAL_PREFLIGHT_BURST="100000")  # load runs outpace the 20/s per-principal default
            if os.environ.get("OPS_TRACE_HOPS")=="1":env["OPS_APPROVAL_HOPS_FILE"]=str(h.EVIDENCE/(name+"-ops-hops.json"))
            self.opslog=(self.directory/"ops.log").open("w")
            self.ops=subprocess.Popen([str(h.ROOT/".tmp/ops-server")],cwd=self.directory,env=env,stdout=self.opslog,stderr=subprocess.STDOUT,
                start_new_session=os.environ.get("OPS_POC_DETACH_CHILDREN")=="1")
            for _ in range(300):
                if self.ops.poll() is not None:raise RuntimeError((self.directory/"ops.log").read_text()[-7000:])
                try:request(self.url+"/health");break
                except (OSError,RuntimeError):time.sleep(.1)
            else:raise RuntimeError("OPS startup timed out")
            self.seed()
            (self.directory/"connections.json").write_text(json.dumps({"ops":self.url,"reth":self.node.rpc_url,"node_directory":str(self.node.directory),"postgres":pg,"redis":redis},indent=2))
        except BaseException:
            self.close();raise

    def admin(self,method,path,body=None):return request(self.url+"/api/v1/admin"+path,method,body,self.admin_token,True)

    def login(self,did):
        sid=request(self.url+"/auth/request","POST",{})["session_id"]
        return request(self.url+"/auth/verify","POST",{"session_id":sid,"jwz_token":"mock."+did})["access_token"]

    def seed(self):
        self.org=self.admin("POST","/orgs",{"slug":"bank-a","name":"Bank A"})["id"]
        foreign=self.admin("POST","/orgs",{"slug":"bank-b","name":"Bank B"})["id"]
        self.foreign=foreign
        group=self.admin("POST",f"/orgs/{self.org}/groups",{"slug":"payments","name":"Payments"})["id"]
        self.group=group
        self.admin("PUT",f"/orgs/{self.org}/groups/{group}/access",{"claims":[],"allowed_methods":["*"]})
        for name,addr in [("alice",h.ALICE),("operator",h.ADMIN)]:
            did="did:test:reth-demo-"+name;token=self.login(did)
            users=self.admin("GET","/users?search="+urllib.parse.quote(did));users=users if isinstance(users,list) else users["data"]
            uid=next(u["id"] for u in users if u["external_id"]==did)
            self.admin("PUT","/users/"+uid,{"kyc":True,"note":name+" (Reth demo)"})
            for m in self.admin("GET",f"/users/{uid}/memberships"):
                self.admin("DELETE",f"/users/{uid}/memberships/{m['membership']['id']}")
            self.admin("POST",f"/users/{uid}/memberships",{"group_id":group})
            token=self.login(did);self.tokens[addr]=token
            challenge=request(self.url+"/api/v1/eth/link/challenge","POST",{},token)
            signature=h.command(["cast","wallet","sign","--private-key",h.KEYS[addr],challenge["message"]])
            request(self.url+"/api/v1/eth/link/verify","POST",{"nonce":challenge["nonce"],"address":addr,"signature":signature},token)
        for addr in [h.ROUTER,h.RELAY,h.VAULT_A,h.BENCH_ROUTER,h.BENCH_RELAY,h.BENCH_VAULT,h.READ_ROUTER,h.READ_RELAY]:
            self.admin("POST",f"/orgs/{self.org}/contracts",{"address":addr,"name":"Bank A "+addr[-4:]})
            self.admin("POST",f"/orgs/{self.org}/contracts/{addr}/grants",{"group_id":group})
        self.admin("POST",f"/orgs/{foreign}/contracts",{"address":h.VAULT_B,"name":"Bank B vault"})

    def rpc(self,method,params,sender=h.ALICE):
        return request(self.url+"/rpc/"+self.org,"POST",{"jsonrpc":"2.0","id":1,"method":method,"params":params},self.tokens[sender],allow_error=True)

    def submit(self,tx):
        return self.rpc("eth_sendRawTransaction",[tx["raw"]],tx["sender"])

    def close(self):
        if self.ops is not None:
            self.ops.terminate()
            try:self.ops.wait(timeout=15)
            except subprocess.TimeoutExpired:self.ops.kill();self.ops.wait(timeout=5)
            self.opslog.close();shutil.copy2(self.directory/"ops.log",h.EVIDENCE/(self.name+"-ops.log"))
        if self.node is not None:self.node.close()
        for container in reversed(self.containers):
            subprocess.run(["docker","stop","-t","3",container],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

def announce(text,pause):
    print("\n"+text,flush=True)
    if pause:input("Press Enter to run this step... ")

def story(stack,pause=False):
    n=stack.node;out={"ops_url":stack.url,"reth_url":n.rpc_url,"checks":[]}
    announce("1. Alice calls Bank A: Router → Relay → Bank A vault. OPS checks its DB policy; Reth commits.",pause)
    tx=n.raw(h.ALICE,h.ROUTER,"run(uint256)",7)
    result=stack.submit(tx);assert result.get("result")==tx["hash"],result
    n.make_block([tx]);assert n.rpc("eth_getTransactionReceipt",tx["hash"])["status"]=="0x1"
    receipt=stack.rpc("eth_getTransactionReceipt",[tx["hash"]]);assert receipt.get("result",{}).get("status")=="0x1",receipt
    out["checks"].append({"name":"same_org_executes","tx":tx["hash"],"receipt_status":"0x1","receipt_via_OPS":receipt})
    print("PASS — real receipt:",tx["hash"],flush=True)
    announce("2. Alice tries Router → Bank B vault. OPS rejects this using the real DB organization boundary.",pause)
    foreign=n.raw(h.ALICE,h.ROUTER,"runDelegate(address,uint256)",h.VAULT_B,7)
    result=stack.submit(foreign);assert "error" in result,result
    assert n.rpc("eth_getTransactionByHash",foreign["hash"]) is None
    out["checks"].append({"name":"OPS_rejects_cross_org","response":result})
    print("PASS — OPS rejected:",json.dumps(result["error"]),flush=True)
    announce("3. OPS approves Alice's Bank A call. A higher-fee transaction then redirects Relay to Bank B before Alice executes.",pause)
    stale=n.raw(h.ALICE,h.ROUTER,"run(uint256)",9)
    result=stack.submit(stale);assert result.get("result")==stale["hash"],result
    mutation=n.raw(h.ADMIN,h.RELAY,"setTarget(address)",h.VAULT_B,fee=4_000_000_000)
    result=stack.submit(mutation);assert result.get("result")==mutation["hash"],result
    before=n.snapshot();n.make_block([mutation],denied=stale);after=n.snapshot()
    for field in ["alice_nonce","alice_balance","router","vault_a","vault_b"]:assert before[field]==after[field],(field,before,after)
    assert n.rpc("eth_getTransactionReceipt",stale["hash"]) is None
    out["checks"].append({"name":"Reth_vetoes_state_divergence","approved_tx":stale["hash"],"mutation_tx":mutation["hash"],"decisions":n.decisions(),"before":before,"after":after})
    print("PASS — Reth excluded Alice's transaction. Her nonce, balance and application writes are unchanged.",flush=True)
    print("The returned transaction hash meant submission, not successful execution.",flush=True)
    (h.EVIDENCE/"demo.json").write_text(json.dumps(out,indent=2)+"\n")

def load(stack,count=64,concurrency=16,samples=3):
    n=stack.node;rows=[];nonce=int(n.rpc("eth_getTransactionCount",h.ADMIN,"latest"),16)
    for sample in range(samples+1):
        txs=[n.raw(h.ADMIN,h.BENCH_ROUTER,"run(uint256,uint256)",10000+(sample*count+i)*32,1,nonce=nonce+i) for i in range(count)]
        # One persistent HTTP connection per worker. Key generation/signing happens
        # above, outside timing. Every timed submission still runs actual OPS gates.
        def worker(part):
            conn=http.client.HTTPConnection(urllib.parse.urlparse(stack.url).netloc,timeout=30);lat=[]
            try:
                for tx in part:
                    body=json.dumps({"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":[tx["raw"]]})
                    start=time.perf_counter_ns()
                    conn.request("POST","/rpc/"+stack.org,body,{"Content-Type":"application/json","Authorization":"Bearer "+stack.tokens[h.ADMIN]})
                    response=conn.getresponse();result=json.loads(response.read());lat.append((time.perf_counter_ns()-start)/1e6)
                    assert response.status==200 and result.get("result")==tx["hash"],result
            finally:conn.close()
            return lat
        before=len(timings(n));start=time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
            lat=sum(list(pool.map(worker,[txs[i::concurrency] for i in range(concurrency)])),[])
        submission_s=time.perf_counter()-start
        payload=n.make_block(txs)
        total_s=time.perf_counter()-start
        matches=[t for t in timings(n)[before:] if t["block_hash"]==payload["blockHash"] and t["transactions"]==count]
        assert matches,"missing Reth timing"
        for tx in txs:assert n.rpc("eth_getTransactionReceipt",tx["hash"])["status"]=="0x1"
        row={"sample":sample,"warmup":sample==0,"module":not stack.disabled,"count":count,"concurrency":concurrency,
             "submission_s":submission_s,"submission_tps":count/submission_s,"submit_to_commit_s":total_s,
             "request_median_ms":statistics.median(lat),"request_p95_ms":sorted(lat)[int(.95*(len(lat)-1))],
             "reth_us_per_tx":matches[0]["elapsed_ns"]/count/1000,"reth":matches[0]}
        rows.append(row);nonce+=count;print("LOAD",json.dumps({k:v for k,v in row.items() if k!="reth"}),flush=True)
    return rows

def main():
    p=argparse.ArgumentParser();p.add_argument("mode",choices=["story","lifecycle","load","all"],nargs="?",default="story")
    p.add_argument("--pause",action="store_true");p.add_argument("--keep",action="store_true");p.add_argument("--count",type=int,default=64);p.add_argument("--concurrency",type=int,default=16);p.add_argument("--samples",type=int,default=3)
    args=p.parse_args();h.prepare()
    if args.mode=="lifecycle":
        from lifecycle_ops_tests import tests
        tests();return
    if args.mode in ("story","all"):
        with contextlib.closing(Stack("demo")) as stack:
            story(stack,args.pause)
            if args.keep:
                print("Services stay up at",stack.url,"— Ctrl-C stops this isolated stack.",flush=True)
                try:
                    while True:time.sleep(1)
                except KeyboardInterrupt:return
    if args.mode in ("load","all"):
        rows=[]
        for disabled in (True,False):
            with contextlib.closing(Stack("live-load-"+("stock" if disabled else "module"),disabled)) as stack:
                rows.extend(load(stack,args.count,args.concurrency,args.samples))
        report={"hardware":machine_info(),"method":"Real HTTP OPS + PostgreSQL + Redis + real Reth; one warmup and measured samples per mode. Stock OPS tracing vs signed-approval preflight. Async durable audit enabled. Submission throughput excludes Engine scheduling; commit duration includes the driver's 100ms polling. No indexer/external identity provider. Sequential fixed mode order, local Docker PG/Redis: diagnostic demo, not capacity certification.","rows":rows}
        (h.EVIDENCE/"live-load.json").write_text(json.dumps(report,indent=2)+"\n")

if __name__=="__main__":main()
