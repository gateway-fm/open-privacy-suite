#!/usr/bin/env python3
"""Compare same-host, opt-in pipeline timestamps. No packet capture claims."""
import json
from pathlib import Path
import re
import statistics
import sys

PHASES=[("signer_queue","queued","sign_start"),("signing","sign_start","sign_end"),
        ("sender_queue","sign_end","delivery_start"),("encoding","delivery_start","encoded"),
        ("socket_write","write_start","written"),("write_to_read_complete","write_start","received"),
        ("verification_queue","received","worker_start"),("decoding","worker_start","parsed"),
        ("signature_verification","parsed","verified"),("publication","verified","published"),
        ("approval_total","queued","published"),("tx_forward_to_pool","forward_start","pool_inserted")]

def distribution(values):
    v=sorted(values)
    return {"median":statistics.median(v),"mean":statistics.mean(v),"p95":v[int(.95*(len(v)-1))],"max":max(v)}

def analyze(directory):
    d=Path(directory)
    go=json.loads((d/"live-load-module-ops-hops.json").read_text())
    node=json.loads((d/"live-load-module-node-hops.json").read_text())
    rows=[dict(g,**node[g["hash"]]) for g in go if g["hash"] in node and node[g["hash"]]["pool_inserted"]]
    assert len(rows)==len(go),"missing node timestamps"
    def summarize(rows):
        return {"count":len(rows),"read_complete_after_pool":sum(r["received"]>r["pool_inserted"] for r in rows),
                "published_after_pool":sum(r["published"]>r["pool_inserted"] for r in rows),
                "microseconds":{label:distribution([(r[b]-r[a])/1000 for r in rows]) for label,a,b in PHASES}}
    out={"all":summarize(rows),"after_64_tx_warmup":summarize(rows[64:]),
         "method":"Same-host Unix timestamps; opt-in instrumentation. Write-to-read includes kernel transport, reader scheduling and any previous frame processing; it is not pure network latency."}
    log=(d/"live-load-module-ops.log").read_text()
    out["connection_counts"]=list(map(int,re.findall(r'approval connections used.*count=(\d+)',log)))
    (d/"pipeline.json").write_text(json.dumps(out,indent=2)+"\n")
    return out

if __name__=="__main__":
    print(json.dumps({str(d):analyze(d) for d in sys.argv[1:]},indent=2))
