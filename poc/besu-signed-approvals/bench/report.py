#!/usr/bin/env python3
"""Join sender and receiver records by frame digest; report one-way delivery and ack round trip."""
import json, statistics, sys

def pct(v, q):
    v = sorted(v); return v[min(len(v) - 1, int(round(q * (len(v) - 1))))] if v else None

def load(path):
    return [json.loads(l) for l in open(path) if l.strip()]

def main(transport, sender, receiver):
    sent = {r["id"]: r for r in load(sender)}
    recv = {r["id"]: r for r in load(receiver)}
    joined = [(recv[i]["recv_ns"] - s["sent_ns"]) / 1000.0 for i, s in sent.items() if i in recv]
    acks = [(s["ack_ns"] - s["sent_ns"]) / 1000.0 for s in sent.values() if s.get("ack_ns")]
    span = (max(s["sent_ns"] for s in sent.values()) - min(s["sent_ns"] for s in sent.values())) / 1e9
    row = {"transport": transport, "sent": len(sent), "received": len(recv), "matched": len(joined),
           "achieved_batches_per_s": round(len(sent) / span, 1) if span else None,
           "one_way_us": {"p50": round(pct(joined, .5), 1), "p90": round(pct(joined, .9), 1),
                          "p99": round(pct(joined, .99), 1), "max": round(max(joined), 1),
                          "mean": round(statistics.fmean(joined), 1)} if joined else None,
           "ack_rtt_us": {"p50": round(pct(acks, .5), 1), "p99": round(pct(acks, .99), 1)} if acks else None,
           "frame_bytes": next(iter(sent.values()))["bytes"]}
    print(json.dumps(row))
    return row

if __name__ == "__main__":
    main(*sys.argv[1:4])
