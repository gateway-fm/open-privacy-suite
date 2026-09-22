#!/usr/bin/env python3
"""Delivery latency of today's raw-TCP approval path, from OPS's own hop marks.

Reads the file OPS wrote at exit (OPS_APPROVAL_HOPS_FILE): one row per approval with
nanosecond marks — queued, sign start/end, delivery start, write start/end, and the moment the
transaction itself was forwarded. Reports the distributions that decide whether transport is a
cost worth optimising, and whether the approval leaves OPS before the transaction does.
"""
import json
import statistics
import sys
from pathlib import Path


def pct(values, q):
    if not values:
        return None
    values = sorted(values)
    return values[min(len(values) - 1, int(round(q * (len(values) - 1))))]


def dist(values, unit=1000.0):
    """p50 / p90 / p99 / max in microseconds (marks are nanoseconds)."""
    if not values:
        return None
    return {"n": len(values), "p50_us": round(pct(values, 0.5) / unit, 1), "p90_us": round(pct(values, 0.9) / unit, 1),
            "p99_us": round(pct(values, 0.99) / unit, 1), "max_us": round(max(values) / unit, 1),
            "mean_us": round(statistics.fmean(values) / unit, 1)}


def analyze(path):
    rows = json.loads(Path(path).read_text())
    complete = [r for r in rows if r.get("written") and r.get("queued")]
    out = {"file": str(path), "approvals": len(rows), "with_write_mark": len(complete)}
    out["queued_to_written"] = dist([r["written"] - r["queued"] for r in complete])
    out["queued_to_sign_start"] = dist([r["sign_start"] - r["queued"] for r in complete if r.get("sign_start")])
    out["sign_duration"] = dist([r["sign_end"] - r["sign_start"] for r in complete if r.get("sign_start") and r.get("sign_end")])
    out["sign_end_to_written"] = dist([r["written"] - r["sign_end"] for r in complete if r.get("sign_end")])
    out["write_call"] = dist([r["written"] - r["write_start"] for r in complete if r.get("write_start")])
    forwarded = [r for r in complete if r.get("forward_start")]
    # Negative = the approval was on the wire before OPS forwarded the transaction.
    lead = [r["written"] - r["forward_start"] for r in forwarded]
    out["approval_written_minus_forward_start"] = dist(lead)
    out["approval_on_wire_before_forward"] = {
        "n": len(forwarded), "count": sum(1 for v in lead if v <= 0),
        "rate": round(sum(1 for v in lead if v <= 0) / len(forwarded), 4) if forwarded else None}
    return out


if __name__ == "__main__":
    for path in sys.argv[1:] or ["evidence/gasstorm/gate-on-hops.json"]:
        print(json.dumps(analyze(path), indent=2))
