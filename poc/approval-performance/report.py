#!/usr/bin/env python3
"""Compact summaries of the local performance evidence, without machine paths.

Histogram percentiles are reported as bucket upper bounds, not exact timings.
Delivery histograms cover first deliveries of batches, not replayed batches.
"""
import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import re

from delivery import metric


def histogram(snapshot):
    for family in snapshot["metrics"]:
        if family["name"] == "privacyproxy_approval_delivery_seconds":
            return family["metric"][0]["histogram"]
    return {"sample_count": 0, "bucket": []}


def bounds(buckets, count):
    if not count:
        return None
    result = {}
    for name, q in [("p50", .5), ("p95", .95), ("p99", .99)]:
        bound = next((le for le, n in sorted(buckets.items()) if n >= math.ceil(count*q)), math.inf)
        result[name] = bound*1000 if math.isfinite(bound) else "> largest finite bucket"
    return result


def delivery_latency(before, after):
    old, new = histogram(before), histogram(after)
    old_buckets = {x["upper_bound"]: x["cumulative_count"] for x in old["bucket"]}
    buckets = {x["upper_bound"]: x["cumulative_count"]-old_buckets.get(x["upper_bound"], 0)
               for x in new["bucket"]}
    return bounds(buckets, new["sample_count"]-old["sample_count"])


def rpc_latency(directory):
    def read(path):
        buckets, count = {}, 0
        for line in path.read_text().splitlines():
            if 'rpc_method="eth_sendRawTransaction"' not in line:
                continue
            if "_rpc_request_duration_seconds_bucket{" in line:
                le = float(re.search(r'le="([^"]+)"', line)[1])
                buckets[le] = float(line.rsplit(" ", 1)[1])
            elif "_rpc_request_duration_seconds_count{" in line:
                count += float(line.rsplit(" ", 1)[1])
        return buckets, count
    old, old_count = read(directory / "metrics-before.txt")
    new, new_count = read(directory / "metrics-after.txt")
    return bounds({le: n-old.get(le, 0) for le, n in new.items()}, new_count-old_count)


def counter_delta(directory, family, filters, label):
    def read(path):
        counts = Counter()
        for line in path.read_text().splitlines():
            if not line.startswith(family + "{"):
                continue
            labels = dict(re.findall(r'(\w+)="([^"]*)"', line.split("}", 1)[0]))
            if all(labels.get(key) == value for key, value in filters.items()):
                counts[labels[label]] += float(line.rsplit(" ", 1)[1])
        return counts
    return dict(read(directory / "metrics-after.txt") - read(directory / "metrics-before.txt"))


def summarize(directory):
    path = directory / "delivery.json"
    if path.exists():
        data = json.loads(path.read_text())
        phases = []
        for phase in data["phases"]:
            before, after, run = phase["before"], phase["after"], phase["run"]
            phases.append({"name": phase["name"], **run, "drain": phase["drain"],
                "fresh_delivery_ms_upper_bounds": delivery_latency(before, after),
                "confirmations_during_sending": None if "confirmed_at_end" not in run else
                    run["confirmed_at_end"]-metric(before, "confirmed_total"),
                "confirmations_total_delta": metric(after, "confirmed_total")-metric(before, "confirmed_total"),
                "delivery_calls_delta": metric(after, "batches_total")-metric(before, "batches_total"),
                "retry_calls_delta": metric(after, "retries_total")-metric(before, "retries_total"),
                "retained": metric(after, "retained"),
                "evicted_delta": metric(after, "evicted_total")-metric(before, "evicted_total"),
                "unconfirmed_dropped_delta": metric(after, "dropped_total")-metric(before, "dropped_total"),
                "sender_live_heap_bytes": after["heap_alloc_bytes"],
                "gc_pause_ns_delta": after["gc_pause_total_ns"]-before["gc_pause_total_ns"],
                "node_restart_seconds": phase.get("node_restart_seconds"),
                "pending_probe": phase.get("pending_probe")})
        result = {k: data[k] for k in ("kind", "node", "rate", "seconds", "capacity", "retain", "ttl")}
        result.update(phases=phases, verify_workers=data.get("verify_workers", 2),
                      warmup_seconds=data.get("warmup", {}).get("run", {}).get("elapsed_seconds", 0))
        result["error"] = data.get("error")
    else:
        path = directory / "transactions-report.json"
        data = json.loads(path.read_text())
        result = {k: data[k] for k in ("kind", "node", "requested_rate", "seconds", "gate", "retain")}
        result.update(receipts=data.get("receipts"), rpc_ms_upper_bounds=rpc_latency(directory))
        result["max_concurrent_requests"] = data.get("max_concurrent_requests", 5000)
        result["verify_workers"] = data.get("verify_workers", 2)
        result["send_rpc_outcomes"] = counter_delta(directory, "privacyproxy_rpc_requests_total",
            {"rpc_method": "eth_sendRawTransaction"}, "outcome")
        result["all_rpc_http_statuses"] = counter_delta(directory, "privacyproxy_http_requests_total",
            {"method": "POST", "path": "/rpc/:org_id"}, "status")
        status = data.get("status", {})
        result["generator"] = {k: status.get(k) for k in ("txSent", "txConfirmed", "txFailed", "status")}
        receipts = json.loads((directory / "receipts.json").read_text())
        missing = {row["hash"] for row in receipts if row["receipt"] is None}
        logs = json.loads((directory / "transactions.json").read_text())
        statuses = {row["txHash"].lower(): row.get("status", "unknown") for row in logs if row.get("txHash")}
        result["missing_by_generator_status"] = dict(Counter(statuses.get(tx, "unknown") for tx in missing))
        result["loadgen_sha256"] = data["loadgen_sha256"]
        result["error"] = data.get("error")
    result["case"] = directory.name
    result["source_report_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    result["supporting_files_sha256"] = {name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
        for name in ("metrics-before.txt", "metrics-after.txt", "transactions.json", "receipts.json")
        if (directory / name).exists()}
    samples = data.get("memory_samples", [])
    result["peak_rss_bytes"] = {name: max(s.get(name, 0) for s in samples)
                                for name in (samples[0] if samples else []) if name.endswith("_rss_bytes")}
    result["memory_sampling_error"] = data.get("memory_sampling_error")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directories", nargs="+", type=Path)
    args = parser.parse_args()
    print(json.dumps([summarize(p) for p in args.directories], indent=2))
