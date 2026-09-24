#!/usr/bin/env python3
"""Paired stock/legacy/optimized measurements inside real Reth payload construction.

--profile enables stage clocks for attribution; leave it OFF for speed comparisons.
Every mode receives the same preflight warming and must produce identical blocks.
"""
import argparse
import contextlib
import hashlib
import json
import os
import statistics
import subprocess
import run as r


def benchmark(samples=9, batch=32, profile=False):
    assert samples > 0 and samples % 3 == 0
    r.h.prepare()
    os.environ["OPS_PROFILE"] = "1" if profile else "0"
    modes = ["baseline", "legacy", "direct"]
    rows = []
    for workload, count in [("single_storage_write", 0), ("three_calls", 1), ("eighteen_calls", 16)]:
        for pair in range(3):
            # Rotate all three modes to avoid always measuring the optimized one last.
            for mode in modes[pair:] + modes[:pair]:
                os.environ["OPS_FINGERPRINT_MODE"] = mode
                with r.node(f"compare-{workload}-{pair}-{mode}", disabled=mode == "baseline") as n, contextlib.closing(r.Client(n, connect=mode != "baseline")) as c:
                    for sample in range(samples // 3 + 1):
                        txs = []
                        for i in range(batch):
                            key = (sample * batch + i) * 32
                            if count:
                                tx = n.raw(r.h.ALICE, r.h.BENCH_ROUTER, "run(uint256,uint256)", key, count, nonce=sample * batch + i, gas=600000)
                            else:
                                tx = n.raw(r.h.ALICE, r.h.BENCH_VAULT, "put(uint256,uint256)", key, 7, nonce=sample * batch + i, gas=100000)
                            approval = c.prepare(tx)
                            if mode != "baseline":
                                c.send(approval)
                            txs.append(tx)
                        for tx in txs:
                            n.submit(tx)
                        before = len(r.timings(n))
                        payload = n.make_block(txs)
                        matches = [t for t in r.timings(n)[before:] if t["block_hash"] == payload["blockHash"] and t["transactions"] == batch]
                        assert matches, "missing in-process timing"
                        if sample:
                            rows.append({"workload": workload, "pair": pair, "mode": mode, "sample": sample, **matches[0]})
                            (r.h.EVIDENCE / "comparison-raw.json").write_text(json.dumps(rows, indent=2) + "\n")
                        print("MEASURE", workload, pair, mode, sample, matches[0]["elapsed_ns"], flush=True)
    summary = []
    for workload in sorted({x["workload"] for x in rows}):
        selected = [x for x in rows if x["workload"] == workload]
        for pair in range(3):
            for sample in range(1, samples // 3 + 1):
                triple = [x for x in selected if x["pair"] == pair and x["sample"] == sample]
                assert len(triple) == 3 and len({x["block_hash"] for x in triple}) == 1, "different blocks across comparison modes"
        times = {mode: [x["elapsed_ns"] / batch / 1000 for x in selected if x["mode"] == mode] for mode in modes}
        medians = {mode: statistics.median(values) for mode, values in times.items()}
        stage_us = {}
        stage_median_us = {}
        for mode in modes[1:]:
            profiles = [x["profile"] for x in selected if x["mode"] == mode and x.get("profile")]
            if profiles:
                transactions = sum(x["transactions"] for x in profiles)
                stage_us[mode] = {key: sum(x["stage_ns"][key] for x in profiles) / transactions / 1000 for key in profiles[0]["stage_ns"]}
                stage_median_us[mode] = {key: statistics.median(x["stage_ns"][key] / x["transactions"] / 1000 for x in profiles) for key in profiles[0]["stage_ns"]}
        summary.append({"workload": workload, "median_us_per_tx": medians,
                        "ranges_us_per_tx": {k: [min(v), max(v)] for k, v in times.items()},
                        "extra_us_per_tx": medians["direct"] - medians["baseline"],
                        "optimized_time_increase_percent": (medians["direct"] / medians["baseline"] - 1) * 100,
                        "optimized_time_reduction_vs_legacy_percent": (1 - medians["direct"] / medians["legacy"]) * 100,
                        "stage_mean_us_per_tx": stage_us,
                        "stage_median_us_per_tx": stage_median_us})
    report = {"method": "Same binary; stock, original JSON fingerprint, direct fingerprint. Internal default_ethereum_payload time including execution and roots, divided by included tx count. Identical preflight warming. Rotated mode order; one discarded warmup per node. All three block hashes equal for every sample. RPC, preflight, approval signature verification/delivery, wait, and engine import excluded.",
              "profile_enabled": profile, "samples_per_mode_per_workload": samples, "batch": batch,
              "hardware": r.machine_info(), "reth_commit": r.h.RETH_COMMIT,
              "binary_sha256": hashlib.sha256(r.h.BINARY.read_bytes()).hexdigest(),
              "rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
              "summary": summary, "raw": rows}
    (r.h.EVIDENCE / "comparison.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", action="store_true")
    parser.add_argument("--samples", type=int, default=9)
    parser.add_argument("--batch", type=int, default=32)
    args = parser.parse_args()
    benchmark(args.samples, args.batch, args.profile)
