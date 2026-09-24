#!/usr/bin/env python3
"""Summarize headless A/B evidence using reconciled receipts."""
import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import statistics
import subprocess


def write_manifest(evidence):
    poc = Path(__file__).resolve().parent
    root = poc.parent.parent
    case = json.loads((evidence / "eth-final/manifest.json").read_text())
    loadgen = Path(case["loadgen_source"])

    def git(path, *args):
        return subprocess.check_output(["git", "-C", str(path), *args], text=True).strip()

    def digest(path):
        with path.open("rb") as stream:
            return hashlib.file_digest(stream, "sha256").hexdigest()

    repositories = {name: {"path": str(path.resolve()), "commit": git(path, "rev-parse", "HEAD"),
                          "branch": git(path, "branch", "--show-current"), "status": git(path, "status", "--short")}
                    for name, path in {"OPS": root, "Gasstorm": loadgen.parent / "gasstorm", "loadgenerator": loadgen,
                                       "Reth": root / ".tmp/reth"}.items()}
    sources = set()
    for directory in [root / "internal/nodeapproval", root / "internal/rbac", root / "internal/nodehttp",
                      poc / "src", poc / "contracts", poc / "client"]:
        sources.update(p for p in directory.rglob("*") if p.suffix in (".go", ".rs", ".sol"))
    sources.update(p for p in poc.iterdir() if p.is_file() and p.suffix in (".py", ".sh", ".toml", ".lock"))
    sources.update(root / p for p in ["go.mod", "go.sum", "internal/server/node_approvals.go", "internal/server/server.go",
                                    "internal/server/jsonrpc_processor.go", "internal/server/jsonrpc_trace.go"])
    binaries = {"OPS": root / ".tmp/ops-server", "approval-client": root / ".tmp/approval-client",
                "loadgenerator": root / ".tmp/gasstorm-loadgen", "Reth": Path(os.environ["OPS_RETH_BINARY"])}
    validation = {}
    for name in ["regression-final/tests.json", "ops-final/tests.json"]:
        path = poc / "evidence/gasstorm" / name
        if path.exists():
            rows = json.loads(path.read_text())
            validation[name] = {"passed": sum(r["passed"] for r in rows), "total": len(rows), "sha256": digest(path)}
    manifest = {"hardware": case["hardware"], "repositories": repositories,
                "source_sha256": {str(p.relative_to(root)): digest(p) for p in sorted(sources)},
                "binaries": {name: {"path": str(path.resolve()), "sha256": digest(path)} for name, path in binaries.items()},
                "configuration": {"wallets": 10, "DIDs": 1, "MAX_CONCURRENT_REQUESTS": 5000, "DB_MAX_OPEN_CONNS": 30,
                    "block_interval_seconds": 1, "hardfork": "Shanghai", "sending_seconds": 20, "repetitions_per_mode_rate": 2,
                    "fixtures": ["development identity-provider login", "Engine API block scheduling"],
                    "real": ["OPS HTTP", "PostgreSQL", "Redis", "Reth EVM and mempool", "DB permissions", "wallet links", "approval signatures"],
                    "indexer": False},
                "command": "bash poc/reth-signed-approvals/gasstorm.sh all",
                "regressions_after_pool_fix": validation,
                "artifacts_sha256": {str(p.relative_to(evidence)): digest(p) for p in
                    [evidence / "comparison.json", evidence / "contention/runs.json", evidence / "safety-final/safety.json"]}}
    (evidence / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("evidence", type=Path)
    args = p.parse_args()
    all_rows = []
    source_files = []
    for directory in [args.evidence / "eth-final", args.evidence / "contract-final"]:
        runs_file = directory / "runs.json"
        source_files.append(runs_file)
        for run in json.loads(runs_file.read_text()):
            workload = run["config"]["transactionType"]
            rate = run["config"]["constantRate"]
            name = f"gasstorm-{workload}-{run['pair']}-{int(run['module'])}"
            timing_file = directory / (name + "-reth-timings.json")
            source_files.append(timing_file)
            # Same convention as the earlier microbenchmark: the first
            # successfully built candidate matching each committed payload.
            first_timing = {}
            for timing in json.loads(timing_file.read_text()):
                first_timing.setdefault(timing["block_hash"], timing)
            begin = datetime.fromisoformat(run["history"]["runs"][0]["startedAt"]).timestamp()
            end = begin + run["config"]["durationSec"]
            blocks = [b for b in run["canonical_blocks"] if begin <= b["at"] <= end and b["transactions"]]
            measured = [first_timing[b["hash"]] for b in blocks]
            assert measured and all(t["module"] == run["module"] for t in measured)
            txs = sum(t["transactions"] for t in measured)
            row = {"workload": workload, "target_tps": rate, "pair": run["pair"], "module": run["module"],
                   **run["receipt_summary"], "canonical_payload_us_per_tx": sum(t["elapsed_ns"] for t in measured) / txs / 1000,
                   "canonical_payload_blocks": len(measured), "canonical_payload_transactions": txs,
                   "gasstorm_verification_passed": run["history"]["runs"][0].get("verification", {}).get("allChecksPass")}
            all_rows.append(row)
    comparison = []
    for workload, rate in sorted({(r["workload"], r["target_tps"]) for r in all_rows}):
        group = [r for r in all_rows if (r["workload"], r["target_tps"]) == (workload, rate)]
        modes = {}
        for enabled in (False, True):
            selected = [r for r in group if r["module"] == enabled]
            assert len(selected) == 2, (workload, rate, enabled, len(selected))
            modes[enabled] = {"runs": len(selected), **{
                key: statistics.mean(r[key] for r in selected) for key in ["settled_successes_per_sending_second",
                "committed_during_sending_tps", "canonical_payload_us_per_tx", "queue_to_commit_p50_ms", "queue_to_commit_p95_ms"]},
                **{key: sum(r[key] for r in selected) for key in ["successful_receipts", "reverted_receipts", "without_receipt", "gasstorm_failed", "missing_but_in_pool", "missing_and_unknown_to_node"]}}
            modes[enabled]["settled_tps_range"] = [min(r["settled_successes_per_sending_second"] for r in selected),
                                                  max(r["settled_successes_per_sending_second"] for r in selected)]
        before, after = modes[False], modes[True]
        comparison.append({"workload": workload, "target_tps": rate, "without_fix": before, "with_fix": after,
            "payload_time_increase_percent": (after["canonical_payload_us_per_tx"] / before["canonical_payload_us_per_tx"] - 1) * 100,
            "settled_throughput_change_percent": (after["settled_successes_per_sending_second"] / before["settled_successes_per_sending_second"] - 1) * 100})
    report = {"method": "Two 20-second sending windows per mode and target. Mean of per-run results; mode order reversed in the second pair. Real Gasstorm HTTP API, all load RPC via OPS. Every logged hash checked for an OPS receipt, then reconciled with canonical block hashes. Settled TPS divides successful receipts by configured sending duration and includes successes after the sending window; committed_during_sending_tps excludes that tail. Latency uses Gasstorm enqueue time to local Engine driver canonical commit time. Reth time covers the selected canonical payload build during sending (EVM plus roots), not every abandoned candidate or whole-node CPU. Verification RPCs run after sending. Shutdown discards and remaining pool entries are reported, not hidden.",
        "rows": all_rows, "comparison": comparison,
        "total_successful_receipts": sum(r["successful_receipts"] for r in all_rows),
        "source_sha256": {str(f.relative_to(args.evidence)): hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted(set(source_files))}}
    (args.evidence / "comparison.json").write_text(json.dumps(report, indent=2) + "\n")
    write_manifest(args.evidence)
    for r in comparison:
        b, a = r["without_fix"], r["with_fix"]
        print(r["workload"], r["target_tps"], "settled TPS", round(b["settled_successes_per_sending_second"], 2), round(a["settled_successes_per_sending_second"], 2),
              "Reth us/tx", round(b["canonical_payload_us_per_tx"], 2), round(a["canonical_payload_us_per_tx"], 2),
              "p95 ms", round(b["queue_to_commit_p95_ms"], 1), round(a["queue_to_commit_p95_ms"], 1))


if __name__ == "__main__":
    main()
