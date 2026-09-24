#!/usr/bin/env python3
"""Summarize captured UI tests without equating a short peak with capacity."""
import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    root = args.directory.resolve()
    peak_file = root / "displayed-peaks.json"
    if not peak_file.exists():
        peak_file.write_text(json.dumps({"screenshots": [
            {"case": p.parent.parent.name,
             "displayedPeakTPS": json.loads(p.read_text())["results"][0]["dashboardPeakTps"]}
            for p in sorted(root.glob("*/browser/browser-results.json"))
        ]}, indent=2) + "\n")
    displayed = {v["case"]: v["displayedPeakTPS"] for v in json.loads(peak_file.read_text())["screenshots"]}
    rows = []
    for workload in ("eth-transfer", "erc20-approve"):
        for mode in ("off", "on"):
            case = root / f"{workload}-{mode}"
            session = json.loads((case / "ui-session.json").read_text())
            assert session["enforcement"] == (mode == "on")
            result = json.loads((case / "browser/browser-results.json").read_text())["results"][0]
            data = json.loads((case / f"browser/{workload}.json").read_text())
            samples = data["samples"]
            running = [s for s in samples if s["status"] == "running"]
            start = running[0]["at"] / 1000 - running[0]["elapsedMs"] / 1000
            end = start + data["history"]["config"]["durationSec"]
            blocks = json.loads((case / "gasstorm-ui-blocks.json").read_text())
            pools = [json.loads(line) for line in (case / "ui-pool.jsonl").read_text().splitlines()]

            def pool_at(at):
                sample = min(pools, key=lambda p: abs(p["at"] - at))
                return {k: sample[k] for k in ("pending", "queued")}

            windows = []
            for block in blocks:
                stop = block["at"]
                begin = stop - 30
                if begin < start or stop > end:
                    continue
                count = sum(len(b["transactions"]) for b in blocks if begin < b["at"] <= stop)
                before, after = pool_at(begin), pool_at(stop)
                windows.append({"from": begin, "to": stop, "canonicalTransactions": count,
                    "tps": count / 30, "poolBefore": before, "poolAfter": after,
                    "poolGrowth": sum(after.values()) - sum(before.values())})
            best = max(windows, key=lambda w: w["tps"])
            non_growing = [w for w in windows if w["poolGrowth"] <= 0]
            row = {"case": case.name, **result, "configuration": data["history"]["config"],
                "dashboardPeakTPS": displayed[case.name],
                "best30SecondWindow": best, "poolAtEndOfSending": pool_at(end),
                "best30SecondsWithoutQueueGrowth": max(non_growing, key=lambda w: w["tps"]) if non_growing else None,
                "completedScreenshot": f"{case.name}/browser/{workload}.png"}
            rows.append(row)
            (case / "canonical-windows.json").write_text(json.dumps(windows, indent=2) + "\n")
    report = {"scope": "One local 120-second Adaptive run per mode and workload; ten wallets; 200M gas blocks.",
        "interpretation": "Live TPS peaks are sampled dashboard measurements. Best 30-second windows count canonical block transactions by local observation time. Neither establishes sustained maximum capacity. Send failures, missing receipts and queue growth remain visible.",
        "runs": rows}
    (root / "comparison.json").write_text(json.dumps(report, indent=2) + "\n")
    evidence_hashes = {name: digest(root / name) for name in ("comparison.json", "displayed-peaks.json")}
    for row in rows:
        for path in sorted((root / row["case"]).rglob("*")):
            if path.is_file():
                evidence_hashes[str(path.relative_to(root))] = digest(path)
    poc = Path(__file__).resolve().parent
    source_paths = [poc / name for name in ("gasstorm.sh", "gasstorm_ui.py", "gasstorm_compare.py",
        "harness.py", "demo.py", "ui_config.py", "ui_browser_test.mjs", "ui_capacity.py", "analyze_ui.py",
        "prepare_gasstorm.py", "patches/loadgenerator-stability.patch", "patches/gasstorm-stability.patch")]
    binaries = [poc.parent.parent / ".tmp" / name for name in ("ops-server", "approval-client", "gasstorm-loadgen")]
    binaries.append(Path(os.environ.get("OPS_RETH_BINARY", str(poc.parent.parent /
        "../../reth-policy-poc/target/release/ops-reth-approvals-poc"))).resolve())
    main_checkout = poc.parent.parent.parent.parent.parent
    revisions = {}
    for name, repository in (("gasstorm", main_checkout.parent / "gasstorm"),
                             ("loadgenerator", main_checkout.parent / "loadgenerator"),
                             ("reth", poc.parent.parent / ".tmp/reth")):
        revisions[name] = {"commit": subprocess.check_output(["git", "-C", str(repository), "rev-parse", "HEAD"], text=True).strip(),
            "status": subprocess.check_output(["git", "-C", str(repository), "status", "--porcelain"], text=True).strip()}
    manifest = {"createdAt": datetime.now().astimezone().isoformat(),
        "repositories": revisions,
        "filesSHA256": evidence_hashes,
        "sourcesSHA256": {str(p.relative_to(poc)): digest(p) for p in source_paths},
        "binariesSHA256": {str(p): digest(p) for p in binaries}}
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    for row in rows:
        print(row["case"], "sampled peak", round(row["peakLiveTps"], 1),
            "best 30s", round(row["best30SecondWindow"]["tps"], 1),
            "successful receipts", row["successfulReceipts"], "send failures", row["failed"])


if __name__ == "__main__":
    main()
