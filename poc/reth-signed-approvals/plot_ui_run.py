#!/usr/bin/env python3
"""Plot the full recorded run; leave the original browser screenshots untouched."""
import argparse
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import StrMethodFormatter


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("case", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    case = args.case
    config = json.loads((case / "ui-last-start.json").read_text())
    session = json.loads((case / "ui-session.json").read_text())
    frames = json.loads((case / "browser/websocket-frames.json").read_text())
    duration = config["durationSec"]
    frames = [f for f in frames if f["status"] == "running" and 0 <= f["elapsedMs"] <= duration * 1000]
    times = [f["elapsedMs"] / 1000 for f in frames]
    rates = [f["currentTps"] for f in frames]
    targets = [f["targetTps"] for f in frames]
    peak = max(range(len(frames)), key=lambda i: rates[i])
    samples = json.loads((case / f"browser/{config['transactionType']}.json").read_text())["samples"]
    first = next(s for s in samples if s["status"] == "running")
    started = (first["at"] - first["elapsedMs"]) / 1000
    pools = [json.loads(line) for line in (case / "ui-pool.jsonl").read_text().splitlines()]
    pools = [p for p in pools if 0 <= p["at"] - started <= duration]

    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 11, "axes.spines.top": False,
                         "axes.spines.right": False, "axes.titleweight": "bold"})
    fig, (top, bottom) = plt.subplots(2, 1, figsize=(13, 8), sharex=True,
                                    gridspec_kw={"height_ratios": [2, 1]})
    fig.subplots_adjust(top=.84, bottom=.14, left=.09, right=.97, hspace=.2)
    mode = "ON" if session["enforcement"] else "OFF"
    fig.suptitle(f"{config['transactionType']} · enforcement {mode} · full {duration}-second run", fontsize=18, y=.97)
    fig.text(.09, .90, "Recorded data from the same test. A short peak does not establish sustainable throughput.", color="#475569")
    top.plot(times, rates, color="#7c3aed", linewidth=1.8, label="Measured TPS — Gasstorm rolling metric")
    top.step(times, targets, where="post", color="#d97706", linewidth=1.3, alpha=.8, label="Sending rate requested by Adaptive")
    top.scatter([times[peak]], [rates[peak]], s=40, color="#7c3aed", zorder=4)
    upper = max(max(rates), max(targets)) * 1.32
    top.set_ylim(0, upper)
    top.annotate(f"Recorded peak: {int(rates[peak]):,} TPS\nat {times[peak]:.1f} seconds",
                 xy=(times[peak], rates[peak]), xytext=(times[peak]+5, upper*.88),
                 arrowprops={"arrowstyle": "->", "color": "#475569"}, color="#4c1d95")
    top.set_ylabel("Transactions / second")
    top.legend(loc="upper right", fontsize=9, frameon=False)
    bottom.plot([p["at"]-started for p in pools], [p["queued"] for p in pools],
                color="#dc2626", linewidth=1.8, label="Queued in Reth — waiting behind earlier transactions")
    bottom.plot([p["at"]-started for p in pools], [p["pending"] for p in pools],
                color="#0284c7", linewidth=1.2, alpha=.7, label="Pending in Reth")
    bottom.set_ylabel("Transactions in node")
    bottom.set_xlabel("Seconds since sending started")
    bottom.legend(loc="upper left", fontsize=9, frameon=False)
    for ax in (top, bottom):
        ax.set_xlim(0, duration)
        ax.set_xticks(range(0, duration+1, 10))
        ax.yaxis.set_major_formatter(StrMethodFormatter("{x:,.0f}"))
        ax.grid(alpha=.18)
    fig.text(.09, .045, "Source: saved WebSocket metrics and txpool_status samples. Full timeline; no additional smoothing or rerun.", fontsize=9, color="#475569")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(args.output.with_suffix(".png"), dpi=160, facecolor="white")
    fig.savefig(args.output.with_suffix(".svg"), facecolor="white")
    plt.close(fig)
    print(f"Peak {rates[peak]:.6f} TPS at {times[peak]:.3f}s; {len(frames)} metric samples, {len(pools)} pool samples")


if __name__ == "__main__":
    main()
