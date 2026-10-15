#!/usr/bin/env python3
"""Summarize saved Besu verifier runs without starting or changing any services.

Input contains jdk/, bouncy-castle/ and approvals-off/ from the historical
comparison runner. Plain JSON and gzip-compressed evidence are supported.
This reports existing measurements; it does not establish a new benchmark run.
"""
import argparse
import collections
import gzip
import hashlib
import json
import math
from pathlib import Path
import re

CASES = ("jdk", "bouncy-castle", "approvals-off")
PREFIX = "privacyproxy_approval_delivery_seconds_"


def read_json(path):
    if path.is_file():
        return json.loads(path.read_text())
    with gzip.open(str(path) + ".gz", "rt") as stream:
        return json.load(stream)


def metrics(path):
    """Keep individual series until after reset detection; aggregate in the report."""
    values = collections.defaultdict(float)
    with path.open() as stream:
        for line in stream:
            if not line.startswith(("privacyproxy_approval_", "ops_approval_")):
                continue
            match = re.fullmatch(r'([^ {]+)(?:\{([^}]+)\})?\s+([^\s]+)\s*', line)
            if not match:
                raise ValueError(f"malformed approval metric in {path.name}")
            name, labels, value = match.groups()
            labels = dict(re.findall(r'(\w+)="((?:[^"\\]|\\.)*)"', labels or ""))
            value = float(value)
            if not math.isfinite(value):
                raise ValueError(f"non-finite metric: {name}")
            values[name, tuple(sorted(labels.items()))] += value
    return dict(values)


def counter_delta(before, after):
    result = {}
    for key in before.keys() | after.keys():
        if not key[0].endswith(("_total", "_count", "_sum", "_bucket")):
            continue
        value = after.get(key, 0) - before.get(key, 0)
        if value < 0:
            raise ValueError(f"counter reset or missing series: {key[0]}")
        result[key] = value
    return result


def total(values, name):
    return sum(value for (metric, _), value in values.items() if metric == name)


def delivery_latency(delta):
    count = total(delta, PREFIX + "count")
    if count == 0:
        return None
    buckets = collections.defaultdict(float)
    for (name, labels), value in delta.items():
        if name == PREFIX + "bucket":
            bound = float(dict(labels)["le"])
            if math.isnan(bound) or bound < 0:
                raise ValueError("invalid delivery histogram bound")
            buckets[bound] += value
    ordered = sorted(buckets.items())
    if not ordered or ordered[-1] != (math.inf, count):
        raise ValueError("delivery histogram does not cover its observation count")
    if any(a[1] > b[1] for a, b in zip(ordered, ordered[1:])):
        raise ValueError("delivery histogram buckets are not cumulative")
    bounds = {}
    for label, fraction in (("p50", .5), ("p95", .95), ("p99", .99)):
        bound = next(bound for bound, value in ordered if value >= math.ceil(fraction * count))
        bounds[label] = bound * 1000 if math.isfinite(bound) else None
    return {"mean_ms": total(delta, PREFIX + "sum") * 1000 / count,
            "histogram_count": count, "percentile_upper_bounds_ms": bounds}


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def summarize_case(directory):
    report = read_json(directory / "transactions-report.json")
    if report.get("error") or report["status"]["status"] != "completed":
        raise ValueError(f"{directory.name}: run did not complete successfully")
    before, after = [metrics(directory / f"metrics-{phase}.txt") for phase in ("before", "after")]
    delta = counter_delta(before, after)
    count = total(delta, PREFIX + "count")
    receipts = read_json(directory / "receipts.json")
    logs = read_json(directory / "transactions.json")
    missing = {row["hash"].lower() for row in receipts if row["receipt"] is None}
    statuses = {row["txHash"].lower(): row.get("status", "unknown") for row in logs if row.get("txHash")}
    return {"case": directory.name, "config": read_json(directory / "verifier-config.json"),
            "receipts": report["receipts"],
            "generator": {key: report["status"].get(key) for key in
                          ("txSent", "txConfirmed", "txFailed", "status", "elapsedMs")},
            "missing_by_generator_status": dict(collections.Counter(statuses.get(tx, "unknown") for tx in missing)),
            "approval_delivery": delivery_latency(delta),
            "mean_approvals_per_batch": total(delta, "privacyproxy_approval_confirmed_total") / count if count else None,
            "loadgen_sha256": report["loadgen_sha256"],
            "source_files_sha256": {path.name: digest(path) for path in sorted(directory.iterdir())
                                    if path.is_file() and path.suffix in (".json", ".txt", ".gz")}}


def write_summary(path, result):
    text = json.dumps(result, indent=2, allow_nan=False) + "\n"
    with path.open("x") as stream:
        stream.write(text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="directory holding all three saved cases")
    parser.add_argument("--output", required=True, type=Path, help="new output file; never overwrites evidence")
    args = parser.parse_args()
    source = args.input.resolve()
    output = args.output.resolve()
    if output == source or source in output.parents:
        parser.error("output must be outside the input evidence directory")
    if output.exists():
        parser.error("output already exists")
    result = {"kind": "summary-of-existing-evidence",
              "full_transaction_cases": [summarize_case(source / case) for case in CASES]}
    write_summary(output, result)


if __name__ == "__main__":
    main()
