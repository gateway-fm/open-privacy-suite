# September 29 benchmark sources and investigations

This archive preserves the investigation behind the
[Besu verifier comparison](../../BESU-VERIFIER-2026-09-29.md).
Its source baseline was `61d91e15816603b3c775443abe9174bdab685d64`;
the measured candidate included the then-uncommitted verifier replacement.
The replacement subsequently landed through PR #514. The findings here are
historical development measurements, not new runs or production capacity claims.

- [Bottleneck investigation](besu-bottleneck.md): admission database work,
  upstream connection pressure, approval verification and controlled comparisons.
- [Focused verifier investigation](besu-verification.md): the crypto comparison,
  delivery capacity, compatibility checks and interpretation.
- [Provenance](provenance.json): original locations and hashes of preserved files.

## Original benchmark scripts

The files under `scripts/` preserve the original Python bytes with a `.txt`
suffix. The hashes of `run_transactions.py.txt` and `run_performance.py.txt`
match the script hashes in the committed
[compact evidence](../../evidence/besu-verifier-2026-09-29.json).
Changing those originals to suit a new checkout would break that provenance.

| Original script | Purpose |
| --- | --- |
| `run_transactions.py` | Adapts the existing transaction harness, adds receiver metrics, and batches post-load receipt reads. |
| `run_performance.py` | Runs original-verifier, candidate and approvals-disabled cases sequentially. |
| `summarize.py` | Assembles the original report with its fixed date, hardware, source, test and advisory metadata. |

These are historical source artifacts. They assume the original
`.tmp/besu-verifier-change/` layout, saved baseline/candidate JARs, a private
Besu distribution, patched load generator, compiled OPS, pinned JDK/compiler,
and the matching transaction-harness source. They replace the plugin in that
private distribution and clean their disposable chain state. They are not
general-purpose launchers for a current checkout.

For an exact historical investigation, restore the source and artifacts named
in the compact evidence into a disposable checkout and restore these scripts
under their `original_path` values in `provenance.json`, removing only the `.txt`
suffix. Verify all recorded source/artifact hashes before interpreting results.
The original candidate was dirty, so checking out the baseline alone does not
reconstruct it. Raw captures and binaries are intentionally kept outside Git.

The original `summarize.py` writes the historical tracked report and inserts
fixed September metadata. Use the portable summarizer below for inspecting
saved runs; it writes a new file and carries no assumed measurement date,
hardware, source revision or validation outcome.

## Summarize saved runs

Python 3.11 or later is sufficient; this command does not launch a node,
require Docker, or modify its inputs:

```sh
python3 poc/approval-performance/summarize_verifier.py \
  --input /path/to/saved/performance \
  --output /path/to/new-summary.json
```

The input directory contains `jdk/`, `bouncy-castle/` and `approvals-off/`.
Each needs `transactions-report.json`, `transactions.json`, `receipts.json`,
`verifier-config.json`, and `metrics-before.txt` / `metrics-after.txt`.
JSON files may instead have a `.gz` suffix. Output must be a new file outside
the evidence directory. Input file hashes accompany each case.

Receipt totals and committed TPS come from the original harness's canonical
receipt verification; this offline command does not query the chain again.
Delivery means are weighted by observation count across targets. Percentiles
are histogram upper bounds; a JSON `null` bound means only the infinite bucket
covered that percentile. Counter resets, incomplete runs, missing inputs and
inconsistent histograms are errors. Each delivery histogram label set must have
count, sum and infinite-bucket series in both snapshots, with matching bucket
boundaries across targets and snapshots. Confirmation counters must cover the
same targets in both snapshots so missing baselines cannot inflate batch sizes.
An entirely absent histogram in both snapshots is valid for approvals-off runs.
No new throughput or compatibility claim is inferred from reprocessing the saved
evidence.

Validation:

```sh
python3 -B -m unittest discover -s poc/approval-performance -p test_verifier_summary.py
```
