#!/usr/bin/env python3
"""Query OSV for pinned/resolved public dependencies. Findings require reachability review."""
import argparse
import datetime
import json
from pathlib import Path
import tomllib
import urllib.request

ROOT = Path(__file__).resolve().parent.parent


def query(payload):
    request = urllib.request.Request("https://api.osv.dev/v1/querybatch",
                                     json.dumps(payload).encode(), {"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("node", choices=["besu", "reth"])
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.node == "besu":
        rows = json.loads((ROOT / "node-approvals/besu/build/dependency-inventory.json").read_text())
        ecosystem = "Maven"
    else:
        packages = tomllib.loads((ROOT / "node-approvals/reth/Cargo.lock").read_text())["package"]
        rows = [{"name": p["name"], "version": p["version"]} for p in packages
                if p.get("source", "").startswith("registry+")]
        ecosystem = "crates.io"
    findings = []
    review = json.loads((ROOT / "node-approvals/advisory-review.json").read_text())
    review_current = datetime.date.today() <= datetime.date.fromisoformat(review["recheck_by"])
    if args.node == "reth":
        versions = {p["name"]: p["version"] for p in rows}
        review_current = review_current and all(versions.get(name) == version
                                               for name, version in review["required_versions"].items())
    exceptions = {(e["ecosystem"], e["name"], e["version"], e["id"]): e["reason"]
                  for e in review["exceptions"]} if review_current else {}
    for start in range(0, len(rows), 100):
        batch = rows[start:start + 100]
        results = query({"queries": [{"package": {"name": r["name"], "ecosystem": ecosystem},
                                       "version": r["version"]} for r in batch]})["results"]
        if len(results) != len(batch):
            raise RuntimeError("incomplete vulnerability response")
        for package, result in zip(batch, results):
            if result.get("next_page_token"):
                raise RuntimeError("vulnerability results paginated: use a full OSV scan before release")
            if result.get("vulns"):
                findings.append({**package, "advisories": [
                    {"id": v["id"], "review": exceptions.get((ecosystem, package["name"], package["version"], v["id"]))}
                    for v in result["vulns"]]})
    report = {"checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "source": "https://api.osv.dev", "ecosystem": ecosystem,
              "dependencies_checked": len(rows), "findings": findings, "review_current": review_current,
              "scope": "Resolved Besu compile/runtime coordinates or registry packages in the Reth lockfile; not a reachability analysis, native-library or OS scan."}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    raise SystemExit(not review_current or any(not a["review"] for f in findings for a in f["advisories"]))


if __name__ == "__main__":
    main()
