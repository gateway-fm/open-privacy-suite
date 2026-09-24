#!/usr/bin/env python3
"""Capture real Gasstorm Adaptive UI runs on fresh stacks, off and on."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--duration", type=int, default=120)
    parser.add_argument("--port", type=int, default=18000)
    args = parser.parse_args()
    poc = Path(__file__).resolve().parent
    root = poc.parent.parent
    destination = args.evidence.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    cases = [("eth-transfer", False), ("eth-transfer", True), ("erc20-approve", True), ("erc20-approve", False)]
    for workload, enabled in cases:
        name = workload + ("-on" if enabled else "-off")
        out = destination / name
        if (out / "browser/browser-results.json").exists():
            print("REUSE completed", name, flush=True); continue
        if out.exists():
            out.rename(destination / ("incomplete-" + name + "-" + str(time.time_ns())))
        out.mkdir(exist_ok=True)
        env = {**os.environ, "OPS_EVIDENCE_DIR": str(out)}
        with (out / "launcher.log").open("w") as log:
            process = subprocess.Popen(["bash", str(poc / "gasstorm.sh"), "ui", "--port", str(args.port),
                *([] if enabled else ["--without-fix"])], cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT,
                start_new_session=True)
            try:
                deadline = time.monotonic() + 180
                while not (out / "ui-session.json").exists():
                    assert process.poll() is None, (out / "launcher.log").read_text()[-4000:]
                    assert time.monotonic() < deadline, "UI startup timed out"
                    time.sleep(.25)
                print("RUN", name, args.duration, "seconds", flush=True)
                test_env = {**os.environ, "GASSTORM_UI_URL": f"http://127.0.0.1:{args.port}", "OPS_UI_TEST_EVIDENCE": str(out / "browser"), "OPS_UI_TEST_WORKLOADS": workload,
                    "OPS_UI_INITIAL": "500", "OPS_UI_STEP": "50", "OPS_UI_TARGET_PENDING": "2000",
                    "OPS_UI_DURATION": str(args.duration), "OPS_UI_CAPTURE_PEAK": "0", "OPS_UI_CAPACITY": "1"}
                with (out / "browser.log").open("w") as browser_log:
                    subprocess.run(["node", str(poc / "ui_browser_test.mjs")], cwd=root, env=test_env,
                        stdout=browser_log, stderr=subprocess.STDOUT, check=True, timeout=args.duration + 400)
                print("PASS", name, (out / "browser/browser-results.json").read_text().replace("\n", " "), flush=True)
            finally:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=60)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=10)
                    raise RuntimeError("UI cleanup timed out; inspect launcher.log")
                assert process.returncode == 0, (out / "launcher.log").read_text()[-4000:]


if __name__ == "__main__":
    main()
