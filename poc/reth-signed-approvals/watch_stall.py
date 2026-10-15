"""Capture diagnostic stacks only if the real browser load test stalls."""
import concurrent.futures
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request

root = Path.cwd()
out = Path(sys.argv[1]).resolve()
session = json.loads((out / 'ui-session.json').read_text())
stack_file = next(p for p in (root / '.tmp/approval-runs').glob('*/connections.json')
                  if json.loads(p.read_text())['ops'] == session['OPS'])
stack = json.loads(stack_file.read_text())

def capture_url(name, url):
    try:
        with urllib.request.urlopen(url, timeout=15) as response:
            (out / name).write_bytes(response.read())
    except Exception as error:
        (out / (name + '.error')).write_text(str(error))

with (out / 'browser.log').open('w') as log:
    process = subprocess.Popen(['node', 'poc/reth-signed-approvals/ui_stability_test.mjs'],
        env={**os.environ, 'OPS_UI_TEST_EVIDENCE': str(out / 'browser')}, stdout=log, stderr=subprocess.STDOUT)
    captured = False
    while process.poll() is None:
        try:
            with urllib.request.urlopen(session['loadgen'] + '/status', timeout=2) as response:
                status = json.load(response)
            stalled = status['status'] == 'running' and status['txSent'] > 60000 and status['currentTps'] < 500
        except Exception:
            stalled = True
        if stalled and not captured:
            captured = True
            print('Capturing stall diagnostics', flush=True)
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                futures = [executor.submit(capture_url, name, 'http://127.0.0.1:6062/debug/pprof/' + suffix)
                    for name, suffix in [('ops-goroutines.txt','goroutine?debug=2'), ('ops-cpu.pprof','profile?seconds=10')]]
                for name, command in [
                    ('processes.txt', ['ps','-axo','pid,pcpu,pmem,comm']),
                    ('memory.txt', ['sysctl','vm.swapusage']),
                    ('pg-waits.txt', ['docker','exec',stack['postgres'],'psql','-U','postgres','-d','ops_approvals_demo','-Atc',
                        'select state,wait_event_type,wait_event,count(*) from pg_stat_activity group by 1,2,3 order by 4 desc'])]:
                    try:
                        result = subprocess.run(command, capture_output=True, text=True, timeout=5)
                        (out / name).write_text(result.stdout + result.stderr)
                    except subprocess.TimeoutExpired:
                        (out / name).write_text('Command timed out')
                for future in futures:
                    future.result()
        time.sleep(2)
    sys.exit(process.wait())
