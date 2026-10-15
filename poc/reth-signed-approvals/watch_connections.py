"""Record local TCP states while exercising the real Gasstorm UI."""
from collections import Counter
import json
import os
from pathlib import Path
import subprocess
import sys
import time

out = Path(sys.argv[1]).resolve()
while not (out / 'ui-session.json').exists():
    time.sleep(.25)
session = json.loads((out / 'ui-session.json').read_text())
ports = {key: str(session[key]).rsplit(':',1)[1] for key in ('OPS','node','loadgen')}
with (out / 'browser.log').open('w') as log, (out / 'connections.jsonl').open('w') as data:
    browser = subprocess.Popen(['node','poc/reth-signed-approvals/ui_stability_test.mjs'],
        env={**os.environ, 'OPS_UI_TEST_EVIDENCE':str(out/'browser')}, stdout=log, stderr=subprocess.STDOUT)
    while browser.poll() is None:
        rows = subprocess.check_output(['netstat','-anp','tcp'],text=True).splitlines()
        counts = Counter(); by_port = Counter()
        for row in rows:
            fields = row.split()
            if len(fields) >= 6 and fields[0].startswith('tcp'):
                state = fields[-1]; counts[state] += 1
                local, remote = fields[3].rsplit('.',1)[-1], fields[4].rsplit('.',1)[-1]
                for label, port in ports.items():
                    if remote == port: by_port[label + ' client ' + state] += 1
                    if local == port: by_port[label + ' server ' + state] += 1
        data.write(json.dumps({'at':time.time(),'total':dict(counts),'ports':dict(by_port)})+'\n');data.flush()
        time.sleep(3)
    sys.exit(browser.wait())
