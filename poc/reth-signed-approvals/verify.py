#!/usr/bin/env python3
"""Run all real-node regression tests with a dedicated disposable PostgreSQL."""
import os
import subprocess
import time
import harness as h
import run
import batch_tests
import lifecycle_tests
from demo import docker

h.prepare()
pg=docker("run","-d","--rm","--label","ops-approvals-test=true","-e","POSTGRES_PASSWORD=postgres",
          "-e","POSTGRES_DB=ops_approvals_test","-p","127.0.0.1::5432","postgres:15-alpine")
try:
    port=docker("port",pg,"5432/tcp").rsplit(":",1)[1]
    for _ in range(200):
        if subprocess.run(["docker","exec",pg,"pg_isready","-U","postgres"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:break
        time.sleep(.1)
    else:raise RuntimeError("test PostgreSQL failed to start")
    os.environ["TEST_DATABASE_URL"]=f"postgres://postgres:postgres@127.0.0.1:{port}/ops_approvals_test?sslmode=disable"
    run.ordinary()
    run.divergence("same_block_cross_org_divergence")
    run.divergence("caught_call_cannot_bypass",catch=True)
    run.divergence("same_org_storage_divergence",storage_only=True)
    run.divergence("stock_control_executes_cross_org",disabled=True)
    run.read_only();run.fingerprint_cases();run.waits();run.waiting_load();run.invalid();run.expiry()
    run.real_ops();run.restart();run.restart_resend();run.history();batch_tests.tests()
    lifecycle_tests.tests()
finally:
    subprocess.run(["docker","stop","-t","3",pg],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
