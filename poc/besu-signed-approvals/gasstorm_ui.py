#!/usr/bin/env python3
"""Gasstorm's dashboard driving OPS and Besu, in an isolated session you can watch.

Same shape as the Reth PoC's UI session: the browser talks to Gasstorm's own dashboard, the
dashboard's test-control calls come here, and transaction traffic goes straight from the generator
to OPS. Adaptive mode raises the rate until the chain stops keeping up, which is how the ceiling is
found rather than assumed.
"""
import argparse
import contextlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import threading
import time
from urllib.parse import urlparse

import harness as h
from demo import docker, request
from gasstorm import LoadStack, Loadgen, Miner, prepare, save
from ui_config import normalize_start


class Control:
    """Test-control traffic only; the generator's transactions never pass through here."""

    def __init__(self, stack, loadgen):
        self.stack = stack
        self.loadgen = loadgen
        self.error = None
        self.pool = {"pending": 0, "queued": 0}
        control = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def respond(self, status, body):
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def handle_request(self):
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    if length > 1048576:
                        raise ValueError("request too large")
                    body = self.rfile.read(length) if length else None
                    if self.path == "/poc/status":
                        self.respond(200, json.dumps(
                            {"enforcement": stack.plugin, "wallets": 10, "pool": control.pool,
                             "gas_limit": int(os.environ["OPS_POC_GAS_LIMIT"]),
                             "error": control.error}).encode())
                        return
                    if control.error:
                        self.respond(409, json.dumps({"error": control.error}).encode())
                        return
                    if self.path == "/start" and self.command == "POST":
                        # The session has ten configured wallets and a real fee market; refuse a
                        # configuration this fixture cannot honour instead of failing mid-run.
                        body = json.dumps(normalize_start(json.loads(body or b"{}"))).encode()
                    connection = http.client.HTTPConnection(
                        urlparse(loadgen.url).netloc, timeout=60)
                    try:
                        connection.request(self.command, self.path, body,
                                           {"Content-Type": "application/json"})
                        response = connection.getresponse()
                        self.respond(response.status, response.read())
                    finally:
                        connection.close()
                except ValueError as e:
                    self.respond(400, json.dumps({"error": str(e)}).encode())
                except Exception as e:  # never leave the dashboard hanging on a control call
                    self.respond(500, json.dumps({"error": str(e)}).encode())

            do_GET = handle_request
            do_POST = handle_request
            do_DELETE = handle_request

        self.server = ThreadingHTTPServer(("127.0.0.1", h.unused_port()), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def sample_pool(self, log):
        try:
            statistics = self.stack.node.rpc("txpool_besuStatistics")
            self.pool = {"pending": int(statistics.get("localCount", 0)) + int(statistics.get("remoteCount", 0)),
                         "queued": 0}
            log.write(json.dumps({"at": time.time(), **self.pool}) + "\n")
            log.flush()
        except Exception as e:
            self.error = f"pool sampling failed: {e}"

    def fail(self, message):
        self.error = message
        raise RuntimeError(message)

    def close(self):
        self.server.shutdown()


class Dashboard:
    """Gasstorm's own dashboard build, served by nginx, proxied at this session's ports."""

    def __init__(self, stack, loadgen, control, port):
        config = stack.directory / "dashboard.conf"
        config.write_text(f"""map $http_upgrade $connection_upgrade {{ default upgrade; '' close; }}
server {{
  listen 80;
  absolute_redirect off;
  root /usr/share/nginx/html;
  location / {{ try_files $uri $uri/index.html $uri.html /index.html; }}
  location /api/loadgen/ {{
    proxy_pass http://host.docker.internal:{control.port}/;
    proxy_http_version 1.1;
    proxy_read_timeout 60s;
  }}
  location = /ws/loadgen {{
    proxy_pass http://host.docker.internal:{urlparse(loadgen.url).port}/ws;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
    proxy_read_timeout 86400;
  }}
  location = /api/privacy/health {{ proxy_pass http://host.docker.internal:{urlparse(stack.url).port}/health; }}
  location = /poc/status {{ proxy_pass http://host.docker.internal:{control.port}/poc/status; }}
  location /rpc/ {{ return 404; }}
  location /ws/ {{ return 404; }}
  location /api/ {{ return 404; }}
}}
""")
        self.container = docker(
            "run", "-d", "--rm", "--label", "ops-besu-demo=true",
            "--name", "ops-besu-gasstorm-ui-" + str(time.time_ns()), "-p", f"127.0.0.1:{port}:80",
            "--add-host", "host.docker.internal:host-gateway",
            "-v", str(config) + ":/etc/nginx/conf.d/default.conf:ro",
            "--entrypoint", "nginx", os.environ["GASSTORM_DASHBOARD_IMAGE"], "-g", "daemon off;")
        self.url = f"http://127.0.0.1:{port}"

    def close(self):
        subprocess.run(["docker", "stop", "-t", "3", self.container],
                       stdout=subprocess.DEVNULL, check=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--without-gate", action="store_true", help="run the same session with the plugin off")
    parser.add_argument("--port", type=int, default=18000)
    parser.add_argument("--gas-limit", type=int, default=200_000_000)
    parser.add_argument("--block-interval", type=float, default=1.0)
    args = parser.parse_args()
    with socket.socket() as sock:  # fail before provisioning if the UI port is taken
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", args.port))
    os.environ["OPS_POC_GAS_LIMIT"] = str(args.gas_limit)
    os.environ.setdefault("GASSTORM_DASHBOARD_IMAGE", "ops-reth-gasstorm-dashboard:local")
    prepare()
    genesis_path = h.EVIDENCE / "genesis.json"
    genesis = json.loads(genesis_path.read_text())
    genesis["gasLimit"] = hex(args.gas_limit)  # room for thousands of transfers per block
    genesis_path.write_text(json.dumps(genesis, indent=2) + "\n")

    def stop(*_):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop)
    try:
        with contextlib.ExitStack() as resources:
            stack = resources.enter_context(contextlib.closing(
                LoadStack("gasstorm-ui", plugin=not args.without_gate)))
            miner = Miner(stack.node, interval=args.block_interval)
            loadgen = resources.enter_context(contextlib.closing(Loadgen(stack)))
            control = resources.enter_context(contextlib.closing(Control(stack, loadgen)))
            dashboard = resources.enter_context(contextlib.closing(
                Dashboard(stack, loadgen, control, args.port)))
            deadline = time.monotonic() + 60
            while True:
                try:
                    assert request(dashboard.url + "/api/loadgen/health")
                    break
                except (OSError, RuntimeError):
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.2)
            session = {"url": dashboard.url + "/load-test/", "pid": os.getpid(),
                       "enforcement": not args.without_gate, "wallets": 10,
                       "gas_limit": args.gas_limit, "block_seconds": args.block_interval,
                       "loadgen": loadgen.url, "ops": stack.url, "org": stack.org,
                       "node": stack.node.rpc_url,
                       "dashboard_image": docker("inspect", "--format", "{{.Image}}", dashboard.container)}
            save("ui-session.json", session)
            print("READY " + session["url"], flush=True)
            print(f"Gate {'OFF' if args.without_gate else 'ON'}; ten wallets; "
                  f"block gas limit {args.gas_limit:,}; {args.block_interval}s blocks.", flush=True)
            print("In the UI: Through Privacy Proxy -> Adaptive -> Start Test. "
                  "Leave JWT empty and Gasless off.", flush=True)
            print("Ctrl+C ends the session and removes everything it created.", flush=True)
            with (h.EVIDENCE / "gasstorm" / "ui-pool.jsonl").open("w") as pool_log:
                while True:
                    if miner.error:
                        control.fail("block production failed: " + str(miner.error))
                    for name, process in [("OPS", stack.ops), ("Besu", stack.node.process),
                                          ("the load generator", loadgen.process)]:
                        if process.poll() is not None:
                            control.fail(name + " exited; see the session logs")
                    control.sample_pool(pool_log)
                    time.sleep(1)
    except KeyboardInterrupt:
        print("Session stopped; everything it created has been removed.", flush=True)
    finally:
        with contextlib.suppress(Exception):
            miner.close("gasstorm-ui")


if __name__ == "__main__":
    main()
