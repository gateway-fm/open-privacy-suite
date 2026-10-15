#!/usr/bin/env python3
"""Interactive, isolated Gasstorm dashboard -> OPS -> custom Reth."""
import argparse
import base64
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
from gasstorm_compare import GasstormStack, Loadgen, Miner, prepare, save
from ui_config import normalize_start


class Control:
    """Test-control traffic only; transaction RPC goes directly from loadgen to OPS."""
    def __init__(self, stack, loadgen):
        self.stack, self.loadgen = stack, loadgen
        self.pool = stack.node_rpc("txpool_status", [])
        self.start_lock = threading.Lock()
        self.error = None
        self.recover = None
        control = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def respond(self, status, body, content_type="application/json"):
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def handle_request(self):
                held = False
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    if length > 1048576:
                        raise ValueError("Request too large")
                    body = self.rfile.read(length) if length else None
                    if self.path == "/poc/status":
                        self.respond(200, json.dumps({"enforcement": not stack.disabled, "hash_mode": "off" if stack.disabled else getattr(stack,"hash_mode","calls"), "wallets": 10,
                            "gas_limit": int(os.environ["OPS_POC_GAS_LIMIT"]), "pool": control.pool, "error": control.error}).encode())
                        return
                    if self.path == "/reset" and self.command == "POST":
                        held = control.start_lock.acquire(blocking=False)
                        if not held:
                            self.respond(409, b'{"error":"Another control action is in progress"}'); return
                        state = request(loadgen.url + "/status")["status"]
                        if state in ("initializing", "running", "verifying"):
                            self.respond(409, b'{"error":"Stop the active test before resetting"}'); return
                        if control.error:
                            if control.recover is None:
                                raise RuntimeError(control.error)
                            control.recover()
                            control.error = None
                    if self.path == "/start" and self.command == "POST":
                        if control.error:
                            self.respond(409, json.dumps({"error":control.error}).encode()); return
                        config = normalize_start(json.loads(body or b"{}"))
                        held = control.start_lock.acquire(blocking=False)
                        if not held:
                            self.respond(409, b'{"error":"Another test is starting"}'); return
                        state = request(loadgen.url + "/status")["status"]
                        if state in ("initializing", "running", "verifying"):
                            self.respond(409, b'{"error":"A test is already active"}'); return
                        # Refresh local development login before the loadgen
                        # snapshots its token file. Never expose the token to UI.
                        token = stack.login("did:test:gasstorm-comparison")
                        payload = token.split(".")[1]
                        expires = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))["exp"]
                        if int(config.get("durationSec", 0)) > expires - time.time() - 30:
                            raise ValueError("Choose a shorter duration so the session token outlives the test")
                        temporary = loadgen.token_path.with_suffix(".new")
                        temporary.write_text(token); temporary.chmod(0o600)
                        temporary.replace(loadgen.token_path)
                        for address in stack.tokens:
                            stack.tokens[address] = token
                        save("ui-last-start.json", config)
                        body = json.dumps(config).encode()
                    upstream = urlparse(loadgen.url)
                    connection = http.client.HTTPConnection(upstream.netloc, timeout=30)
                    try:
                        connection.request(self.command, self.path, body, {"Content-Type": "application/json"})
                        response = connection.getresponse()
                        self.respond(response.status, response.read(), response.getheader("Content-Type", "application/json"))
                    finally:
                        connection.close()
                except (ValueError, KeyError, TypeError) as error:
                    self.respond(400, json.dumps({"error": str(error)}).encode())
                except Exception as error:
                    self.respond(502, json.dumps({"error": str(error)}).encode())
                finally:
                    if held:
                        control.start_lock.release()

            do_GET = do_POST = do_PATCH = do_DELETE = handle_request

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def fail(self, message):
        if self.error:
            return
        self.error = message + ". The test is being stopped; use Reset to retry."
        print(self.error, flush=True)
        def stop_load():
            try:
                request(self.loadgen.url + "/stop", method="POST")
            except Exception as error:
                print("Could not stop load generator: " + str(error), flush=True)
        threading.Thread(target=stop_load, daemon=True).start()

    def close(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=5)

    def sample_pool(self, pool_log):
        try:
            pool = self.stack.node_rpc("txpool_status", [])
            record = {"at": time.time(), **{k: int(v, 16) for k, v in pool.items()}}
            pool_log.write(json.dumps(record) + "\n")
            pool_log.flush()
            self.pool = pool
            return True
        except Exception as error:
            # Diagnostics must not tear down the dashboard on an RPC error,
            # malformed reply or broken keep-alive connection.
            print("Pool sample failed: " + str(error), flush=True)
            return False


class Dashboard:
    def __init__(self, stack, loadgen, control, port):
        # Serve the patched native Gasstorm UI and WebSocket through nginx.
        # This config only connects its load-test page to the isolated services.
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
        self.container = docker("run", "-d", "--rm", "--label", "ops-approvals-demo=true",
            "--name", "ops-gasstorm-ui-" + str(time.time_ns()), "-p", f"127.0.0.1:{port}:80",
            "--add-host", "host.docker.internal:host-gateway", "-v", str(config) + ":/etc/nginx/conf.d/default.conf:ro",
            "--entrypoint", "nginx", os.environ["GASSTORM_DASHBOARD_IMAGE"], "-g", "daemon off;")
        self.url = f"http://127.0.0.1:{port}"

    def close(self):
        subprocess.run(["docker", "stop", "-t", "3", self.container], stdout=subprocess.DEVNULL, check=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--without-fix", action="store_true")
    parser.add_argument("--port", type=int, default=18000)
    parser.add_argument("--gas-limit", type=int, default=200000000)
    args = parser.parse_args()
    if args.gas_limit < 30000000:
        parser.error("gas limit must be at least 30000000")
    # Fail before provisioning if the requested UI port is already occupied.
    with socket.socket() as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", args.port))
    os.environ["OPS_POC_GAS_LIMIT"] = str(args.gas_limit)
    # Let this launcher stop children in order; terminal Ctrl+C must not kill
    # Reth while the Engine driver is still finishing a block.
    os.environ["OPS_POC_DETACH_CHILDREN"] = "1"
    os.environ["OPS_POC_RPC_MAX_CONNECTIONS"] = "4096"
    os.environ["OPS_POC_KEEPALIVE"] = "1"
    prepare()

    def stop(*_):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)
    try:
        with contextlib.ExitStack() as resources:
            stack = resources.enter_context(contextlib.closing(GasstormStack("gasstorm-ui", disabled=args.without_fix,
                ops_env={"OPS_POC_PPROF_ADDR": os.environ.get("OPS_POC_PPROF_ADDR", ""), "NODE_HTTP_MAX_IDLE_CONNS": "4096", "NODE_HTTP_MAX_IDLE_CONNS_PER_HOST": "1024",
                         "NODE_HTTP_MAX_CONNS_PER_HOST": "1024"})))
            stack.prepare_contracts("erc20-approve")
            miner = resources.enter_context(contextlib.closing(Miner(stack.node, realtime=True)))
            loadgen = resources.enter_context(contextlib.closing(Loadgen(stack)))
            control = resources.enter_context(contextlib.closing(Control(stack, loadgen)))
            def recover_driver():
                for name, process in [("OPS", stack.ops), ("Reth", stack.node.process), ("loadgen", loadgen.process)]:
                    if process.poll() is not None:
                        raise RuntimeError(name + " exited. Restart gasstorm.sh ui to recreate the isolated stack")
                if miner.error:
                    miner.restart()
            control.recover = recover_driver
            dashboard = resources.enter_context(contextlib.closing(Dashboard(stack, loadgen, control, args.port)))
            deadline = time.monotonic() + 30
            while True:
                try:
                    assert request(dashboard.url + "/api/loadgen/health")
                    break
                except (OSError, RuntimeError):
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(.2)
            metadata = {"url": dashboard.url + "/load-test/", "pid": os.getpid(), "enforcement": not args.without_fix, "hash_mode": "off" if args.without_fix else stack.hash_mode,
                        "wallets": 10, "gas_limit": args.gas_limit, "block_seconds": 1, "loadgen": loadgen.url,
                        "reth_rpc_connections": 4096, "OPS_upstream_connections_per_client": 1024,
                        "OPS": stack.url, "org": stack.org, "node": stack.node.rpc_url,
                        "dashboard_image": docker("inspect", "--format", "{{.Image}}", dashboard.container)}
            save("ui-session.json", metadata)
            print("READY " + metadata["url"], flush=True)
            print(f"Enforcement {'OFF' if args.without_fix else 'ON'}; hash mode {metadata['hash_mode']}; ten wallets; block gas limit {args.gas_limit:,}.", flush=True)
            print("Choose Through Privacy Proxy -> Adaptive -> Start. Leave JWT empty and Gasless off.", flush=True)
            print("Ctrl+C stops this session. Evidence: " + str(h.EVIDENCE), flush=True)
            with (h.EVIDENCE / "ui-pool.jsonl").open("w") as pool_log:
                while True:
                    if miner.error:
                        control.fail("Block production failed: " + str(miner.error))
                    for name, process in [("OPS", stack.ops), ("Reth", stack.node.process), ("loadgen", loadgen.process)]:
                        if process.poll() is not None:
                            control.fail(name + " exited; inspect session logs")
                    control.sample_pool(pool_log)
                    time.sleep(1)
    except KeyboardInterrupt:
        print("Stopped; isolated session cleaned up.", flush=True)


if __name__ == "__main__":
    main()
