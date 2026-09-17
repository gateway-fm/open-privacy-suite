#!/usr/bin/env python3
"""Isolated development OPS/Reth stack. No operations target another stack."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = Path(__file__).resolve().parent
MARKER = "ops-reth-stack/v1"


def run(args, cwd=ROOT, env=None, **kwargs):
    return subprocess.run([str(x) for x in args], cwd=cwd, env=env, check=True, **kwargs)


def write_private(path, value):
    path.write_text(value)
    path.chmod(0o600)


def compose_document(ports, password):
    return {"services": {
        "postgres": {"image": "postgres:15-alpine", "environment": {
            "POSTGRES_PASSWORD": password, "POSTGRES_DB": "privacy_proxy"},
            "ports": [f"127.0.0.1:{ports['postgres']}:5432"],
            "volumes": ["postgres:/var/lib/postgresql/data"],
            "healthcheck": {"test": ["CMD", "pg_isready", "-h", "127.0.0.1", "-U", "postgres"], "interval": "1s", "timeout": "3s", "retries": 30}},
        "redis": {"image": "redis:7-alpine", "command": ["redis-server", "--requirepass", password],
            "ports": [f"127.0.0.1:{ports['redis']}:6379"],
            "healthcheck": {"test": ["CMD", "redis-cli", "-a", password, "ping"], "interval": "1s", "timeout": "3s", "retries": 30}}},
        "volumes": {"postgres": {}}}


def compose(state, *args, **kwargs):
    return run(["docker", "compose", "--project-name", state["project"], "-f", Path(state["directory"])/"compose.json", *args], **kwargs)


def process_started(pid):
    result = subprocess.run(["ps", "-p", str(pid), "-o", "lstart="], capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else ""


def same_process(record, started):
    return bool(started) and record["started"] == started


def save(state):
    write_private(Path(state["directory"])/"state.json", json.dumps(state, indent=2)+"\n")


def launch(state, name, args, env, cwd=ROOT):
    log = Path(state["directory"])/f"{name}.log"
    with log.open("ab") as output:
        process = subprocess.Popen([str(x) for x in args], cwd=cwd, env=env, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
    state["processes"][name] = {"pid": process.pid, "started": process_started(process.pid), "log": str(log),
        "argv": [str(x) for x in args], "cwd": str(cwd),
        "environment": {key: value for key, value in env.items() if os.environ.get(key) != value}}
    save(state)


def read_state(directory):
    directory = Path(directory).resolve()
    state = json.loads((directory/"state.json").read_text())
    if state.get("marker") != MARKER or state.get("directory") != str(directory) or not state.get("project", "").startswith("ops-reth-"):
        raise RuntimeError("Refusing unrecognized stack state")
    return state


def stop_processes(state):
    for name, record in reversed(list(state["processes"].items())):
        if same_process(record, process_started(record["pid"])):
            os.killpg(record["pid"], signal.SIGTERM)
    deadline = time.monotonic()+15
    while time.monotonic() < deadline:
        remaining = [r for r in state["processes"].values() if same_process(r, process_started(r["pid"]))]
        if not remaining:
            break
        time.sleep(.2)
    for record in state["processes"].values():
        if same_process(record, process_started(record["pid"])):
            os.killpg(record["pid"], signal.SIGKILL)


def stop(state, remove_volumes=False):
    stop_processes(state)
    compose(state, "down", *(["--volumes"] if remove_volumes else []), timeout=60)
    state["stopped"] = True
    save(state)


def restart(state, rebuild=False):
    records = list(state["processes"].items())
    if any("argv" not in record for _, record in records):
        raise RuntimeError("This early harness state has no restart manifest; create a fresh stack")
    if rebuild:
        directory = Path(state["directory"])
        run(["go", "build", "-tags", "mockauth", "-o", directory/"bin/ops", "./cmd/server"], timeout=300)
        run(["go", "build", "-o", directory/"bin/helper", "./scripts/ops-reth-stack/helper"], timeout=300)
    stop_processes(state)
    compose(state, "up", "-d", "--wait", timeout=90)
    state["processes"] = {}
    for name, record in records:
        if name == "reth" and "--engine.cross-block-cache-size" not in record["argv"]:
            record["argv"].extend(["--engine.cross-block-cache-size", "64"])
        launch(state, name, record["argv"], {**os.environ, **record["environment"]}, cwd=record["cwd"])
        if name == "reth":
            wait_reth(state)
    wait_http(state, "OPS restart readiness", state["urls"]["ops"]+"/ready")
    wait_http(state, "explorer restart", state["urls"]["explorer"])
    wait_http(state, "indexer restart", state["urls"]["ops"]+"/api/v1/explorer/blocks/latest/number")
    state["stopped"] = False
    save(state)
    record_builds(state)
    print("Restarted the same chain, signing trust, databases and node policy state", flush=True)
    from acceptance import verify_persistence
    verify_persistence(state)


def record_builds(state):
    state["binaryDigests"] = {}
    for name in ["reth", "ops", "indexer", "explorer-api"]:
        record = state["processes"].get(name)
        if record:
            with Path(record["argv"][0]).open("rb") as binary:
                state["binaryDigests"][name] = hashlib.file_digest(binary, "sha256").hexdigest()
    save(state)


def http(url, body=None, token=None, method=None, extra_headers=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer "+token
    headers.update(extra_headers or {})
    req = urllib.request.Request(url, json.dumps(body).encode() if body is not None else None, headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            raw = response.read()
            try:
                return response.status, json.loads(raw) if raw else None
            except json.JSONDecodeError:
                return response.status, raw.decode()
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            return error.code, json.loads(raw)
        except json.JSONDecodeError:
            return error.code, raw.decode()


def wait_http(state, name, url, timeout=90):
    deadline = time.monotonic()+timeout
    while time.monotonic() < deadline:
        for process_name, record in state["processes"].items():
            if not same_process(record, process_started(record["pid"])):
                raise RuntimeError(f"{process_name} exited; inspect {record['log']}")
        try:
            if http(url)[0] == 200:
                return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(.5)
    raise RuntimeError(f"Timed out waiting for {name}: {url}; inspect stack logs")


def wait_reth(state):
    deadline = time.monotonic()+60
    while time.monotonic() < deadline:
        record = state["processes"]["reth"]
        if not same_process(record, process_started(record["pid"])):
            raise RuntimeError("Reth exited; inspect "+record["log"])
        try:
            status, response = http(f"http://127.0.0.1:{state['ports']['reth']}", {"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []})
            if status == 200 and response.get("result") == "0x7a69":
                return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(.2)
    raise RuntimeError("Timed out waiting for Reth chain startup")


def helper(state, value):
    result = run([Path(state["directory"])/"bin/helper"], input=json.dumps(value), text=True, capture_output=True)
    return json.loads(result.stdout)


def start(args):
    common = Path(run(["git", "rev-parse", "--git-common-dir"], capture_output=True, text=True).stdout.strip()).resolve().parent
    indexer = Path(args.indexer or common.parent/"chain-indexer").resolve()
    explorer = Path(args.explorer or common.parent/"block-explorer").resolve()
    reth = Path(args.reth or common/".tmp/reth-policy-poc/target/release/ops-reth").resolve()
    for required in [indexer/"go.mod", explorer/"backend/go.mod", explorer/"frontend/node_modules/.bin/vite", ROOT/"frontend/node_modules/.bin/vite", reth]:
        if not required.exists():
            raise RuntimeError(f"Missing prerequisite: {required}")
    for command in ["go", "node", "docker", "solc"]:
        if not shutil.which(command):
            raise RuntimeError(f"Missing prerequisite: {command}")
    project = "ops-reth-"+secrets.token_hex(5)
    directory = Path(args.directory or ROOT/".tmp"/project).resolve()
    directory.mkdir(parents=True, mode=0o700, exist_ok=False)
    directory.chmod(0o700)
    (directory/"bin").mkdir()
    sockets = []
    ports = {}
    for name in ["postgres", "redis", "reth", "private", "authrpc", "p2p", "ops", "ui", "indexer", "bff", "explorer"]:
        sock = socket.socket(); sock.bind(("127.0.0.1", 0)); sockets.append(sock)
        ports[name] = sock.getsockname()[1]
    state = {"marker": MARKER, "project": project, "directory": str(directory), "ports": ports, "processes": {},
             "secrets": {k: secrets.token_hex(32) for k in ["database", "jwt", "refresh", "admin", "private", "sso"]},
             "subjects": {k: "did:test:ops-reth-"+k for k in ["author", "reviewer", "user"]}}
    save(state)
    print(f"Stack state: {directory}", flush=True)
    try:
        builds = [(ROOT, ["go", "build", "-tags", "mockauth", "-o", directory/"bin/ops", "./cmd/server"]),
                  (ROOT, ["go", "build", "-o", directory/"bin/helper", "./scripts/ops-reth-stack/helper"]),
                  (indexer, ["go", "build", "-o", directory/"bin/indexer", "./cmd/indexer"]),
                  (explorer/"backend", ["go", "build", "-tags", "privacy", "-o", directory/"bin/explorer-api", "./cmd/api"])]
        for cwd, command in builds:
            print(f"Building {Path(command[command.index('-o')+1]).name}…", flush=True)
            run(command, cwd=cwd, timeout=300)
        keys = helper(state, {"Action": "keys", "Secret": state["secrets"]["sso"]})
        state["sender"] = keys["sender"]
        write_private(directory/"policy-key", keys["seed"]+"\n")
        write_private(directory/"compose.json", json.dumps(compose_document(ports, state["secrets"]["database"]), indent=2))
        genesis = {"config": {"chainId": 31337, **{k: 0 for k in ["homesteadBlock", "eip150Block", "eip155Block", "eip158Block", "byzantiumBlock", "constantinopleBlock", "petersburgBlock", "istanbulBlock", "berlinBlock", "londonBlock"]}, "terminalTotalDifficulty": 0, "terminalTotalDifficultyPassed": True, "shanghaiTime": 0}, "nonce": "0x0", "timestamp": "0x0", "gasLimit": "0x1c9c380", "difficulty": "0x0", "baseFeePerGas": "0x3b9aca00", "alloc": {keys["sender"]: {"balance": "0x3635c9adc5dea00000"}}}
        write_private(directory/"genesis.json", json.dumps(genesis))
        for sock in sockets:
            sock.close()
        compose(state, "up", "-d", "--wait", timeout=90)
        password = state["secrets"]["database"]
        sql = "CREATE DATABASE privacy_proxy_audit;\nCREATE DATABASE chain_indexer;\nCREATE DATABASE explorer;\nCREATE ROLE privacy_proxy_app LOGIN PASSWORD '"+password+"';\n"
        compose(state, "exec", "-T", "postgres", "psql", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "privacy_proxy", input=sql, text=True, stdout=subprocess.DEVNULL)
        env = os.environ.copy()
        node_env = {**env, "OPS_NODE_POLICY_CHAIN_ID": "31337", "OPS_NODE_POLICY_DEPLOYMENT_ID": project,
            "OPS_NODE_POLICY_PUBLIC_KEYS": json.dumps({"stack": keys["publicKey"]}),
            "OPS_NODE_POLICY_LISTEN": f"127.0.0.1:{ports['private']}", "OPS_NODE_POLICY_TOKEN": state["secrets"]["private"],
            "OPS_NODE_POLICY_STATE_DIR": str(directory/"policy")}
        launch(state, "reth", [reth, "node", "--chain", directory/"genesis.json", "--dev", "--dev.finality-depth", "1", "--dev.block-time", "1s", "--engine.cross-block-cache-size", "64", "--datadir", directory/"reth-data", "--http", "--http.addr", "127.0.0.1", "--http.port", ports["reth"], "--http.api", "eth,net,web3", "--authrpc.port", ports["authrpc"], "--port", ports["p2p"], "--disable-discovery", "--log.file.directory", directory/"reth-logs", "--color", "never"], node_env)
        wait_reth(state)
        dsn = lambda db, user="postgres": f"postgres://{user}:{password}@127.0.0.1:{ports['postgres']}/{db}?sslmode=disable"
        launch(state, "indexer", [directory/"bin/indexer"], {**env, "RPC_URL": f"http://127.0.0.1:{ports['reth']}", "DATABASE_URL": dsn("chain_indexer"), "GRPC_LISTEN_ADDR": f"127.0.0.1:{ports['indexer']}", "METRICS_ENABLED": "false", "POLL_INTERVAL": "1s", "ENABLE_TRACING": "false", "ENABLE_OP_DEPOSITS": "false", "LOG_LEVEL": "info"})
        ops = f"http://localhost:{ports['ops']}"
        ui = f"http://localhost:{ports['ui']}"
        explorer_url = f"http://localhost:{ports['explorer']}"
        ops_env = {**env, "ENVIRONMENT": "development", "ALLOW_MOCK_LOGIN": "true", "MOCK_SIGNATURES": "false",
            "PORT": str(ports["ops"]), "NODE_URL": f"http://127.0.0.1:{ports['reth']}", "DATABASE_URL": dsn("privacy_proxy"),
            "AUDIT_ADMIN_DATABASE_URL": dsn("privacy_proxy_audit"), "AUDIT_DATABASE_URL": dsn("privacy_proxy_audit", "privacy_proxy_app"),
            "REDIS_URL": f"redis://:{password}@127.0.0.1:{ports['redis']}", "INDEXER_URL": f"127.0.0.1:{ports['indexer']}", "EXPLORER_DATABASE_URL": dsn("chain_indexer"),
            "VERIFIER_ID": "did:privado:verifier:dev-0000000000000000", "BASE_URL": ops, "FRONTEND_URL": ui, "CORS_ALLOWED_ORIGINS": ui+","+explorer_url,
            "JWT_SECRET": state["secrets"]["jwt"], "JWT_REFRESH_SECRET": state["secrets"]["refresh"], "ADMIN_API_TOKEN": state["secrets"]["admin"],
            "PLATFORM_ADMIN_SUBJECTS": state["subjects"]["author"]+","+state["subjects"]["reviewer"], "OAUTH_FIRST_PARTY_CLIENTS": "explorer:"+keys["bcrypt"],
            "OPS_NODE_POLICY_MODE": "reth", "OPS_NODE_POLICY_URL": f"http://127.0.0.1:{ports['private']}", "OPS_NODE_POLICY_TOKEN": state["secrets"]["private"],
            "OPS_NODE_POLICY_PRIVATE_KEY_FILE": str(directory/"policy-key"), "OPS_NODE_POLICY_KEY_ID": "stack", "OPS_NODE_POLICY_CHAIN_ID": "31337", "OPS_NODE_POLICY_DEPLOYMENT_ID": project}
        launch(state, "ops", [directory/"bin/ops"], ops_env)
        wait_http(state, "OPS readiness", ops+"/ready")
        launch(state, "explorer-api", [directory/"bin/explorer-api"], {**env, "DATABASE_URL": dsn("explorer"), "API_PORT": str(ports["bff"]), "RPC_URL": ops,
            "PRIVACY_PROXY_URL": ops, "PRIVACY_PROXY_PUBLIC_URL": ops, "CORS_ALLOWED_ORIGINS": ui+","+explorer_url, "COOKIE_SECURE": "false",
            "SSO_CLIENT_ID": "explorer", "SSO_CLIENT_SECRET": state["secrets"]["sso"], "SSO_REDIRECT_URI": explorer_url+"/api/auth/callback", "LOG_LEVEL": "info"})
        launch(state, "frontend", [ROOT/"frontend/node_modules/.bin/vite", "--host", "127.0.0.1", "--port", ports["ui"], "--strictPort"], {**env, "VITE_API_TARGET": ops, "VITE_ALLOW_MOCK_LOGIN": "true", "VITE_BLOCK_EXPLORER_URL": explorer_url}, cwd=ROOT/"frontend")
        # Keep sibling source/cache files untouched. Only dependency reads use its node_modules.
        copied = directory/"explorer-frontend"
        shutil.copytree(explorer/"frontend", copied, ignore=shutil.ignore_patterns("node_modules", ".git", "dist", "coverage", ".vite", ".env*", ".npmrc"))
        (copied/"node_modules").symlink_to(explorer/"frontend/node_modules", target_is_directory=True)
        config = copied/"vite.config.ts"
        config.write_text(config.read_text().replace("export default defineConfig({", "export default defineConfig({\n  cacheDir: '.vite',").replace("__dirname", json.dumps(str(copied))))
        launch(state, "explorer-frontend", [copied/"node_modules/.bin/vite", "--configLoader", "runner", "--host", "127.0.0.1", "--port", ports["explorer"], "--strictPort"], {**env, "API_PROXY_TARGET": f"http://127.0.0.1:{ports['bff']}", "VITE_PRIVACY_MODE": "true", "VITE_CHAIN_ID": "31337", "VITE_NETWORK_NAME": "OPS Reth"}, cwd=copied)
        wait_http(state, "OPS frontend", ui)
        wait_http(state, "explorer frontend", explorer_url)
        state["urls"] = {"ops": ops, "frontend": ui, "explorer": explorer_url}
        save(state)
        record_builds(state)
        print(json.dumps({"state": str(directory), **state["urls"]}, indent=2), flush=True)
    except BaseException:
        for sock in sockets:
            sock.close()
        print(f"Startup failed. Inspect logs in {directory}; stop with: python3 {SCRIPT/'stack.py'} stop {directory} --remove-volumes", file=sys.stderr)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    begin = commands.add_parser("start")
    for name in ["directory", "indexer", "explorer", "reth"]:
        begin.add_argument("--"+name)
    end = commands.add_parser("stop"); end.add_argument("directory"); end.add_argument("--remove-volumes", action="store_true")
    status = commands.add_parser("status"); status.add_argument("directory")
    resume = commands.add_parser("restart"); resume.add_argument("directory"); resume.add_argument("--rebuild", action="store_true")
    acceptance = commands.add_parser("acceptance"); acceptance.add_argument("directory")
    args = parser.parse_args()
    if args.command == "start":
        start(args)
    elif args.command == "stop":
        stop(read_state(args.directory), args.remove_volumes)
    elif args.command == "restart":
        restart(read_state(args.directory), args.rebuild)
    elif args.command == "status":
        state = read_state(args.directory)
        print(json.dumps({"urls": state.get("urls"), "processes": {name: same_process(r, process_started(r["pid"])) for name, r in state["processes"].items()}}, indent=2))
    else:
        from acceptance import accept
        accept(read_state(args.directory))


if __name__ == "__main__":
    main()
