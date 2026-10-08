#!/usr/bin/env python3
"""Compose lifecycle adapter for the existing real OPS/Reth demonstration."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import threading
import time
import urllib.request

import harness as h
import demo

STATE = Path('/demo/scenario.json')


class RemoteNode(h.Node):
    """Use the tested transaction/Engine methods against the Compose-owned node."""
    def __init__(self):
        self.rpc_url = 'http://reth:8545'
        self.engine_url = 'http://reth:8551'
        self.secret = Path('/demo/engine.jwt').read_bytes()
        self.secret = bytes.fromhex(self.secret.decode())
        self.fork = 'shanghai'
        self.records = []
        self.rpc_local = threading.local()
        self.rpc_connections = []
        self.rpc_connections_lock = threading.Lock()
        self.log_path = Path('/demo/node.log')
        self.head = self.rpc('eth_getBlockByNumber', 'latest', False)
        if int(self.rpc('eth_chainId'), 16) != 31337:
            raise RuntimeError('refusing a node outside the synthetic demo chain')


class DockerStack(demo.Stack):
    """Reuse HTTP fixture seeding; Compose owns all service processes."""
    def __init__(self, seed=False):
        self.url = 'http://proxy-backend:8080'
        self.admin_token = 'ops-reth-local-demo-only'
        self.tokens = {}
        self.node = RemoteNode()
        if seed:
            self.seed()
            STATE.write_text(json.dumps({key: getattr(self, key)
                                         for key in ('org', 'foreign', 'group', 'tokens')}, indent=2))
            STATE.chmod(0o600)
        else:
            state = json.loads(STATE.read_text())
            for key in ('org', 'foreign', 'group', 'tokens'):
                setattr(self, key, state[key])


def initialize():
    # solc-js works on both ARM64 and AMD64; its output is projected into the
    # same combined-json shape consumed by the native fixture generator.
    source = (h.HERE / 'contracts/Applications.sol').read_text()
    inp = {'language': 'Solidity', 'sources': {'Applications.sol': {'content': source}},
           'settings': {'optimizer': {'enabled': True, 'runs': 200}, 'evmVersion': 'shanghai',
                        'outputSelection': {'*': {'*': ['abi', 'evm.bytecode.object',
                                                       'evm.deployedBytecode.object']}}}}
    output = subprocess.check_output(['node', '/app/node-approvals/docker/compile.js'],
                                     input=json.dumps(inp), text=True)
    compiled = json.loads(output)
    errors = [e for e in compiled.get('errors', []) if e['severity'] == 'error']
    if errors:
        raise RuntimeError(errors)
    contracts = {f'Applications.sol:{name}': {'abi': c['abi'], 'bin': c['evm']['bytecode']['object'],
                                            'bin-runtime': c['evm']['deployedBytecode']['object']}
                 for name, c in compiled['contracts']['Applications.sol'].items()}
    h.prepare_fixtures({'contracts': contracts})
    Path('/demo/engine.jwt').write_text('11' * 32)
    Path('/demo/approval-seed.hex').write_text('07' * 32)
    for path in (Path('/demo/engine.jwt'), Path('/demo/approval-seed.hex')):
        path.chmod(0o600)
    # Match the shared backend and Reth runtime uid. Initialization alone runs root.
    for directory, _, files in os.walk('/demo'):
        os.chown(directory, 1000, 1000)
        for filename in files:
            os.chown(Path(directory) / filename, 1000, 1000)


def seed():
    wait_for_ready()
    if STATE.exists():
        print('Existing demo fixtures retained; use demo-reth-reset for a fresh chain.', flush=True)
        return
    stack = DockerStack(seed=True)
    print(f'Seeded Bank A {stack.org}, Bank B {stack.foreign}.', flush=True)
    print('Development identity: did:test:reth-demo-alice', flush=True)
    print('Local development admin token: ops-reth-local-demo-only', flush=True)


def wait_for_ready():
    """Process health alone does not establish a usable approval receiver."""
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen('http://proxy-backend:8080/metrics', timeout=5) as response:
                metrics = response.read().decode()
            if any(line.startswith('privacyproxy_approval_target_ready{')
                   and float(line.rsplit(' ', 1)[1]) == 1 for line in metrics.splitlines()):
                return
        except OSError:
            pass
        time.sleep(.5)
    raise RuntimeError('OPS has no compatible ready approval producer')


def direct_canary(stack, pause):
    demo.announce('4. Submit directly to Reth without an OPS approval. '
                  'It must not consume nonce, fees, or change application state.', pause)
    n = stack.node
    before = n.snapshot()
    # The preceding veto can leave Alice's nonce in the pool until TTL expiry.
    # Replace that pending transaction so this checks approval enforcement,
    # rather than failing at the ordinary replacement-price gate.
    tx = n.raw(h.ALICE, h.ADMIN, '0x', value=1, gas=21000, fee=4_000_000_000)
    n.submit(tx)
    n.make_block([])
    time.sleep(2)
    n.make_block([])
    deadline = time.monotonic() + 5
    while n.rpc('eth_getTransactionByHash', tx['hash']) is not None:
        if time.monotonic() >= deadline:
            raise RuntimeError('unapproved transaction did not leave the pool')
        time.sleep(.1)
    receipt = n.rpc('eth_getTransactionReceipt', tx['hash'])
    after = n.snapshot()
    if receipt is not None or before != after:
        raise RuntimeError({'receipt': receipt, 'before': before, 'after': after})
    (h.EVIDENCE / 'direct-canary.json').write_text(json.dumps(
        {'passed': True, 'transaction': tx['hash'], 'receipt': receipt,
         'before': before, 'after': after}, indent=2) + '\n')
    print('PASS — no approval: no receipt, no nonce or balance change; transaction dropped.', flush=True)


def drive():
    n = RemoteNode()
    print('Demo Engine API driver producing blocks every second.', flush=True)
    while True:
        n.head = n.rpc('eth_getBlockByNumber', 'latest', False)
        state = {'headBlockHash': n.head['hash'], 'safeBlockHash': n.head['hash'],
                 'finalizedBlockHash': n.head['hash']}
        attrs = {'timestamp': hex(int(n.head['timestamp'], 16) + 1),
                 'prevRandao': h.ZERO, 'suggestedFeeRecipient': h.ADMIN, 'withdrawals': []}
        result = n.engine('engine_forkchoiceUpdatedV2', state, attrs)
        if result['payloadStatus']['status'] != 'VALID':
            raise RuntimeError(result)
        time.sleep(.5)
        payload = n.engine('engine_getPayloadV2', result['payloadId'])['executionPayload']
        result = n.engine('engine_newPayloadV2', payload)
        if result['status'] != 'VALID':
            raise RuntimeError(result)
        state = {key: payload['blockHash'] for key in state}
        result = n.engine('engine_forkchoiceUpdatedV2', state, None)
        if result['payloadStatus']['status'] != 'VALID':
            raise RuntimeError(result)
        time.sleep(.5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['init', 'seed', 'drive', 'check', 'walkthrough'])
    args = parser.parse_args()
    if args.mode == 'init':
        initialize()
    elif args.mode == 'seed':
        seed()
    elif args.mode == 'drive':
        drive()
    else:
        stack = DockerStack()
        if int(stack.node.head['number'], 16) != 0:
            raise RuntimeError('walkthrough/check requires fresh demo volumes and a stopped driver')
        pause = args.mode == 'walkthrough'
        demo.story(stack, pause)
        direct_canary(stack, pause)
        # Leave the retained development stack usable after the adversarial story.
        restore = stack.node.raw(h.ADMIN, h.RELAY, 'setTarget(address)', h.VAULT_A)
        response = stack.submit(restore)
        if response.get('result') != restore['hash']:
            raise RuntimeError(response)
        stack.node.make_block([restore])
        print('All four real OPS/Reth scenarios passed.', flush=True)


if __name__ == '__main__':
    main()
