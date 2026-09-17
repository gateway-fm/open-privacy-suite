#!/usr/bin/env python3
"""Run an isolated real-node policy/identity/creation/revocation smoke test.
Needs the repo's Go toolchain and Python cryptography. All keys are public test keys.
"""
import argparse, base64, hashlib, json, os, pathlib, socket, subprocess, tempfile, time, urllib.request
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
ROOT = pathlib.Path(__file__).resolve().parents[3]
parser = argparse.ArgumentParser()
parser.add_argument('--binary', required=True)
args = parser.parse_args()
work = pathlib.Path(tempfile.mkdtemp(prefix='ops-reth-smoke-', dir=ROOT / '.tmp'))
signed = json.loads(subprocess.check_output(['go', 'run', './node/reth/scripts/smoke-sign'], cwd=ROOT))
key = Ed25519PrivateKey.from_private_bytes(bytes([7]) * 32)
network = {'chain_id': 31337, 'deployment_id': 'runtime-smoke'}
def seal(kind, payload):
    raw = json.dumps(payload, separators=(',', ':')).encode()
    preimage = b'OPS_NODE_POLICY_V1\0'
    for part in [kind.encode(), b'ops', raw]: preimage += len(part).to_bytes(4, 'big') + part
    return {'version': 1, 'kind': kind, 'key_id': 'ops', 'payload': base64.b64encode(raw).decode(), 'signature': base64.b64encode(key.sign(preimage)).decode()}
def header():
    now = int(time.time())
    return {'network': network, 'issued_at': now - 1, 'expires_at': now + 300}
def identity(scope, binding, context):
    return seal('identity', dict(header(), scope=scope, context_id=context, principal_id='fixture_principal', org_id='org_acme', signer=signed['sender'].lower(), binding_hash=binding, min_snapshot_version=1))
def port():
    with socket.socket() as sock: sock.bind(('127.0.0.1', 0)); return sock.getsockname()[1]
public, private, auth, p2p = [port() for _ in range(4)]
def rpc(method, params, internal=False):
    headers = {'Content-Type': 'application/json'}
    if internal: headers['Authorization'] = 'Bearer local-runtime-smoke-token'
    request = urllib.request.Request(f'http://127.0.0.1:{private if internal else public}', json.dumps({'jsonrpc': '2.0', 'id': 'smoke', 'method': method, 'params': params}).encode(), headers)
    return json.load(urllib.request.urlopen(request, timeout=10))
def result(method, params, internal=False):
    response = rpc(method, params, internal)
    assert 'error' not in response, (method, response)
    return response['result']
def simulation(method='eth_call', target=None, data=None, dry_run=False, candidate=None, options=None):
    request = json.dumps({'method': method, 'params': [{'from': signed['sender'].lower(), 'to': target or signed['target'], 'data': data or signed['data'], 'gas': '0x493e0'}, 'latest'] + ([] if options is None else [options]), 'dry_run': dry_run, 'candidate_policy': candidate}, separators=(',', ':')).encode()
    digest = '0x' + hashlib.sha256(b'OPS_SIMULATION_V1\0' + len(request).to_bytes(4, 'big') + request).hexdigest()
    return rpc('ops_simulate', [identity('simulation', digest, 'sim-' + str(time.time_ns())), base64.b64encode(request).decode()], True)
snapshot = json.loads((ROOT / 'internal/policydsl/testdata/lifecycle-v1.json').read_text())['snapshot']
snapshot.update(header())
snapshot['principals'][0]['linked_addresses'] = [signed['sender'].lower()]
foreign = '0x' + 'ee' * 20
snapshot['contracts'].append({'address': foreign, 'org_id': 'org_foreign', 'shared_infrastructure': False, 'code_hash': '', 'deployer_principal_id': '', 'pending': False})
config = dict(chainId=31337, homesteadBlock=0, eip150Block=0, eip155Block=0, eip158Block=0, byzantiumBlock=0, constantinopleBlock=0, petersburgBlock=0, istanbulBlock=0, berlinBlock=0, londonBlock=0, terminalTotalDifficulty=0, terminalTotalDifficultyPassed=True, shanghaiTime=0)
genesis = dict(config=config, nonce='0x0', timestamp='0x0', gasLimit='0x1c9c380', difficulty='0x0', baseFeePerGas='0x3b9aca00', alloc={signed['sender']: {'balance': '0x3635c9adc5dea00000'}, signed['target']: {'balance': '0x0', 'code': '0x00', 'storage': {'0x' + '00' * 32: '0x' + '00' * 30 + 'face'}}})
(work / 'genesis.json').write_text(json.dumps(genesis))
env = dict(os.environ, OPS_NODE_POLICY_CHAIN_ID='31337', OPS_NODE_POLICY_DEPLOYMENT_ID=network['deployment_id'], OPS_NODE_POLICY_PUBLIC_KEYS=json.dumps({'ops': base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()}), OPS_NODE_POLICY_STATE_DIR=str(work / 'policy'), OPS_NODE_POLICY_LISTEN=f'127.0.0.1:{private}', OPS_NODE_POLICY_TOKEN='local-runtime-smoke-token')
log = open(work / 'node.log', 'w')
command = [str(pathlib.Path(args.binary).resolve()), 'node', '--chain', str(work / 'genesis.json'), '--dev', '--dev.finality-depth', '1', '--dev.block-time', '1s', '--datadir', str(work / 'data'), '--http', '--http.addr', '127.0.0.1', '--http.port', str(public), '--http.api', 'eth,net,web3', '--authrpc.port', str(auth), '--port', str(p2p), '--disable-discovery', '--log.file.directory', str(work / 'logs'), '--color', 'never']
process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
try:
    for _ in range(100):
        if process.poll() is not None: raise RuntimeError('node exited during startup')
        try: status = result('ops_policyStatus', [], True); break
        except OSError: time.sleep(.1)
    else: raise RuntimeError('private API startup timeout')
    assert not status['ready']
    ack = result('ops_policyApply', [seal('snapshot', snapshot)], True)
    assert ack['version'] == snapshot['version'] and result('ops_policyStatus', [], True)['ready']
    assert 'result' in simulation(), 'signed current simulation failed'
    assert 'result' in simulation('eth_estimateGas'), 'scoped estimate failed'
    assert 'result' in simulation('debug_traceCall'), 'scoped trace failed'
    hidden_read = {signed['target']: {'code': '0x60005460005260206000f3'}}
    for diagnostic in [False, True]:
        assert 'error' in simulation(options=hidden_read, dry_run=diagnostic), 'simulation replaced allowed code with a hidden-storage oracle'
        assert 'error' in simulation('debug_traceCall', options={'stateOverrides': hidden_read}, dry_run=diagnostic), 'trace replaced allowed code'
        assert 'error' in simulation('debug_traceCall', options={'blockOverrides': {'number': '0x123'}}, dry_run=diagnostic), 'trace replaced block context'
    assert 'result' in simulation(options={}), 'empty override object should remain a no-op'
    candidate = dict(snapshot['policies'][0])
    candidate_bytes = bytes.fromhex('600160005260206000f3')
    candidate.update(bytecode=base64.b64encode(candidate_bytes).decode(), runtime_digest=hashlib.sha256(candidate_bytes).hexdigest())
    preview = simulation(candidate=candidate)
    assert preview['result']['policy']['would_allow'] is False and preview['result']['result'] == '0x', preview
    assert 'result' in simulation(), 'candidate altered the active policy'
    candidate_bytes = bytes.fromhex('73' + signed['target'][2:] + '3150600060005260206000f3')
    candidate.update(bytecode=base64.b64encode(candidate_bytes).decode(), runtime_digest=hashlib.sha256(candidate_bytes).hexdigest())
    assert 'error' in simulation(candidate=candidate), 'candidate probed unapproved live state'
    assert simulation(candidate=candidate, dry_run=True)['result']['policy']['would_allow'] is True
    assert 'error' in rpc('eth_call', [{'from': signed['sender'], 'to': signed['target'], 'data': signed['data']}, 'latest']), 'public call inherited identity'
    assert 'error' in rpc('ops_policyStatus', []), 'private API leaked onto public listener'
    receipts = {}
    for name in ['call', 'create']:
        tx = signed[name]
        accepted = result('ops_submitTransaction', [identity('transaction', tx['hash'], name), tx['raw']], True)
        assert accepted['transaction_hash'] == tx['hash']
        for _ in range(100):
            receipt = result('eth_getTransactionReceipt', [tx['hash']])
            if receipt: break
            time.sleep(.2)
        else: raise RuntimeError(f'{name} receipt timeout')
        assert receipt['status'] == '0x1', receipt
        receipts[name] = receipt
        for _ in range(100):
            status = result('ops_transactionStatus', [tx['hash']], True)
            if status['execution'].get('finalized'): break
            time.sleep(.1)
        else: raise RuntimeError(f'{name} finality timeout: {status}')
        assert status['execution']['status'] == 'included', status
        assert status['execution']['finalized_block_number'] >= int(receipt['blockNumber'], 16), status
        final_header = result('eth_getBlockByNumber', [hex(status['execution']['finalized_block_number']), False])
        assert final_header['hash'] == status['execution']['finalized_block_hash'], status
        assert status['execution']['block_hash'] == receipt['blockHash'], status
        if name == 'create':
            assert status['execution']['created'] == [{'address': receipt['contractAddress'], 'org_id': 'org_acme', 'principal_id': 'fixture_principal'}], status
    assert receipts['create']['contractAddress']
    snapshot.update(header()); snapshot['version'] += 1; snapshot['principals'][0]['banned'] = True
    result('ops_policyApply', [seal('snapshot', snapshot)], True)
    assert 'error' in simulation(), 'revoked principal still simulated'
    allowing = bytes.fromhex('600060005260206000f3')
    candidate.update(bytecode=base64.b64encode(allowing).decode(), runtime_digest=hashlib.sha256(allowing).hexdigest())
    assert 'error' in simulation(candidate=candidate), 'candidate bypassed active revocation'
    diagnostic = simulation(dry_run=True)
    assert diagnostic['result']['policy']['would_allow'] is False and diagnostic['result']['result'] == '0x', diagnostic
    assert 'error' in simulation(target=foreign, dry_run=True), 'diagnostic escaped the selected organization'
    tx = signed['denied']
    response = rpc('ops_submitTransaction', [identity('transaction', tx['hash'], 'banned'), tx['raw']], True)
    if 'result' in response:
        time.sleep(3)
        assert result('eth_getTransactionReceipt', [tx['hash']]) is None, 'revoked principal executed'
        status = result('ops_transactionStatus', [tx['hash']], True)
        assert status['execution']['status'] == 'denied' and not status['execution']['created'], status
    process.terminate(); process.wait(timeout=10)
    process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
    for _ in range(100):
        if process.poll() is not None: raise RuntimeError('node exited during restart')
        try: status = result('ops_policyStatus', [], True); break
        except OSError: time.sleep(.1)
    else: raise RuntimeError('private API restart timeout')
    assert status['ready'] and status['version'] == snapshot['version'], status
    status = result('ops_transactionStatus', [signed['create']['hash']], True)
    assert status['execution']['status'] == 'included' and status['execution']['created'][0]['address'] == receipts['create']['contractAddress'], status
    summary = {'ok': True, 'workdir': str(work), 'created': receipts['create']['contractAddress'], 'blocks': {name: receipt['blockNumber'] for name, receipt in receipts.items()}, 'checks': ['signed-facts', 'scoped-call-estimate-trace', 'public-isolation', 'state-and-block-override-rejection', 'signed-pool-submission', 'real-block-self-import', 'create', 'canonical-creation-status', 'chain-finality-evidence', 'candidate-preview-active-gate', 'candidate-live-read-isolation', 'current-revocation', 'scoped-admin-diagnostics', 'restart-recovery']}
    (work / 'result.json').write_text(json.dumps(summary, indent=2)); print(json.dumps(summary))
except Exception:
    log.flush(); print((work / 'node.log').read_text()[-16000:]); raise
finally:
    process.terminate()
    try: process.wait(timeout=10)
    except subprocess.TimeoutExpired: process.kill(); process.wait()
    log.close()
