#!/usr/bin/env python3
"""Bounded real-node load acceptance. Uses public deterministic development keys.

This measures private HTTP admission through canonical mining, with durable facts,
identity journals and block manifests enabled. It is not an isolated EVM benchmark.
Run beside other workloads only when their contention is recorded in the report.
"""
import argparse
import base64
import concurrent.futures
import copy
import hashlib
import http.client
import json
import os
import pathlib
import platform
import socket
import subprocess
import tempfile
import threading
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = pathlib.Path(__file__).resolve().parents[3]
TARGET = '0x1f98431c8ad98523631ae4a59f267346ea31f984'
TOKEN = 'isolated-public-development-load-token'
KEY = Ed25519PrivateKey.from_private_bytes(bytes([7]) * 32)


def encode(value):
    return json.dumps(value, separators=(',', ':')).encode()


def seal(kind, payload):
    raw = encode(payload)
    preimage = b'OPS_NODE_POLICY_V1\0'
    for part in [kind.encode(), b'load', raw]:
        preimage += len(part).to_bytes(4, 'big') + part
    return dict(version=1, kind=kind, key_id='load', payload=base64.b64encode(raw).decode(),
                signature=base64.b64encode(KEY.sign(preimage)).decode())


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def command_value(command):
    try:
        return subprocess.check_output(command, stderr=subprocess.DEVNULL, text=True, timeout=15).strip()
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None


def distribution(values):
    if not values:
        return None
    values = sorted(values)
    return dict(count=len(values), mean=sum(values) / len(values),
                p50=values[int((len(values)-1)*.50)], p95=values[int((len(values)-1)*.95)],
                p99=values[int((len(values)-1)*.99)], maximum=values[-1])


class Node:
    def __init__(self, args, work, phase, generated):
        self.args, self.work, self.phase = args, work, phase
        self.public, self.private, auth, p2p = [free_port() for _ in range(4)]
        self.network = dict(chain_id=31337, deployment_id='load-' + phase)
        self.local = threading.local()
        self.snapshot = copy.deepcopy(json.loads((ROOT / 'internal/policydsl/testdata/lifecycle-v1.json').read_text())['snapshot'])
        self.snapshot.update(self.header())
        self.snapshot['principals'][0]['linked_addresses'] += [address.lower() for address in generated['senders']]
        for i in range(args.facts_principals - 1):
            self.snapshot['principals'].append(dict(id=f'inactive-load-{i}', banned=False, kyc=False,
                                                    linked_addresses=[f'0x{0x100000+i:040x}'], memberships=[]))
        alloc = {address: dict(balance='0x3635c9adc5dea00000') for address in generated['senders']}
        alloc[TARGET] = dict(balance='0x0', code='0x00')
        self.expected_frames = 1
        if phase == 'nested':
            b, c = '0x' + 'dd' * 20, '0x' + 'ee' * 20
            def call(address):
                return '0x6000600060006000600073' + address[2:] + '5af15000'
            alloc[TARGET]['code'], alloc[b], alloc[c] = call(b), dict(balance='0x0', code=call(c)), dict(balance='0x0', code='0x00')
            for address in [b, c]:
                self.snapshot['contracts'].append(dict(address=address, org_id='org_acme', shared_infrastructure=False,
                                                       code_hash='', deployer_principal_id='', pending=False))
            self.expected_frames = 3
        if phase == 'record-party':
            vector = json.loads((ROOT / 'internal/policydsl/testdata/record-party-v1.json').read_text())
            bytecode = bytes.fromhex(vector['policy_runtime_hex'][2:])
            self.snapshot['policies'][0].update(bytecode=base64.b64encode(bytecode).decode(),
                                                runtime_digest=hashlib.sha256(bytecode).hexdigest(), policy_digest=vector['policy_digest'])
            source=(ROOT/'node/reth/scripts/LoadRecord.sol').read_text()
            compiler_input=dict(language='Solidity',sources={'LoadRecord.sol':{'content':source}},settings={
                'optimizer':{'enabled':True,'runs':200},'evmVersion':'shanghai','outputSelection':{'*':{'*':['evm.deployedBytecode.object']}}})
            compiled=json.loads(subprocess.check_output([os.environ.get('POLICY_SOLC','solc'),'--standard-json'],input=encode(compiler_input)))
            if any(error.get('severity')=='error' for error in compiled.get('errors',[])):
                raise RuntimeError(str(compiled['errors']))
            runtime='0x'+compiled['contracts']['LoadRecord.sol']['LoadRecord']['evm']['deployedBytecode']['object']
            (work/'record-compiler.json').write_text(json.dumps(compiled,indent=2))
            alloc[TARGET].update(code=runtime, storage={f'0x{int(k, 0):064x}': f'0x{int(v, 0):064x}'
                                for k, v in vector['cases'][0]['storage'].items()})
        config = dict(chainId=31337, homesteadBlock=0, eip150Block=0, eip155Block=0, eip158Block=0,
                      byzantiumBlock=0, constantinopleBlock=0, petersburgBlock=0, istanbulBlock=0,
                      berlinBlock=0, londonBlock=0, terminalTotalDifficulty=0,
                      terminalTotalDifficultyPassed=True, shanghaiTime=0)
        genesis = dict(config=config, nonce='0x0', timestamp='0x0', gasLimit=hex(args.block_gas_limit),
                       difficulty='0x0', baseFeePerGas='0x3b9aca00', alloc=alloc)
        (work / 'genesis.json').write_bytes(encode(genesis))
        self.log = open(work / 'node.log', 'w')
        env = dict(os.environ, OPS_NODE_POLICY_CHAIN_ID='31337', OPS_NODE_POLICY_DEPLOYMENT_ID=self.network['deployment_id'],
                   OPS_NODE_POLICY_PUBLIC_KEYS=json.dumps({'load': base64.b64encode(KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()}),
                   OPS_NODE_POLICY_STATE_DIR=str(work / 'policy'), OPS_NODE_POLICY_LISTEN=f'127.0.0.1:{self.private}',
                   OPS_NODE_POLICY_TOKEN=TOKEN)
        self.command = [str(pathlib.Path(args.binary).resolve()), 'node', '--chain', str(work / 'genesis.json'),
                        '--dev', '--dev.finality-depth', '1', '--dev.block-time', '1s', '--builder.gaslimit', str(args.block_gas_limit),
                        '--engine.cross-block-cache-size', str(args.execution_cache_mib),
                        '--txpool.max-account-slots', str(args.transactions * args.rounds + 64),
                        '--datadir', str(work / 'data'), '--http', '--http.addr', '127.0.0.1', '--http.port', str(self.public),
                        '--http.api', 'eth,net,web3', '--authrpc.port', str(auth), '--port', str(p2p), '--disable-discovery',
                        '--log.file.directory', str(work / 'logs'), '--color', 'never']
        self.process = subprocess.Popen(self.command, cwd=ROOT, env=env, stdout=self.log, stderr=subprocess.STDOUT)
        self.stop = threading.Event()
        self.samples, self.publications, self.publication_errors = [], [], []
        self.publisher = None
        for _ in range(200):
            if self.process.poll() is not None:
                raise RuntimeError('node startup failed: ' + (work / 'node.log').read_text()[-6000:])
            try:
                self.rpc('ops_policyStatus', [], True)
                break
            except (OSError, RuntimeError, http.client.HTTPException):
                time.sleep(.1)
        else:
            raise RuntimeError('node startup timeout')
        ack = self.rpc('ops_policyApply', [seal('snapshot', self.snapshot)], True)
        self.digest, self.version = ack['digest'], ack['version']
        assert self.rpc('ops_policyStatus', [], True)['ready']
        self.sampler = threading.Thread(target=self.sample_memory, daemon=True)
        self.sampler.start()

    def header(self):
        now = int(time.time())
        return dict(network=self.network, issued_at=now-1, expires_at=now+300)

    def rpc(self, method, params, private=False):
        key = 'private' if private else 'public'
        connections = getattr(self.local, 'connections', None)
        if connections is None:
            connections = self.local.connections = {}
        body = encode(dict(jsonrpc='2.0', id='load', method=method, params=params))
        headers = {'Content-Type': 'application/json'}
        if private:
            headers['Authorization'] = 'Bearer ' + TOKEN
        # Identical RPC retries are idempotent for these benchmark methods.
        for attempt in range(2):
            connection = connections.setdefault(key, http.client.HTTPConnection('127.0.0.1', self.private if private else self.public, timeout=30))
            try:
                connection.request('POST', '/', body, headers)
                response = connection.getresponse()
                result = json.loads(response.read())
                if response.status != 200 or 'error' in result:
                    raise RuntimeError(str(result))
                return result['result']
            except (OSError, http.client.HTTPException):
                connection.close()
                del connections[key]
                if attempt:
                    raise

    def identity(self, tx):
        return seal('identity', dict(self.header(), scope='transaction', context_id='load-' + tx['hash'][2:],
                                    principal_id='fixture_principal', org_id='org_acme', signer=tx['signer'].lower(),
                                    binding_hash=tx['hash'], min_snapshot_version=1))

    def sample_memory(self):
        while not self.stop.is_set():
            value = command_value(['ps', '-o', 'rss=', '-p', str(self.process.pid)])
            if value:
                self.samples.append(dict(at=time.time(), rss_kib=int(value)))
            self.stop.wait(.5)

    def churn(self):
        while not self.stop.wait(self.args.churn_interval):
            try:
                previous, previous_digest = self.version, self.digest
                self.version += 1
                self.snapshot.update(self.header(), version=self.version)
                self.snapshot['groups'][0]['claims'] = 7 if self.version % 2 else 3
                kind, payload = 'snapshot', self.snapshot
                if self.version % 8:
                    kind = 'delta'
                    empty = dict(principals=[], groups=[], contracts=[], policies=[], sanctions=[])
                    payload = dict(self.header(), previous_version=previous, previous_digest=previous_digest, version=self.version,
                                   upserts=dict(empty, groups=self.snapshot['groups']), deletes=empty)
                started = time.monotonic()
                ack = self.rpc('ops_policyApply', [seal(kind, payload)], True)
                assert ack['version'] == self.version
                self.digest = ack['digest']
                self.publications.append(dict(kind=kind, version=self.version, milliseconds=(time.monotonic()-started)*1000))
            except Exception as error:
                self.publication_errors.append(str(error))
                return

    def close(self):
        if hasattr(self,'stop'):
            self.stop.set()
        if getattr(self,'publisher',None):
            self.publisher.join(timeout=35)
        if hasattr(self,'sampler'):
            self.sampler.join(timeout=2)
        if hasattr(self,'process'):
            self.process.terminate()
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        if hasattr(self,'log'):
            self.log.close()


def run_phase(args, work, phase):
    vector = json.loads((ROOT / 'internal/policydsl/testdata/record-party-v1.json').read_text())
    data = vector['call_data_hex'] if phase == 'record-party' else '0x'
    total = args.transactions * args.rounds
    generated = json.loads(subprocess.check_output(['go', 'run', './node/reth/scripts/load-sign', '-count', str(total),
                            '-senders', str(args.senders), '-data', data], cwd=ROOT))
    node = Node.__new__(Node)
    records, rounds, mined = {}, [], {}
    try:
        node.__init__(args, work, phase, generated)
        if phase == 'churn':
            node.publisher = threading.Thread(target=node.churn, daemon=True)
            node.publisher.start()
        last_block = int(node.rpc('eth_blockNumber', []), 16)
        def submit(tx):
            started = time.monotonic()
            record = dict(hash=tx['hash'], signer=tx['signer'], nonce=tx['nonce'], started=started)
            try:
                ack = node.rpc('ops_submitTransaction', [node.identity(tx), tx['raw']], True)
                assert ack['transaction_hash'] == tx['hash']
                record['accepted'] = True
            except Exception as error:
                record.update(accepted=False, error=str(error))
            record['admission_ms'] = (time.monotonic()-started)*1000
            return record
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as executor:
            for index in range(args.rounds):
                started = time.monotonic()
                batch = generated['transactions'][index*args.transactions:(index+1)*args.transactions]
                futures = [executor.submit(submit, tx) for tx in batch]
                deadline = started + args.timeout
                while time.monotonic() < deadline:
                    latest = int(node.rpc('eth_blockNumber', []), 16)
                    for height in range(last_block+1, latest+1):
                        block = node.rpc('eth_getBlockByNumber', [hex(height), False])
                        observed = time.monotonic()
                        for txhash in block['transactions']:
                            mined[txhash] = dict(block=height, observed=observed)
                    last_block = latest
                    if all(future.done() for future in futures):
                        current = [future.result() for future in futures]
                        if all(not item['accepted'] or item['hash'] in mined for item in current):
                            break
                    time.sleep(.05)
                current = [future.result() for future in futures]
                for item in current:
                    records[item['hash']] = item
                rounds.append(dict(round=index+1, admitted=sum(item['accepted'] for item in current),
                                   mined=sum(item['hash'] in mined for item in current), seconds=time.monotonic()-started))
                if rounds[-1]['mined'] != rounds[-1]['admitted']:
                    break
        # Receipts validate actual execution success; block membership alone is
        # not classified as a successful application transaction.
        memory_stages={'before_receipts_kib':command_value(['ps','-o','rss=','-p',str(node.process.pid)])}
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as executor:
            receipts = list(executor.map(lambda txhash: node.rpc('eth_getTransactionReceipt', [txhash]),
                                         [txhash for txhash in records if txhash in mined]))
        receipt_statuses = [receipt['status'] for receipt in receipts]
        memory_stages['after_receipts_kib']=command_value(['ps','-o','rss=','-p',str(node.process.pid)])
        reconciliation_start = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as executor:
            reconciled = list(executor.map(lambda txhash: node.rpc('ops_transactionStatus', [txhash], True)['execution'],
                                           [txhash for txhash in records if txhash in mined]))
        reconciliation_seconds = time.monotonic() - reconciliation_start
        memory_stages['after_status_kib']=command_value(['ps','-o','rss=','-p',str(node.process.pid)])
        if args.memory_map:
            mapped=command_value(['vmmap','-summary',str(node.process.pid)])
            if mapped:
                (work/'memory-map.txt').write_text(mapped)
        node.stop.set()
        if node.publisher:
            node.publisher.join(timeout=35)
        pending = [txhash for txhash, record in records.items() if record['accepted'] and txhash not in mined]
        pending_status = [node.rpc('ops_transactionStatus', [txhash], True)['execution']['status'] for txhash in pending]
        # A separate denied probe is deliberately excluded from allowed TPS.
        node.snapshot.update(node.header(), version=node.version+1)
        node.snapshot['principals'][0]['banned'] = True
        node.rpc('ops_policyApply', [seal('snapshot', node.snapshot)], True)
        probe = submit(generated['transactions'][-1])
        probe_status = 'admission_rejected'
        if probe['accepted']:
            for _ in range(100):
                probe_status = node.rpc('ops_transactionStatus', [probe['hash']], True)['execution']['status']
                if probe_status == 'denied':
                    break
                time.sleep(.1)
            assert node.rpc('eth_getTransactionReceipt', [probe['hash']]) is None, 'banned probe mined'
        duration = sum(item['seconds'] for item in rounds)
        included = [record for txhash, record in records.items() if txhash in mined]
        result = dict(phase=phase, attempted=len(records), admitted=sum(item['accepted'] for item in records.values()),
                      admission_rejected=sum(not item['accepted'] for item in records.values()),
                      mined=len(included), succeeded=receipt_statuses.count('0x1'), reverted=receipt_statuses.count('0x0'),
                      pending=len(pending), pending_statuses=pending_status, denied_probe=dict(admitted=probe['accepted'], status=probe_status),
                      reconciliation_seconds=reconciliation_seconds, canonical_statuses=sum(item['status']=='included' for item in reconciled),
                      memory_stages=memory_stages,
                      seconds=duration, mined_tps=len(included)/duration, rounds=rounds,
                      admission_ms=distribution([item['admission_ms'] for item in records.values()]),
                      submission_to_observed_inclusion_ms=distribution([(mined[item['hash']]['observed']-item['started'])*1000 for item in included]),
                      application_frames_per_transaction=node.expected_frames, record_party_getter=(phase=='record-party'),
                      facts_principals=len(node.snapshot['principals']), publications=node.publications,
                      publication_ms=distribution([item['milliseconds'] for item in node.publications]), publication_errors=node.publication_errors,
                      rss_samples=node.samples, admission_errors=[item['error'] for item in records.values() if not item['accepted']],
                      node_command=node.command)
        rss = [sample['rss_kib'] for sample in node.samples]
        result['rss'] = dict(first_kib=rss[0], last_kib=rss[-1], peak_kib=max(rss), samples=len(rss)) if rss else None
        result['correct'] = (result['attempted']==total and result['admitted']==total and result['succeeded']==total
                             and result['canonical_statuses']==total and not pending and not node.publication_errors and probe_status=='denied')
        return result
    finally:
        node.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--transactions', type=int, default=512, help='allowed transactions per round')
    parser.add_argument('--rounds', type=int, default=3)
    parser.add_argument('--senders', type=int, default=8)
    parser.add_argument('--concurrency', type=int, default=8)
    parser.add_argument('--facts-principals', type=int, default=1000)
    parser.add_argument('--block-gas-limit', type=int, default=150000000)
    parser.add_argument('--execution-cache-mib', type=int, default=64, help='Reth cross-block cache budget; upstream64bit default4096')
    parser.add_argument('--timeout', type=float, default=120)
    parser.add_argument('--churn-interval', type=float, default=.25)
    parser.add_argument('--phases', default='plain,nested,record-party,churn')
    parser.add_argument('--contention-note', default='Other workload contention was not controlled.')
    parser.add_argument('--memory-map',action='store_true',help='Save own-node vmmap summary on macOS')
    args = parser.parse_args()
    if min(args.transactions,args.rounds,args.senders,args.concurrency,args.facts_principals)<1:
        parser.error('workload counts must be positive')
    phases=args.phases.split(',')
    if any(phase not in ['plain','nested','record-party','churn'] for phase in phases):
        parser.error('unknown phase')
    work=pathlib.Path(tempfile.mkdtemp(prefix='ops-reth-load-',dir=ROOT/'.tmp'))
    report=dict(schema=1, workdir=str(work), configuration=vars(args), started_at=time.time(),
                binary_sha256=hashlib.sha256(pathlib.Path(args.binary).read_bytes()).hexdigest(),
                hardware=dict(platform=platform.platform(),machine=platform.machine(),logical_cpus=os.cpu_count(),
                              model=command_value(['sysctl','-n','hw.model']), cpu=command_value(['sysctl','-n','machdep.cpu.brand_string']),
                              memory_bytes=command_value(['sysctl','-n','hw.memsize'])), phases=[])
    for phase in phases:
        directory=work/phase
        directory.mkdir()
        result=run_phase(args,directory,phase)
        result['archive_kib']=command_value(['du','-sk',str(directory/'policy')])
        report['phases'].append(result)
        (work/'result.json').write_text(json.dumps(report,indent=2))
        print(json.dumps({key:result[key] for key in ['phase','correct','admitted','mined','succeeded','seconds','mined_tps','rss']}),flush=True)
    report['finished_at']=time.time()
    report['correct']=all(phase['correct'] for phase in report['phases'])
    (work/'result.json').write_text(json.dumps(report,indent=2))
    print(json.dumps(dict(correct=report['correct'],report=str(work/'result.json'))),flush=True)
    if not report['correct']:
        raise SystemExit(1)


if __name__=='__main__':
    main()
