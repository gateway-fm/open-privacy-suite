"""Opt-in real HTTP group-artifact acceptance, following stack.py acceptance.

No application-table writes or node admission bypasses. The benchmark fixture
contains only disposable policy bytecode and identifiers, never credentials.
"""
import base64
import copy
import hashlib
import json
from pathlib import Path
import statistics
import sys
import time
import uuid

from stack import helper, http, read_state, save, wait_http, write_private


def accept_groups(state):
    base = state['urls']['ops']
    previous = state['acceptance']
    org, target = previous['orgId'], previous['contract']
    prefix = '/api/v1/admin/orgs/'+org
    evidence = {'checks': [], 'latency': [], 'binaryDigests': state['binaryDigests']}
    report = Path(state['directory'])/'group-acceptance.json'

    def check(name):
        evidence['checks'].append(name)
        write_private(report, json.dumps(evidence, indent=2)+'\n')
        print('PASS '+name, flush=True)

    def request(path, body=None, token=None, method=None, expect=200):
        status, result = http(base+path, body, token, method, timeout=320)
        assert status == expect, f'{path}: expected {expect}, got {status}: {result}'
        return result

    def login(role):
        session = request('/auth/request', {})
        return request('/auth/verify', {'session_id': session['session_id'], 'jwz_token': 'mock.'+state['subjects'][role]})['access_token']

    author, reviewer, user = [login(role) for role in ['author', 'reviewer', 'user']]

    def ready():
        wait_http(state, 'group policy publication', base+'/ready', timeout=90)

    def submit(kind, source):
        started = time.monotonic()
        result = request(prefix+'/configuration/'+kind+'/revisions', source, author, expect=201)
        evidence.setdefault('compileSeconds', []).append({'kind': kind, 'seconds': round(time.monotonic()-started, 3), 'revision': result['id']})
        return result

    def activate(kind, revision):
        path = prefix+'/configuration/'+kind+'/revisions/'+revision['id']
        request(path+'/simulate', {'coactivate': []}, reviewer)
        denied, _ = http(base+path+'/activate', {'coactivate': []}, author)
        assert denied == 403, f'Self-approval accepted: {denied}'
        request(path+'/activate', {'coactivate': []}, reviewer)
        ready()

    def call(selector):
        return http(base+'/rpc/'+org, {'jsonrpc': '2.0', 'id': 1, 'method': 'eth_call', 'params': [{'from': state['sender'], 'to': target, 'data': selector}, 'latest']}, user)

    def allowed(selector):
        status, result = call(selector)
        return status == 200 and 'result' in result

    def member(group, remove=False):
        request(prefix+'/memberships/by-did', {'did': state['subjects']['user'], 'group_id': group}, author, method='DELETE' if remove else 'POST', expect=200 if remove else 201)

    def preview(revision, expected):
        time.sleep(1.05)  # The real administrator preview API enforces 1 request/s.
        result = request(prefix+'/execution/simulate', {'principalId': previous['principals']['user'], 'candidateRevisionId': revision['id'], 'dryRun': True, 'method': 'eth_call', 'params': [{'from': state['sender'], 'to': target, 'data': '0x3fa4f245'}, 'latest']}, reviewer)
        decisions = result['policy']['decisions']
        assert len(decisions) == 1, result
        assert (decisions[0]['reason_code'] == 0) == expected, result
        return result

    original = request(prefix+'/configuration/execution-rules/context', token=author)['source']
    groups_source = request(prefix+'/configuration/groups/context', token=author)['source']
    groups = sorted(str(uuid.uuid4()) for _ in range(60))
    for i, group in enumerate(groups):
        groups_source['spec']['groups'].append({'id': group, 'slug': 'scale-'+str(i), 'name': 'Scale '+str(i), 'description': 'Disposable live group acceptance', 'isOrgAdmin': False, 'isOrgReadonlyAdmin': False, 'allowedMethods': ['*'], 'claims': [], 'verboseErrors': True})
    activate('groups', submit('groups', groups_source))
    registry = request(prefix+'/configuration/contract-registry/context', token=author)['source']
    abi = next(c['abi'] for c in registry['spec']['contracts'] if c['address'] == target)
    digest = hashlib.sha256(json.dumps(abi, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    source = copy.deepcopy(original)
    bindings = []
    for i, group in enumerate(groups):
        rules = [{'storageAddress': target, 'selector': '0xd09de08a', 'abiDigest': digest}]
        if i == 59:
            rules.append({'storageAddress': target, 'selector': '0x3fa4f245', 'abiDigest': digest})
        bindings.append({'group': group, 'allow': rules})
    source['spec']['policy']['bindings'] = bindings
    large = submit('execution-rules', source)
    artifacts = large['artifact']['groups']
    assert set(artifacts) == set(groups), 'Compilation did not retain all 60 artifacts'
    sizes = [len(base64.b64decode(a['runtime_bytecode'])) for a in artifacts.values()]
    assert all(0 < size <= 24576 for size in sizes), sizes
    evidence['artifacts'] = {'count': len(sizes), 'minBytes': min(sizes), 'maxBytes': max(sizes), 'totalBytes': sum(sizes)}
    # Reproducible release benchmark input: the exact bytecode returned by OPS.
    fixture = {'org': org, 'target': target, 'signer': state['sender'], 'groups': groups, 'artifacts': artifacts}
    write_private(Path(state['directory'])/'group-cost-fixture.json', json.dumps(fixture)+'\n')
    activate('execution-rules', large)
    member(groups[-1])
    ready()
    assert allowed('0x3fa4f245'), 'Single matching group denied'
    status, nonce = http(f"http://127.0.0.1:{state['ports']['reth']}", {'jsonrpc': '2.0', 'id': 1, 'method': 'eth_getTransactionCount', 'params': [state['sender'], 'latest']})
    assert status == 200 and 'result' in nonce
    signed = helper(state, {'Action': 'transaction', 'Nonce': int(nonce['result'], 16), 'GasPrice': state['acceptanceGasPrice']*2, 'To': target, 'Data': '0xd09de08a'})
    sent = request('/rpc/'+org, {'jsonrpc': '2.0', 'id': 1, 'method': 'eth_sendRawTransaction', 'params': [signed['raw']]}, user)
    assert sent.get('result') == signed['hash'], sent
    deadline = time.monotonic()+90
    while time.monotonic() < deadline:
        result = request('/api/v1/me/transactions/'+signed['hash']+'/execution', token=user)
        assert result['status'] not in ['denied', 'reverted'], result
        if result['status'] == 'included' and result['reconciled']:
            break
        time.sleep(.5)
    else:
        raise AssertionError(f'60-group transaction did not finalize: {result}')
    evidence['finalizedTransaction'] = signed['hash']
    check('60-group document compiled, independently activated, published and executed')

    # Two memberships: the first group has no value() rule; the second does.
    member(groups[0])
    ready()
    assert allowed('0x3fa4f245'), 'Later matching group did not permit execution'
    member(groups[-1], remove=True)
    ready()
    assert not allowed('0x3fa4f245'), 'Removed membership retained its grant'
    assert allowed('0xd09de08a'), 'Remaining membership lost its own grant'
    member(groups[-1])
    ready()
    check('any-group grant union and live membership revocation enforce current facts')

    replacement = request(prefix+'/configuration/execution-rules/context', token=author)['source']
    replacement['spec']['policy']['bindings'] = [bindings[0]]
    reduced = submit('execution-rules', replacement)
    preview(reduced, False)
    assert allowed('0x3fa4f245'), 'Candidate preview changed active policy'
    activate('execution-rules', reduced)
    assert not allowed('0x3fa4f245'), 'Removed artifact survived replacement'
    assert allowed('0xd09de08a')
    check('candidate replacement is isolated; activation removes absent group artifacts')

    # Refresh baseRevision from current context before each replacement.
    restored = request(prefix+'/configuration/execution-rules/context', token=author)['source']
    restored['spec']['policy']['bindings'] = bindings
    activate('execution-rules', submit('execution-rules', restored))
    current_count = 2
    for count in [1, 2, 5, 10, 20, 40, 60]:
        if count == 1:
            member(groups[0], remove=True)
            current_count = 1
        while current_count < count:
            member(groups[current_count-1])
            current_count += 1
        ready()
        for mode, selector in [('allow-first', '0xd09de08a'), ('allow-last', '0x3fa4f245')]:
            durations, outcomes, errors = [], [], []
            for i in range(23):
                time.sleep(.12)  # Measure serial latency without exercising the RPC rate limiter.
                started = time.monotonic()
                status, result = call(selector)
                elapsed = (time.monotonic()-started)*1000
                ok = status == 200 and 'result' in result
                if i >= 3:
                    durations.append(elapsed)
                    outcomes.append(ok)
                    if not ok:
                        errors.append({'status': status, 'response': result})
            assert len(set(outcomes)) == 1, f'Unstable live verdict: {count} {mode}'
            if mode == 'allow-first' or count <= 2:
                assert all(outcomes), f'Expected execution grant: {count} {mode}'
            if errors:
                assert all(e == {'status': 403, 'response': {'error': 'request rejected by execution node', 'reason': 'node_rejected'}} for e in errors), errors
            ordered = sorted(durations)
            row = {'membershipsWithArtifacts': count, 'mode': mode, 'samples': len(durations), 'allowed': outcomes[0], 'medianMs': round(statistics.median(durations), 3), 'p95Ms': round(ordered[18], 3)}
            if errors:
                row['error'] = errors[0]
            evidence['latency'].append(row)
            print(json.dumps(row), flush=True)
    check('live RPC latency measured across 1, 2, 5, 10, 20, 40 and 60 group memberships')

    # Reduce memberships before checking semantic denial, independently of gas.
    for group in groups[:-1]:
        member(group, remove=True)
    ready()
    empty_source = request(prefix+'/configuration/execution-rules/context', token=author)['source']
    empty_source['spec']['policy']['bindings'] = []
    empty = submit('execution-rules', empty_source)
    preview(empty, False)
    activate('execution-rules', empty)
    assert not allowed('0x3fa4f245')
    recovery_source = request(prefix+'/configuration/execution-rules/context', token=author)['source']
    recovery_source['spec']['policy']['bindings'] = [bindings[-1]]
    recovery = submit('execution-rules', recovery_source)
    preview(recovery, True)
    assert not allowed('0x3fa4f245'), 'Recovery preview changed deny-all active policy'
    activate('execution-rules', recovery)
    assert allowed('0x3fa4f245')
    check('empty set denies execution; scoped candidate diagnostics can recover it')

    # Restore the original revocation document for the harness restart assertions.
    final_source = request(prefix+'/configuration/execution-rules/context', token=author)['source']
    final_source['spec'] = original['spec']
    final_revision = submit('execution-rules', final_source)
    activate('execution-rules', final_revision)
    previous['activeRevisionId'], previous['activePolicyDigest'] = final_revision['id'], final_revision['digest']
    write_private(Path(state['directory'])/'acceptance.json', json.dumps(previous, indent=2)+'\n')
    state['groupAcceptance'] = evidence
    save(state)
    write_private(report, json.dumps(evidence, indent=2)+'\n')
    print('Group acceptance complete: '+str(report), flush=True)


if __name__ == '__main__':
    accept_groups(read_state(sys.argv[1]))
