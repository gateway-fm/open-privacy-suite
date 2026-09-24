#!/usr/bin/env python3
"""Call-only approval correctness against real Reth and the real OPS HTTP stack."""
import argparse
import concurrent.futures
import contextlib
import json
import os
import time
import harness as h
import run as r
from lifecycle_tests import receipt, storage, balance, nonce


def counter_comparison(count=64):
    for mode in ['strict','calls']:
        with r.node('counter-'+mode) as n,contextlib.closing(r.Client(n,hash_mode=mode)) as c:
            txs=[n.raw(h.ALICE,h.VAULT_A,'note(uint256)',1,nonce=i) for i in range(count)]
            approvals=[c.prepare(tx) for tx in txs]
            assert {a.get('hash_mode',0) for a in approvals}==({3} if mode=='calls' else {0})
            c.send(c.batch(approvals[:32]));c.send(c.batch(approvals[32:]))
            for tx in txs:n.submit(tx)
            included=txs if mode=='calls' else txs[:1]
            n.make_block(included,denied=None if mode=='calls' else txs[1])
            for tx in included:receipt(n,tx)
            assert storage(n,h.VAULT_A)==len(included)
            r.record('counter_'+mode,approved=count,confirmed=len(included),total=storage(n,h.VAULT_A))


def shared_token_and_nested_counters():
    with r.node('shared-token') as n,contextlib.closing(r.Client(n,hash_mode='calls')) as c:
        for address in [h.ALICE,h.ADMIN]:
            tx=n.raw(h.ADMIN,h.CALL_HASH_TOKEN,'mint(address,uint256)',address,1000)
            c.approve(tx);n.submit(tx);n.make_block([tx]);receipt(n,tx)
        txs=[]
        for sender,to in [(h.ALICE,h.ADMIN),(h.ADMIN,h.ALICE)]:
            start=nonce(n,sender)
            txs += [n.raw(sender,h.CALL_HASH_TOKEN,'transfer(address,uint256)',to,1,nonce=start+i) for i in range(32)]
        approvals=[c.prepare(tx) for tx in txs]
        for i in range(0,len(txs),32):c.send(c.batch(approvals[i:i+32]))
        for tx in txs:n.submit(tx)
        n.make_block(txs)
        for tx in txs:receipt(n,tx)
        for address in [h.ALICE,h.ADMIN]:
            data=h.command(['cast','calldata','balanceOf(address)',address]);value=n.rpc('eth_call',{'to':h.CALL_HASH_TOKEN,'data':data},'latest')
            assert int(value,16)==1000,value
        r.record('shared_token_balances',confirmed=len(txs))
        start=nonce(n,h.ALICE)
        txs=[n.raw(h.ALICE,h.ROUTER,'run(uint256)',1,nonce=start+i) for i in range(32)]
        c.send(c.batch([c.prepare(tx) for tx in txs]))
        for tx in txs:n.submit(tx)
        n.make_block(txs)
        assert storage(n,h.VAULT_A)==32 and storage(n,h.ROUTER)==32 and storage(n,h.RELAY,1)==32
        r.record('three_nested_shared_counters',confirmed=32)
        tx=n.raw(h.ALICE,h.CALL_HASH_CASES,'identity()');c.approve(tx);n.submit(tx);n.make_block([tx]);receipt(n,tx);r.record('precompile_call_identity')


def changed_calls():
    for case in ['argument','extra_call','unexpected_create','executed_code','native_value']:
        with r.node('call-change-'+case) as n,contextlib.closing(r.Client(n,hash_mode='calls')) as c:
            if case=='executed_code':
                tx=n.raw(h.ALICE,h.DESTRUCTIBLE,'marker()')
                mutation=n.raw(h.ADMIN,h.DESTRUCTIBLE,'destroy(address)',h.ADMIN,fee=4_000_000_000)
            elif case=='native_value':
                # Stored amount becomes native CALL value, while root calldata stays identical.
                tx=n.raw(h.ALICE,h.CALL_HASH_CASES,'payNative()',value=10)
                mutation=n.raw(h.ADMIN,h.CALL_HASH_CASES,'setAmount(uint256)',1,fee=4_000_000_000)
            else:
                function={'argument':'pay()','extra_call':'branch()','unexpected_create':'maybeCreate()'}[case]
                tx=n.raw(h.ALICE,h.CALL_HASH_CASES,function)
                mutation=n.raw(h.ADMIN,h.CALL_HASH_CASES,'setAmount(uint256)' if case=='argument' else 'setExtra(bool)',1 if case=='argument' else 'true',fee=4_000_000_000)
            approval=c.approve(tx);assert approval.get('hash_mode')==3,approval
            c.approve(mutation);before=(nonce(n,h.ALICE),balance(n,h.ALICE),storage(n,h.CALL_HASH_CASES),storage(n,h.VAULT_A))
            n.submit(tx);n.submit(mutation);n.make_block([mutation],denied=tx)
            assert (nonce(n,h.ALICE),balance(n,h.ALICE),storage(n,h.CALL_HASH_CASES),storage(n,h.VAULT_A))==before
            assert n.rpc('eth_getTransactionReceipt',tx['hash']) is None
            r.record('reject_changed_'+case,decisions=n.decisions())
    r.divergence('calls_cross_org_redirect')
    r.divergence('calls_caught_foreign_redirect',catch=True)
    r.read_only()


def documented_limit_and_mode_tampering():
    with r.node('call-only-limit') as n,contextlib.closing(r.Client(n,hash_mode='calls')) as c:
        tx=n.raw(h.ALICE,h.CALL_HASH_CASES,'internalAccounting()')
        mutation=n.raw(h.ADMIN,h.CALL_HASH_CASES,'setAmount(uint256)',120,fee=4_000_000_000)
        c.approve(tx);c.approve(mutation);n.submit(tx);n.submit(mutation);n.make_block([mutation,tx])
        receipt(n,tx);assert storage(n,h.CALL_HASH_CASES)==120
        r.record('documented_limit_internal_accounting_can_change',preflight_increment=0,executed_increment=120)
    for mode in [0,42]:
        with r.node('tamper-mode-'+str(mode),wait_ms=100) as n,contextlib.closing(r.Client(n,hash_mode='calls')) as c:
            tx=n.raw(h.ALICE,h.CALL_HASH_CASES,'tick()');batch=c.batch([c.prepare(tx)])
            if mode==0:
                # Relabelled strict after signing: the signed domain no longer matches.
                c.send(dict(batch,approvals=[dict(batch['approvals'][0],hash_mode=0)]),expect='UNAUTHENTICATED')
            else:
                c.send_envelope(r.with_member_domain(batch['envelope'],0,b'OPS_APPROVAL_V9\0'),expect='INVALID_ARGUMENT')
            n.submit(tx)
            time.sleep(.2);n.make_block([])
            assert n.rpc('eth_getTransactionReceipt',tx['hash']) is None and storage(n,h.CALL_HASH_CASES)==0
            r.record('reject_tampered_mode_'+str(mode))


def ops_stack():
    from demo import Stack, story
    with contextlib.closing(Stack('calls-ops',ops_env={'OPS_APPROVAL_HASH_MODE':'calls'})) as stack:
        n=stack.node
        for address in [h.CALL_HASH_CASES,h.CALL_HASH_TOKEN]:
            stack.admin('POST',f'/orgs/{stack.org}/contracts',{'address':address,'name':'Call hash fixture'})
            stack.admin('POST',f'/orgs/{stack.org}/contracts/{address}/grants',{'group_id':stack.group})
        txs=[n.raw(h.ALICE,h.CALL_HASH_CASES,'tick()',nonce=i) for i in range(64)]
        # All real OPS preflights complete before any transaction is executed.
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            replies=list(pool.map(stack.submit,txs))
        for tx,reply in zip(txs,replies):assert reply.get('result')==tx['hash'],reply
        n.make_block(txs)
        for tx in txs:receipt(n,tx)
        assert storage(n,h.CALL_HASH_CASES)==64
        r.record('real_OPS_parallel_counter',approved=64,confirmed=64)
        story(stack)
        r.record('real_OPS_DB_cross_org_and_execution_redirect_rejected')

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('mode',choices=['node','ops','all'],default='all',nargs='?');args=parser.parse_args()
    os.environ['OPS_APPROVAL_HASH_MODE']='calls'
    h.prepare()
    if args.mode in ['node','all']:
        counter_comparison();shared_token_and_nested_counters();changed_calls();documented_limit_and_mode_tampering();r.ordinary()
    if args.mode in ['ops','all']:ops_stack()
