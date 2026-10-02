#!/usr/bin/env python3
"""Value/lifecycle regressions against real EVM execution; OPS policy cases run separately."""
import contextlib
import json
import harness as h
from run import node, Client, record

RECIPIENT = "0x" + format(0x8100, "040x")

def balance(n, address): return int(n.rpc("eth_getBalance", address, "latest"), 16)
def nonce(n, address): return int(n.rpc("eth_getTransactionCount", address, "latest"), 16)
def storage(n, address, slot=0): return int(n.rpc("eth_getStorageAt", address, hex(slot), "latest"),16)
def address_at(n, address, slot=0): return "0x" + format(storage(n,address,slot),"040x")
def receipt(n, tx, status=1):
    r=n.rpc("eth_getTransactionReceipt",tx["hash"])
    assert r and int(r["status"],16)==status,r
    return r

def initcode(number=7, target="0x"+"00"*20):
    compiled=json.loads((h.EVIDENCE/"contracts.json").read_text())["contracts"]
    code=next(v["bin"] for k,v in compiled.items() if k.endswith(":LifeChild"))
    args=h.command(["cast","abi-encode","constructor(uint256,address)",str(number),target])
    return "0x"+code+args[2:]

def ordinary(fork="shanghai"):
    with node("lifecycle-"+fork,fork=fork) as n,contextlib.closing(Client(n)) as c:
        for sender, target, dynamic in [(h.ALICE,RECIPIENT,False),(h.ALICE,h.ADMIN,True),(h.ADMIN,h.ALICE,False),(h.ALICE,h.ALICE,True)]:
            before={a:balance(n,a) for a in {sender,target,h.ADMIN}}
            tx=n.raw(sender,target,"0x",value=13,legacy=not dynamic)
            c.approve(tx);n.submit(tx);n.make_block([tx]);r=receipt(n,tx)
            gas,price=int(r["gasUsed"],16),int(r["effectiveGasPrice"],16)
            changes={a:0 for a in before}
            changes[sender]-=13+gas*price;changes[target]+=13
            changes[h.ADMIN]+=gas*(price-int(n.head["baseFeePerGas"],16))
            for a in before: assert balance(n,a)==before[a]+changes[a],(a,before,changes)
        record(fork+"_native_transfers_self_and_fee_recipient")
        tx=n.raw(h.ALICE,h.VALUE_ROUTER,"send(uint256)",13,value=21)
        c.approve(tx);n.submit(tx);n.make_block([tx]);receipt(n,tx)
        assert balance(n,h.VALUE_ROUTER)==8 and balance(n,h.VALUE_RECEIVER)==13
        assert storage(n,h.VALUE_RECEIVER)==13
        record(fork+"_payable_nested_transfer")
        tx=n.raw(h.ALICE,h.VALUE_ROUTER,"caught(address)",h.VALUE_RECEIVER,value=11)
        c.approve(tx);n.submit(tx);n.make_block([tx]);receipt(n,tx)
        assert balance(n,h.VALUE_ROUTER)==19 and balance(n,h.VALUE_RECEIVER)==13
        record(fork+"_caught_value_transfer_reverted")
        tx=n.raw(h.ALICE,h.VALUE_RECEIVER,"fail()",value=17)
        before=balance(n,h.VALUE_RECEIVER)
        c.approve(tx);n.submit(tx);n.make_block([tx]);receipt(n,tx,status=0)
        assert balance(n,h.VALUE_RECEIVER)==before
        record(fork+"_root_revert_only_pays_fees")
        # Preflight both before either is included. Reth debug_traceCall normally drops the requested nonce.
        start=nonce(n,h.ALICE)
        first=n.raw(h.ALICE,RECIPIENT,"0x",value=3,nonce=start)
        deploy=n.raw(h.ALICE,None,initcode(),value=23,gas=1000000,nonce=start+1)
        c.approve(first);c.approve(deploy);n.submit(deploy);n.submit(first);n.make_block([first,deploy])
        created=receipt(n,deploy)["contractAddress"]
        assert n.rpc("eth_getCode",created,"latest")!="0x" and balance(n,created)==23 and storage(n,created)==7
        record(fork+"_payable_deployment_with_queued_nonce",address=created)
        tx=n.raw(h.ALICE,h.LIFE_FACTORY,"create(uint256,address)",9,h.VAULT_A,value=31,gas=1500000)
        c.approve(tx);n.submit(tx);n.make_block([tx]);receipt(n,tx)
        created=address_at(n,h.LIFE_FACTORY)
        assert balance(n,created)==31 and storage(n,created)==10 and storage(n,h.VAULT_A)==9
        record(fork+"_nested_create_constructor_call_and_new_contract_call")
        empty=n.raw(h.ALICE,None,"0x60006000f3",value=5,gas=1000000)
        c.approve(empty);n.submit(empty);n.make_block([empty]);empty_address=receipt(n,empty)["contractAddress"]
        assert n.rpc("eth_getCode",empty_address,"latest")=="0x" and nonce(n,empty_address)==1 and balance(n,empty_address)==5
        record(fork+"_empty_runtime_code_deployment")
        salt="0x"+format(42,"064x")
        init_hash=h.command(["cast","keccak",initcode(17)])
        expected="0x"+h.command(["cast","keccak","0xff"+h.LIFE_FACTORY[2:]+salt[2:]+init_hash[2:]])[-40:]
        fund=n.raw(h.ADMIN,expected,"0x",value=5)
        c.approve(fund);n.submit(fund);n.make_block([fund])
        for status in (1,0):
            tx=n.raw(h.ALICE,h.LIFE_FACTORY,"create2(bytes32,uint256)",salt,17,value=19,gas=1500000)
            c.approve(tx);n.submit(tx);n.make_block([tx]);receipt(n,tx,status=status)
        created=address_at(n,h.LIFE_FACTORY)
        assert created.lower()==expected.lower() and balance(n,created)==24 and storage(n,created)==17
        record(fork+"_prefunded_create2_success_and_collision")
        tx=n.raw(h.ALICE,created,"destroy(address)",RECIPIENT)
        c.approve(tx);n.submit(tx);n.make_block([tx]);receipt(n,tx)
        tx=n.raw(h.ALICE,h.LIFE_FACTORY,"create2(bytes32,uint256)",salt,17,value=19,gas=1500000)
        c.approve(tx);n.submit(tx);n.make_block([tx]);receipt(n,tx,status=1 if fork=="shanghai" else 0)
        assert balance(n,created)==(19 if fork=="shanghai" else 0)
        record(fork+"_create2_redeployment_after_destruction")
        tx=n.raw(h.ALICE,h.DESTRUCTIBLE,"destroy(address)",RECIPIENT)
        before=balance(n,RECIPIENT)
        c.approve(tx);n.submit(tx);n.make_block([tx]);receipt(n,tx)
        assert balance(n,RECIPIENT)==before+1000 and balance(n,h.DESTRUCTIBLE)==0
        assert (n.rpc("eth_getCode",h.DESTRUCTIBLE,"latest")=="0x") == (fork=="shanghai")
        assert storage(n,h.DESTRUCTIBLE)==(0 if fork=="shanghai" else 7)
        record(fork+"_existing_selfdestruct_account_effects")
        for target in (RECIPIENT,"0x"+"00"*20):
            before=balance(n,RECIPIENT)
            factory_nonce=nonce(n,h.LIFE_FACTORY)
            temp=h.command(["cast","compute-address",h.LIFE_FACTORY,"--nonce",str(factory_nonce)]).split()[-1]
            tx=n.raw(h.ALICE,h.LIFE_FACTORY,"createAndDestroy(address)",target,value=29,gas=1500000)
            c.approve(tx);n.submit(tx);n.make_block([tx]);receipt(n,tx)
            assert n.rpc("eth_getCode",temp,"latest")=="0x" and balance(n,temp)==0
            assert balance(n,RECIPIENT)==before+(29 if target==RECIPIENT else 0)
        record(fork+"_create_and_destroy_including_self_beneficiary")
        before=(balance(n,RECIPIENT),nonce(n,h.LIFE_FACTORY))
        tx=n.raw(h.ALICE,h.LIFE_FACTORY,"caught(address)",RECIPIENT,value=37,gas=1500000)
        c.approve(tx);n.submit(tx);n.make_block([tx]);receipt(n,tx)
        assert (balance(n,RECIPIENT),nonce(n,h.LIFE_FACTORY))==before
        assert balance(n,h.LIFE_FACTORY)==37
        record(fork+"_caught_revert_undoes_creation_and_destruction")

def divergence(fork="shanghai"):
    for case in ("value_recipient","destruction_balance","constructor_state"):
        with node("lifecycle-divergence-"+fork+"-"+case,fork=fork) as n,contextlib.closing(Client(n)) as c:
            if case=="value_recipient":
                tx=n.raw(h.ALICE,h.VALUE_ROUTER,"send(uint256)",17,value=17)
                mutation=n.raw(h.ADMIN,h.VALUE_ROUTER,"setTarget(address)",RECIPIENT,fee=4_000_000_000)
            elif case=="destruction_balance":
                tx=n.raw(h.ALICE,h.DESTRUCTIBLE,"destroy(address)",RECIPIENT)
                mutation=n.raw(h.ADMIN,h.DESTRUCTIBLE,"0x",value=1,fee=4_000_000_000)
            else:
                tx=n.raw(h.ALICE,None,initcode(7,h.VAULT_A),value=11,gas=1000000)
                mutation=n.raw(h.ADMIN,h.VAULT_A,"note(uint256)",1,fee=4_000_000_000)
            c.approve(tx);c.approve(mutation)
            before=(balance(n,h.ALICE),nonce(n,h.ALICE),balance(n,RECIPIENT))
            n.submit(tx);n.submit(mutation);n.make_block([mutation],denied=tx)
            assert (balance(n,h.ALICE),nonce(n,h.ALICE),balance(n,RECIPIENT))==before
            assert n.rpc("eth_getTransactionReceipt",tx["hash"]) is None
            assert n.rpc("eth_getCode",h.DESTRUCTIBLE,"latest")!="0x"
            record(fork+"_reject_changed_"+case)

def destruction_edges(fork):
    for target in (h.DESTRUCTIBLE,h.ADMIN):
        with node("destruction-edge-"+fork+"-"+target[-4:],fork=fork) as n,contextlib.closing(Client(n)) as c:
            before=balance(n,h.ADMIN)
            tx=n.raw(h.ALICE,h.DESTRUCTIBLE,"destroy(address)",target)
            c.approve(tx);n.submit(tx);n.make_block([tx]);r=receipt(n,tx)
            remaining=1000 if target==h.DESTRUCTIBLE and fork=="cancun" else 0
            assert balance(n,h.DESTRUCTIBLE)==remaining
            reward=int(r["gasUsed"],16)*(int(r["effectiveGasPrice"],16)-int(n.head["baseFeePerGas"],16))
            assert balance(n,h.ADMIN)==before+reward+(1000 if target==h.ADMIN else 0)
            assert (n.rpc("eth_getCode",h.DESTRUCTIBLE,"latest")=="0x")== (fork=="shanghai")
            record(fork+"_selfdestruct_"+("self_beneficiary" if target==h.DESTRUCTIBLE else "fee_beneficiary"))

def contract_fee_recipient():
    with node("contract-fee-recipient") as n,contextlib.closing(Client(n)) as c:
        tx=n.raw(h.ALICE,h.BENCH_VAULT,"put(uint256,uint256)",31,7)
        c.approve(tx);n.submit(tx);n.make_block([tx],fee_recipient=h.DESTRUCTIBLE);r=receipt(n,tx)
        reward=int(r["gasUsed"],16)*(int(r["effectiveGasPrice"],16)-int(n.head["baseFeePerGas"],16))
        assert balance(n,h.DESTRUCTIBLE)==1000+reward
        record("contract_fee_recipient_does_not_change_application_fingerprint")

def tests():
    contract_fee_recipient()
    for fork in ("shanghai","cancun"):
        ordinary(fork);divergence(fork);destruction_edges(fork)

if __name__=="__main__":
    h.prepare();tests()
