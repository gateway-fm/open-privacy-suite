#!/usr/bin/env python3
"""Real HTTP OPS + its normal PostgreSQL/Redis + custom Reth lifecycle checks."""
import contextlib
import time
import harness as h
from demo import Stack
from lifecycle_tests import initcode, receipt, balance, storage, address_at, nonce, RECIPIENT
from run import record

def tests():
    with contextlib.closing(Stack("lifecycle-ops",fork="cancun")) as s:
        n=s.node
        for addr in [h.VALUE_ROUTER,h.VALUE_RECEIVER,h.LIFE_FACTORY,h.DESTRUCTIBLE]:
            s.admin("POST",f"/orgs/{s.org}/contracts",{"address":addr,"name":"Lifecycle "+addr[-4:]})
            s.admin("POST",f"/orgs/{s.org}/contracts/{addr}/grants",{"group_id":s.group})
        def allow(tx):
            r=s.submit(tx);assert r.get("result")==tx["hash"],r
            n.make_block([tx]);return receipt(n,tx)
        def deny(tx):
            r=s.submit(tx);assert "error" in r,r
            assert n.rpc("eth_getTransactionByHash",tx["hash"]) is None
        def registered(address):
            for _ in range(120):
                rows=s.admin("GET",f"/orgs/{s.org}/contracts")
                rows=rows if isinstance(rows,list) else rows.get("data",rows.get("contracts",[]))
                if any(x["address"].lower()==address.lower() for x in rows): return
                time.sleep(.1)
            raise AssertionError("creation was not registered to its OPS organisation: "+address)
        # Existing root-transfer policy permits an unregistered EOA, unlike contract calls.
        tx=n.raw(h.ALICE,RECIPIENT,"0x",value=13);allow(tx)
        assert balance(n,RECIPIENT)==13
        record("OPS_native_EOA_transfer_uses_existing_policy")
        tx=n.raw(h.ALICE,h.VALUE_ROUTER,"send(uint256)",17,value=17);allow(tx)
        assert balance(n,h.VALUE_RECEIVER)==17
        record("OPS_payable_nested_call")
        allow(n.raw(h.ADMIN,h.VALUE_ROUTER,"setTarget(address)",RECIPIENT))
        before=balance(n,RECIPIENT)
        allow(n.raw(h.ALICE,h.VALUE_ROUTER,"send(uint256)",11,value=11))
        assert balance(n,RECIPIENT)==before+11
        foreign_eoa="0x"+format(0x8200,"040x")
        s.admin("POST",f"/orgs/{s.foreign}/contracts",{"address":foreign_eoa,"name":"Foreign registered recipient"})
        allow(n.raw(h.ADMIN,h.VALUE_ROUTER,"setTarget(address)",foreign_eoa))
        deny(n.raw(h.ALICE,h.VALUE_ROUTER,"send(uint256)",11,value=11))
        deny(n.raw(h.ALICE,h.DESTRUCTIBLE,"destroy(address)",foreign_eoa))
        allow(n.raw(h.ADMIN,h.VALUE_ROUTER,"setTarget(address)",h.VALUE_RECEIVER))
        record("OPS_nested_wallet_transfers_preserve_registered_org_boundaries")
        deny(n.raw(h.ALICE,None,initcode(),value=19,gas=1000000))
        deny(n.raw(h.ALICE,h.LIFE_FACTORY,"create(uint256,address)",7,h.VAULT_A,value=23,gas=1500000))
        record("OPS_root_and_nested_creation_require_deploy_claim")
        s.admin("PUT",f"/orgs/{s.org}/groups/{s.group}/access",{"claims":["deploy"],"allowed_methods":["*"]})
        deny(n.raw(h.ALICE,None,initcode(7,h.VAULT_B),gas=1000000))
        deny(n.raw(h.ALICE,h.LIFE_FACTORY,"create(uint256,address)",7,h.VAULT_B,gas=1500000))
        deny(n.raw(h.ALICE,h.DESTRUCTIBLE,"destroy(address)",h.VAULT_B))
        record("OPS_constructor_nested_creation_and_selfdestruct_foreign_targets_denied")
        deployed=allow(n.raw(h.ALICE,None,initcode(7,h.VAULT_A),value=19,gas=1000000))["contractAddress"]
        registered(deployed)
        assert balance(n,deployed)==19 and storage(n,deployed)==7
        record("OPS_payable_root_deployment_registered",address=deployed)
        allow(n.raw(h.ALICE,h.LIFE_FACTORY,"create(uint256,address)",9,h.VAULT_A,value=23,gas=1500000))
        child=address_at(n,h.LIFE_FACTORY);registered(child)
        assert storage(n,child)==10
        record("OPS_nested_deployment_new_child_call_and_registration",address=child)
        salt="0x"+format(49,"064x")
        allow(n.raw(h.ALICE,h.LIFE_FACTORY,"create2(bytes32,uint256)",salt,17,value=29,gas=1500000))
        child=address_at(n,h.LIFE_FACTORY);registered(child)
        record("OPS_CREATE2_registered",address=child)
        # SELFDESTRUCT does not invoke the beneficiary's fallback. A registered
        # Bank A contract is a valid target under the existing org policy.
        before=balance(n,h.VALUE_RECEIVER)
        allow(n.raw(h.ALICE,h.DESTRUCTIBLE,"destroy(address)",h.VALUE_RECEIVER))
        assert balance(n,h.VALUE_RECEIVER)==before+1000
        assert n.rpc("eth_getCode",h.DESTRUCTIBLE,"latest")!="0x"
        record("OPS_SELFDESTRUCT_Cancun_preserves_code")
        allow(n.raw(h.ALICE,h.DESTRUCTIBLE,"0x",value=41))
        before=balance(n,h.ALICE)
        r=allow(n.raw(h.ALICE,h.DESTRUCTIBLE,"destroy(address)",h.ALICE))
        assert balance(n,h.ALICE)==before+41-int(r["gasUsed"],16)*int(r["effectiveGasPrice"],16)
        record("OPS_SELFDESTRUCT_pays_normal_wallet")
        factory_nonce=nonce(n,h.LIFE_FACTORY)
        temp=h.command(["cast","compute-address",h.LIFE_FACTORY,"--nonce",str(factory_nonce)]).split()[-1]
        allow(n.raw(h.ALICE,h.LIFE_FACTORY,"createAndDestroy(address)",h.VALUE_RECEIVER,value=31,gas=1500000))
        assert n.rpc("eth_getCode",temp,"latest")=="0x"
        rows=s.admin("GET",f"/orgs/{s.org}/contracts");rows=rows if isinstance(rows,list) else rows.get("data",rows.get("contracts",[]))
        assert all(x["address"].lower()!=temp.lower() for x in rows)
        record("OPS_temporary_creation_not_registered")
        stale=n.raw(h.ALICE,h.VALUE_ROUTER,"send(uint256)",17,value=17)
        r=s.submit(stale);assert r.get("result")==stale["hash"],r
        mutation=n.raw(h.ADMIN,h.VALUE_ROUTER,"setTarget(address)",h.VAULT_B,fee=4_000_000_000)
        r=s.submit(mutation);assert r.get("result")==mutation["hash"],r
        before=(balance(n,h.ALICE),nonce(n,h.ALICE),balance(n,h.VALUE_ROUTER),balance(n,h.VALUE_RECEIVER))
        n.make_block([mutation],denied=stale)
        assert (balance(n,h.ALICE),nonce(n,h.ALICE),balance(n,h.VALUE_ROUTER),balance(n,h.VALUE_RECEIVER))==before
        assert n.rpc("eth_getTransactionReceipt",stale["hash"]) is None
        record("OPS_approved_ETH_call_redirected_cross_org_is_excluded_by_Reth")

if __name__=="__main__":
    h.prepare();tests()
