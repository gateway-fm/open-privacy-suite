use alloy_evm::{
    Evm, EvmEnv, EvmFactory,
    revm::{
        context::{CfgEnv, TxEnv},
        database::InMemoryDB,
        primitives::hardfork::SpecId,
        state::AccountInfo,
    },
};
use alloy_primitives::{Address, B256, Bytes, U256, address, hex};
use ops_reth_policy::{
    context::{
        ExecutionBinding, ExecutionIdentity, FramePolicy, IdentityResolver, ObservedCall,
        PinnedPolicySnapshot, PolicyInvocation,
    },
    policy::PolicyFactory,
    transaction::PolicyTx,
};
use std::sync::Arc;

const SIGNER: Address = address!("0000000000000000000000000000000000001000");
const TARGET: Address = address!("0000000000000000000000000000000000002000");
const ALICE: B256 = B256::repeat_byte(1);
const BOB: B256 = B256::repeat_byte(2);

#[derive(Debug)]
struct Identities;
impl IdentityResolver for Identities {
    fn resolve(
        &self,
        binding: &ExecutionBinding,
        _transaction: &TxEnv,
    ) -> Result<ExecutionIdentity, String> {
        let principal = match binding {
            ExecutionBinding::Transaction(hash) if *hash == ALICE => "alice",
            ExecutionBinding::Transaction(hash) if *hash == BOB => "bob",
            _ => return Err("missing authenticated context".into()),
        };
        Ok(ExecutionIdentity {
            principal_id: principal.into(),
            org_id: "org-a".into(),
            context_id: principal.into(),
            signer: SIGNER,
            binding: binding.clone(),
            min_snapshot_version: 1,
        })
    }
}

#[derive(Debug)]
struct Rules {
    allow_alice: bool,
}
impl FramePolicy for Rules {
    fn prepare(
        &self,
        identity: &ExecutionIdentity,
        _call: &ObservedCall,
    ) -> Result<PolicyInvocation, String> {
        let allowed = identity.principal_id == "alice" && self.allow_alice;
        Ok(PolicyInvocation {
            revision: B256::repeat_byte(3),
            bytecode: Bytes::copy_from_slice(if allowed {
                &hex!("600060005260206000f3")
            } else {
                &hex!("600960005260206000f3")
            }),
            calldata: Bytes::new(),
        })
    }
}

fn factory(version: u64, allow_alice: bool) -> PolicyFactory {
    PolicyFactory::new(
        Arc::new(PinnedPolicySnapshot::new(
            version,
            B256::repeat_byte(version as u8),
            Arc::new(Rules { allow_alice }),
        )),
        Arc::new(Identities),
    )
}
fn env() -> EvmEnv {
    EvmEnv {
        cfg_env: CfgEnv::new_with_spec(SpecId::SHANGHAI),
        ..Default::default()
    }
}
fn db() -> InMemoryDB {
    let mut db = InMemoryDB::default();
    db.insert_account_info(
        SIGNER,
        AccountInfo {
            balance: U256::from(1_000_000_000),
            ..Default::default()
        },
    );
    db
}
fn tx(hash: B256) -> PolicyTx {
    PolicyTx::bound(
        TxEnv::builder()
            .caller(SIGNER)
            .to(TARGET)
            .gas_limit(100_000)
            .gas_price(0)
            .build()
            .unwrap(),
        ExecutionBinding::Transaction(hash),
    )
}

#[test]
fn shared_signer_uses_only_authenticated_principal_permissions() {
    let mut evm = factory(1, true).create_evm(db(), env());
    assert!(evm.transact_raw(tx(ALICE)).unwrap().result.is_success());
    assert!(
        evm.transact_raw(tx(BOB)).is_err(),
        "Bob must not inherit Alice's permissions through shared signer"
    );
}

#[test]
fn missing_binding_fails_closed() {
    let mut evm = factory(1, true).create_evm(db(), env());
    assert!(evm.transact_raw(tx(B256::ZERO)).is_err());
    assert!(
        evm.transact_raw(PolicyTx::unbound(TxEnv::default()))
            .is_err()
    );
}

#[test]
fn snapshot_is_immutable_for_the_execution_lifetime() {
    let mut old = factory(1, true).create_evm(db(), env());
    let mut next = factory(2, false).create_evm(db(), env());
    assert!(old.transact_raw(tx(ALICE)).unwrap().result.is_success());
    assert!(
        next.transact_raw(tx(ALICE)).is_err(),
        "new snapshot revokes Alice"
    );
    assert!(
        old.transact_raw(tx(ALICE)).unwrap().result.is_success(),
        "existing execution retains its snapshot"
    );
}

#[test]
fn identity_signer_mismatch_and_snapshot_lag_deny() {
    let mut evm = factory(1, true).create_evm(db(), env());
    let mismatched = PolicyTx::bound(
        TxEnv::builder()
            .caller(TARGET)
            .to(TARGET)
            .gas_limit(100_000)
            .gas_price(0)
            .build()
            .unwrap(),
        ExecutionBinding::Transaction(ALICE),
    );
    assert!(evm.transact_raw(mismatched).is_err());
    let mut lagged = factory(0, true).create_evm(db(), env());
    assert!(lagged.transact_raw(tx(ALICE)).is_err());
}

#[test]
fn authorization_transactions_are_explicitly_outside_supported_model() {
    let mut environment = env();
    environment.cfg_env = CfgEnv::new_with_spec(SpecId::PRAGUE);
    let mut evm = factory(1, true).create_evm(db(), environment);
    let mut transaction = TxEnv::builder()
        .caller(SIGNER)
        .to(TARGET)
        .gas_limit(100_000)
        .gas_price(0)
        .build()
        .unwrap();
    transaction.tx_type = 4;
    let result = evm.transact_raw(PolicyTx::bound(
        transaction,
        ExecutionBinding::Transaction(ALICE),
    ));
    assert!(result.unwrap_err().to_string().contains("EIP-7702"));
}
