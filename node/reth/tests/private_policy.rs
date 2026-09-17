use alloy_evm::{
    EthEvmFactory, Evm, EvmEnv, EvmFactory,
    revm::{
        bytecode::Bytecode,
        context::{CfgEnv, TxEnv},
        database::InMemoryDB,
        primitives::hardfork::SpecId,
        state::AccountInfo,
    },
};
use alloy_primitives::{Address, B256, Bytes, U256, address, hex, keccak256};
use alloy_sol_types::{SolCall, sol};
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
const APP: Address = address!("0000000000000000000000000000000000002000");
const POLICY: Address = address!("0000000000000000000000000000000000000900");

sol! {
    function check(address subject, address caller, address codeAddress, address storageAddress,
                   bytes callData, uint256 value, uint256 depth) external view returns (uint256);
}

#[derive(Debug)]
struct FixturePolicy(Bytes);
impl FramePolicy for FixturePolicy {
    fn authorize_policy_read(
        &self,
        _: &ExecutionIdentity,
        _: &ObservedCall,
        account: Address,
        _: B256,
        _: bool,
        _: &[ops_reth_policy::context::CreatedContract],
    ) -> Result<(), String> {
        if account == address!("0000000000000000000000000000000000003000") {
            Ok(())
        } else {
            Err("fixture read denied".into())
        }
    }
    fn prepare(
        &self,
        identity: &ExecutionIdentity,
        call: &ObservedCall,
    ) -> Result<PolicyInvocation, String> {
        Ok(PolicyInvocation {
            revision: B256::repeat_byte(1),
            bytecode: self.0.clone(),
            calldata: checkCall {
                subject: identity.signer,
                caller: call.caller,
                codeAddress: call.code_address,
                storageAddress: call.storage_address,
                callData: call.calldata.clone(),
                value: call.value,
                depth: U256::from(call.depth),
            }
            .abi_encode()
            .into(),
        })
    }
}
#[derive(Debug)]
struct FixtureIdentity;
impl IdentityResolver for FixtureIdentity {
    fn resolve(&self, binding: &ExecutionBinding, _: &TxEnv) -> Result<ExecutionIdentity, String> {
        Ok(ExecutionIdentity {
            principal_id: "fixture".into(),
            org_id: "org-a".into(),
            context_id: "fixture-context".into(),
            signer: SIGNER,
            binding: binding.clone(),
            min_snapshot_version: 1,
        })
    }
}
fn factory(code: Bytes) -> PolicyFactory {
    PolicyFactory::new(
        Arc::new(PinnedPolicySnapshot::new(
            1,
            B256::repeat_byte(1),
            Arc::new(FixturePolicy(code)),
        )),
        Arc::new(FixtureIdentity),
    )
}
fn protected_tx() -> PolicyTx {
    PolicyTx::bound(
        transaction(),
        ExecutionBinding::Transaction(B256::repeat_byte(1)),
    )
}

fn database(app: &[u8], public_policy: Option<&[u8]>) -> InMemoryDB {
    let mut db = InMemoryDB::default();
    db.insert_account_info(
        SIGNER,
        AccountInfo {
            balance: U256::from(1_000_000_000),
            ..Default::default()
        },
    );
    for (address, code) in [(APP, Some(app)), (POLICY, public_policy)] {
        if let Some(code) = code {
            let code = Bytes::copy_from_slice(code);
            db.insert_account_info(
                address,
                AccountInfo {
                    code_hash: keccak256(&code),
                    code: Some(Bytecode::new_raw(code)),
                    ..Default::default()
                },
            );
        }
    }
    db
}

fn environment() -> EvmEnv {
    EvmEnv {
        cfg_env: CfgEnv::new_with_spec(SpecId::SHANGHAI),
        ..Default::default()
    }
}

fn transaction() -> TxEnv {
    TxEnv::builder()
        .caller(SIGNER)
        .to(APP)
        .gas_limit(1_000_000)
        .gas_price(0)
        .build()
        .unwrap()
}

#[test]
fn private_policy_runs_without_a_policy_account() {
    let policy = Bytes::from_static(&hex!("600060005260206000f3"));
    let factory = factory(policy);
    let mut evm = factory.create_evm(database(&[0x00], None), environment());
    let result = evm
        .transact_raw(protected_tx())
        .expect("private allow policy must execute");
    assert!(result.result.is_success());
    assert!(
        !result.state.contains_key(&POLICY),
        "policy account must never enter the state result"
    );
}

#[test]
fn public_code_cannot_replace_the_private_policy() {
    let deny = Bytes::from_static(&hex!("600760005260206000f3"));
    let allow = hex!("600060005260206000f3");
    let mut evm = factory(deny).create_evm(database(&[0x00], Some(&allow)), environment());
    assert!(
        evm.transact_raw(protected_tx()).is_err(),
        "public allow code must not override private denial"
    );
}

#[test]
fn policy_does_not_change_application_gas_or_state() {
    // Policy reads an otherwise cold balance; the application reads the same address.
    let policy = Bytes::from_static(&hex!("6130003150600060005260206000f3"));
    let app = hex!("6130003160005260206000f3");
    let mut guarded = factory(policy).create_evm(database(&app, None), environment());
    let mut ordinary = EthEvmFactory::default().create_evm(database(&app, None), environment());
    let expected = ordinary.transact_raw(transaction()).unwrap();
    let actual = guarded.transact_raw(protected_tx()).unwrap();
    assert_eq!(actual.result, expected.result);
    assert_eq!(actual.state, expected.state);
}

#[test]
fn application_cannot_observe_private_code() {
    let policy = Bytes::from_static(&hex!("600060005260206000f3"));
    let app = hex!("6109003b60005260206000f3"); // EXTCODESIZE(private address)
    let mut evm = factory(policy).create_evm(database(&app, None), environment());
    let result = evm.transact_raw(protected_tx()).unwrap();
    assert_eq!(result.result.output().unwrap().as_ref(), &[0_u8; 32]);
}

#[test]
fn caught_inner_denial_vetoes_the_entire_transaction() {
    // Old fixture ABI's third argument is code address. Deny only the child at 0x3000.
    let policy = Bytes::from_static(&hex!("6044356130001460005260206000f3"));
    // Write slot 0, CALL child and catch failure, write slot 1, return success.
    let app = hex!("6001600055600060006000600060006130005af150600260015500");
    let mut ordinary = EthEvmFactory::default().create_evm(database(&app, None), environment());
    assert!(
        ordinary
            .transact_raw(transaction())
            .unwrap()
            .result
            .is_success()
    );
    let mut evm = factory(policy).create_evm(database(&app, None), environment());
    let error = evm.transact_raw(protected_tx()).unwrap_err();
    assert!(error.to_string().contains("rule 1"), "{error}");
}

#[test]
fn invalid_private_policy_fails_closed() {
    for code in [
        "",
        "60006000fd",
        "60006000f3",
        "5b600056",
        "6001600055600060005260206000f3",
    ] {
        let mut evm = factory(hex::decode(code).unwrap().into())
            .create_evm(database(&[0x00], None), environment());
        assert!(
            evm.transact_raw(protected_tx()).is_err(),
            "invalid policy {code} must deny"
        );
    }
}
