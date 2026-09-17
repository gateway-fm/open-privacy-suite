use alloy_primitives::{Address, B256, Bytes, U256, address, keccak256};
use alloy_sol_types::{SolCall, sol};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer, SigningKey};
use ops_reth_policy::{
    context::{
        CodeKind, ExecutionBinding, ExecutionIdentity, FrameKind, FramePolicy, ObservedCall,
    },
    facts::FactsPolicy,
    stream::FactStream,
    wire::{Network, Verifier},
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

sol! {
    struct Facts { address signer; address[] linkedAddresses; bytes32[] groups; bytes32 policyOrg; bytes32 callerOrg; bytes32 codeOrg; bytes32 storageOrg; uint8 claims; bool codeShared; bool storageShared; uint8 codeKind; bytes32 upgradeTargetOrg; uint8[] groupClaims; bool storageDeployer; bool storagePending; }
    struct Call { uint8 kind; address caller; address codeAddress; address storageAddress; bytes data; uint256 value; uint256 depth; }
    function check(Facts facts, Call frame) external returns (uint256);
}
const SIGNER: Address = address!("0000000000000000000000000000000000001000");
const TARGET: Address = address!("0000000000000000000000000000000000002000");
fn identity() -> ExecutionIdentity {
    ExecutionIdentity {
        principal_id: "user-a".into(),
        org_id: "org-a".into(),
        context_id: "ctx".into(),
        signer: SIGNER,
        binding: ExecutionBinding::Transaction(B256::repeat_byte(1)),
        min_snapshot_version: 7,
    }
}
fn frame() -> ObservedCall {
    ObservedCall {
        kind: FrameKind::Call,
        caller: SIGNER,
        code_address: TARGET,
        storage_address: TARGET,
        calldata: Bytes::from_static(&[1, 2, 3, 4]),
        value: U256::ZERO,
        depth: 0,
        code_hash: keccak256([0]),
        storage_code_hash: keccak256([0]),
        code_kind: CodeKind::Contract,
    }
}
fn policy(change: impl FnOnce(&mut Value)) -> FactsPolicy {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../internal/nodepolicy/testdata/envelopes-v1.json"
    ))
    .unwrap();
    let mut snapshot: Value = serde_json::from_slice(
        &STANDARD
            .decode(fixture["snapshot"]["payload"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    snapshot["contracts"] = json!([{"address":format!("{TARGET:#x}"),"org_id":"org-a","shared_infrastructure":false,"code_hash":"","deployer_principal_id":"","pending":false}]);
    snapshot["groups"] = json!([
        {"id":"g-a","org_id":"org-a","claims":4,"org_admin":false,"contract_claims":[{"address":format!("{TARGET:#x}"),"claims":4}]},
        {"id":"g-b","org_id":"org-a","claims":2,"org_admin":false,"contract_claims":[]}]);
    snapshot["principals"][0]["memberships"] =
        json!([{"group_id":"g-b","expires_at":0},{"group_id":"g-a","expires_at":0}]);
    snapshot["principals"][0]["banned"] = json!(false);
    snapshot["principals"][0]["linked_addresses"] = json!([format!("{SIGNER:#x}")]);
    snapshot["principals"][1]["memberships"] = json!([]);
    let compiler: Value = serde_json::from_str(include_str!(
        "../../../internal/policydsl/testdata/lifecycle-v1.json"
    ))
    .unwrap();
    snapshot["policies"] = compiler["snapshot"]["policies"].clone();
    snapshot["policies"][0]["org_id"] = json!("org-a");
    change(&mut snapshot);
    let payload = serde_json::to_vec(&snapshot).unwrap();
    let mut signed = b"OPS_NODE_POLICY_V1\0".to_vec();
    for part in [b"snapshot".as_slice(), b"ops-a", payload.as_slice()] {
        signed.extend_from_slice(&(part.len() as u32).to_be_bytes());
        signed.extend_from_slice(part);
    }
    let key = SigningKey::from_bytes(&[7; 32]);
    let wire=serde_json::to_vec(&json!({"version":1,"kind":"snapshot","key_id":"ops-a","payload":STANDARD.encode(payload),"signature":STANDARD.encode(key.sign(&signed).to_bytes())})).unwrap();
    let stream = FactStream::new(Verifier::new(
        Network {
            chain_id: 31337,
            deployment_id: "ops-test".into(),
        },
        BTreeMap::from([("ops-a".into(), key.verifying_key())]),
    ));
    stream.accept("snapshot", &wire, 1020).unwrap();
    FactsPolicy::new(stream.pin(1020, 7).unwrap(), 1020).unwrap()
}

#[test]
fn final_a5_abi_has_current_ownership_and_aligned_per_group_claims() {
    assert_eq!(checkCall::SELECTOR, [0x9f, 0x0a, 0x7e, 0x8f]);
    let invocation = policy(|_| {}).prepare(&identity(), &frame()).unwrap();
    let decoded = checkCall::abi_decode(&invocation.calldata).unwrap();
    assert_eq!(
        decoded.facts.groups,
        vec![keccak256("g-a"), keccak256("g-b")]
    );
    assert_eq!(decoded.facts.groupClaims, vec![4, 0]);
    assert_eq!(decoded.facts.policyOrg, keccak256("org-a"));
    assert_eq!(decoded.facts.codeOrg, keccak256("org-a"));
    assert_eq!(decoded.facts.storageOrg, keccak256("org-a"));
    assert_eq!(decoded.frame.data, frame().calldata);
}

#[test]
fn named_deployer_and_pending_facts_use_authoritative_creation_overlay() {
    use ops_reth_policy::context::CreatedContract;
    let adapter =
        policy(|snapshot| snapshot["contracts"][0]["deployer_principal_id"] = json!("user-a"));
    let facts = checkCall::abi_decode(&adapter.prepare(&identity(), &frame()).unwrap().calldata)
        .unwrap()
        .facts;
    assert!(facts.storageDeployer);
    assert!(!facts.storagePending);
    let mut other = identity();
    other.principal_id = "user-b".into();
    assert!(adapter.prepare(&other, &frame()).is_err());
    let adapter = policy(|snapshot| snapshot["contracts"][0]["pending"] = json!(true));
    let facts = checkCall::abi_decode(&adapter.prepare(&identity(), &frame()).unwrap().calldata)
        .unwrap()
        .facts;
    assert!(facts.storagePending);
    assert!(!facts.storageDeployer);
    assert_eq!(facts.groupClaims, vec![4, 2]);
    let created = [CreatedContract {
        address: TARGET,
        org_id: "org-a".into(),
        principal_id: "user-a".into(),
    }];
    let facts = checkCall::abi_decode(
        &adapter
            .prepare_with_creations(&identity(), &frame(), &created)
            .unwrap()
            .calldata,
    )
    .unwrap()
    .facts;
    assert!(facts.storageDeployer);
    assert!(!facts.storagePending);
    let foreign = policy(|snapshot| snapshot["contracts"][0]["org_id"] = json!("foreign"));
    assert!(
        foreign
            .prepare_with_creations(&identity(), &frame(), &created)
            .is_err()
    );
}

#[test]
fn current_ban_unlink_membership_expiry_and_scoped_sanction_deny() {
    for case in 0..4 {
        let adapter = policy(|snapshot| match case {
            0 => snapshot["principals"][0]["banned"] = json!(true),
            1 => snapshot["principals"][0]["linked_addresses"] = json!([]),
            2 => {
                snapshot["principals"][0]["memberships"] =
                    json!([{"group_id":"g-a","expires_at":1020}])
            }
            _ => {
                snapshot["sanctions"] = json!([{"org_id":"org-a","address":format!("{SIGNER:#x}")}])
            }
        });
        assert!(
            adapter.prepare(&identity(), &frame()).is_err(),
            "case {case}"
        );
    }
    let adapter = policy(|s| {
        s["sanctions"] = json!([{"org_id":"org-other","address":format!("{SIGNER:#x}")} ])
    });
    assert!(adapter.prepare(&identity(), &frame()).is_ok());
}

#[test]
fn shared_flags_require_matching_live_code_pins() {
    let adapter = policy(|s| {
        s["contracts"][0]["shared_infrastructure"] = json!(true);
        s["contracts"][0]["code_hash"] = json!(format!("{:#x}", keccak256([0])));
    });
    let invocation = adapter.prepare(&identity(), &frame()).unwrap();
    assert!(
        checkCall::abi_decode(&invocation.calldata)
            .unwrap()
            .facts
            .codeShared
    );
    let mut changed = frame();
    changed.code_hash = keccak256([1]);
    assert!(adapter.prepare(&identity(), &changed).is_err());
    let unpinned = policy(|s| s["contracts"][0]["shared_infrastructure"] = json!(true));
    assert!(
        checkCall::abi_decode(&unpinned.prepare(&identity(), &frame()).unwrap().calldata)
            .unwrap()
            .facts
            .codeShared
    );
}

#[test]
fn upgrade_target_ownership_comes_from_canonical_argument() {
    let adapter = policy(|_| {});
    let mut call = frame();
    let mut data = vec![0x36, 0x59, 0xcf, 0xe6];
    data.extend_from_slice(&[0; 12]);
    data.extend_from_slice(TARGET.as_slice());
    call.calldata = data.clone().into();
    assert_eq!(
        checkCall::abi_decode(&adapter.prepare(&identity(), &call).unwrap().calldata)
            .unwrap()
            .facts
            .upgradeTargetOrg,
        keccak256("org-a")
    );
    data[4] = 1;
    call.calldata = data.into();
    assert_eq!(
        checkCall::abi_decode(&adapter.prepare(&identity(), &call).unwrap().calldata)
            .unwrap()
            .facts
            .upgradeTargetOrg,
        B256::ZERO
    );
}

#[test]
fn creation_has_pending_owner_and_group_deployment_claims() {
    let adapter = policy(|_| {});
    let mut call = frame();
    call.kind = FrameKind::Create;
    call.code_address = Address::repeat_byte(9);
    call.storage_address = call.code_address;
    call.code_kind = CodeKind::NoCode;
    let decoded =
        checkCall::abi_decode(&adapter.prepare(&identity(), &call).unwrap().calldata).unwrap();
    assert_eq!(decoded.frame.kind, 4);
    assert_eq!(decoded.facts.groupClaims, vec![4, 2]);
    assert_eq!(decoded.facts.codeOrg, keccak256("org-a"));
    assert_eq!(decoded.facts.storageOrg, keccak256("org-a"));
}

#[test]
fn creation_never_relabels_a_registered_foreign_address() {
    let adapter = policy(|s| s["contracts"][0]["org_id"] = json!("foreign-org"));
    let mut call = frame();
    call.kind = FrameKind::Create2;
    call.code_kind = CodeKind::NoCode;
    let decoded =
        checkCall::abi_decode(&adapter.prepare(&identity(), &call).unwrap().calldata).unwrap();
    assert_eq!(decoded.facts.codeOrg, keccak256("foreign-org"));
    assert_eq!(decoded.facts.storageOrg, keccak256("foreign-org"));
    assert_ne!(decoded.facts.storageOrg, decoded.facts.policyOrg);
}

#[test]
fn go_compiler_vectors_match_rust_encoding_and_executable_decisions() {
    use alloy_evm::{
        Evm, EvmEnv, EvmFactory,
        eth::EthEvmFactory,
        revm::{
            bytecode::Bytecode,
            context::{CfgEnv, TxEnv},
            database::InMemoryDB,
            primitives::hardfork::SpecId,
            state::AccountInfo,
        },
    };
    fn field<T: serde::de::DeserializeOwned>(value: &Value, key: &str) -> T {
        serde_json::from_value(value[key].clone()).unwrap()
    }
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../internal/policydsl/testdata/lifecycle-v1.json"
    ))
    .unwrap();
    assert_eq!(fixture["signature"].as_str().unwrap(), checkCall::SIGNATURE);
    let runtime = Bytes::from(
        STANDARD
            .decode(
                fixture["snapshot"]["policies"][0]["bytecode"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap(),
    );
    let target = Address::repeat_byte(0x90);
    for case in fixture["cases"].as_array().unwrap() {
        let f = &case["facts"];
        let c = &case["call"];
        let input = checkCall {
            facts: Facts {
                signer: field(f, "signer"),
                linkedAddresses: field(f, "linked_addresses"),
                groups: field(f, "groups"),
                policyOrg: field(f, "policy_org"),
                callerOrg: field(f, "caller_org"),
                codeOrg: field(f, "code_org"),
                storageOrg: field(f, "storage_org"),
                claims: field(f, "claims"),
                codeShared: field(f, "code_shared"),
                storageShared: field(f, "storage_shared"),
                codeKind: field(f, "code_kind"),
                upgradeTargetOrg: field(f, "upgrade_target_org"),
                groupClaims: field(f, "group_claims"),
                storageDeployer: field(f, "storage_deployer"),
                storagePending: field(f, "storage_pending"),
            },
            frame: Call {
                kind: field(c, "kind"),
                caller: field(c, "caller"),
                codeAddress: field(c, "code_address"),
                storageAddress: field(c, "storage_address"),
                data: field(c, "data_hex"),
                value: U256::from_str_radix(c["value"].as_str().unwrap(), 10).unwrap(),
                depth: U256::from_str_radix(c["depth"].as_str().unwrap(), 10).unwrap(),
            },
        };
        let encoded = input.abi_encode();
        assert_eq!(
            format!("0x{}", alloy_primitives::hex::encode(&encoded)),
            case["calldata_hex"].as_str().unwrap(),
            "{}",
            case["name"]
        );
        let mut db = InMemoryDB::default();
        db.insert_account_info(
            SIGNER,
            AccountInfo {
                balance: U256::from(1_000_000_000),
                ..Default::default()
            },
        );
        db.insert_account_info(
            target,
            AccountInfo {
                code_hash: keccak256(&runtime),
                code: Some(Bytecode::new_raw(runtime.clone())),
                ..Default::default()
            },
        );
        let mut evm = EthEvmFactory::default().create_evm(
            db,
            EvmEnv {
                cfg_env: CfgEnv::new_with_spec(SpecId::PRAGUE),
                ..Default::default()
            },
        );
        let result = evm
            .transact_raw(
                TxEnv::builder()
                    .caller(SIGNER)
                    .to(target)
                    .data(encoded.into())
                    .gas_limit(2_000_000)
                    .gas_price(0)
                    .build()
                    .unwrap(),
            )
            .unwrap();
        assert!(result.result.is_success(), "{}", case["name"]);
        assert_eq!(
            U256::from_be_slice(result.result.output().unwrap()),
            U256::from(case["expected_reason"].as_u64().unwrap()),
            "{}",
            case["name"]
        );
    }
}

#[test]
fn diagnostic_scope_is_independent_of_operational_denials_and_other_memberships() {
    let adapter = policy(|snapshot| snapshot["principals"][0]["banned"] = json!(true));
    assert!(adapter.prepare(&identity(), &frame()).is_err());
    assert!(
        adapter
            .authorize_diagnostic(&identity(), &frame(), &[])
            .is_ok()
    );
    let mut other = identity();
    other.org_id = "org-foreign".into();
    assert!(adapter.authorize_diagnostic(&other, &frame(), &[]).is_err());
    let mut unknown = frame();
    unknown.code_address = Address::repeat_byte(0xee);
    unknown.storage_address = unknown.code_address;
    assert!(
        adapter
            .authorize_diagnostic(&identity(), &unknown, &[])
            .is_err()
    );
    unknown.code_kind = CodeKind::NoCode;
    assert!(
        adapter
            .authorize_diagnostic(&identity(), &unknown, &[])
            .is_ok()
    );
    assert!(
        adapter
            .authorize_diagnostic_account(
                &identity(),
                TARGET,
                frame().code_hash,
                CodeKind::Contract,
                &[]
            )
            .is_ok()
    );
    assert!(
        adapter
            .authorize_diagnostic_account(
                &identity(),
                unknown.code_address,
                frame().code_hash,
                CodeKind::Contract,
                &[]
            )
            .is_err()
    );
}

#[test]
fn diagnostic_and_private_reads_honor_owned_and_precompile_code_pins() {
    let adapter = policy(|snapshot| {
        snapshot["contracts"][0]["code_hash"] = json!(format!("{:#x}", keccak256([1])))
    });
    assert!(
        adapter
            .authorize_diagnostic(&identity(), &frame(), &[])
            .is_err()
    );
    assert!(
        adapter
            .authorize_policy_read(&identity(), &frame(), TARGET, frame().code_hash, false, &[])
            .is_err()
    );
    assert!(
        adapter
            .authorize_policy_read(&identity(), &frame(), TARGET, frame().code_hash, true, &[])
            .is_err()
    );
    assert!(
        policy(|_| {})
            .authorize_policy_read(
                &identity(),
                &frame(),
                Address::with_last_byte(1),
                keccak256([]),
                true,
                &[]
            )
            .is_ok()
    );
}

#[test]
fn candidate_override_is_confined_to_signed_organization_and_valid_runtime() {
    use ops_reth_policy::wire::PolicyArtifact;
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../internal/policydsl/testdata/lifecycle-v1.json"
    ))
    .unwrap();
    let mut artifact: PolicyArtifact =
        serde_json::from_value(fixture["snapshot"]["policies"][0].clone()).unwrap();
    assert!(policy(|_| {}).with_candidate(&artifact, "org-a").is_err());
    artifact.org_id = "org-a".into();
    assert!(policy(|_| {}).with_candidate(&artifact, "org-a").is_ok());
    artifact.bytecode = vec![0];
    assert!(policy(|_| {}).with_candidate(&artifact, "org-a").is_err());
}
