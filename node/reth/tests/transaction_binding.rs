use alloy_consensus::{SignableTransaction, TxEnvelope, TxLegacy};
use alloy_evm::{FromRecoveredTx, FromTxWithEncoded, env::TransactionEnvMut};
use alloy_primitives::{Address, Bytes, Signature, U256};
use ops_reth_policy::{context::ExecutionBinding, transaction::PolicyTx};

fn envelope(signature: u64) -> TxEnvelope {
    TxLegacy {
        chain_id: Some(31337),
        gas_limit: 100_000,
        ..Default::default()
    }
    .into_signed(Signature::new(U256::from(signature), U256::from(2), false))
    .into()
}

#[test]
fn conversion_preserves_signed_hash_not_sender_nonce_or_unsigned_environment() {
    let first = envelope(1);
    let second = envelope(3);
    let a = PolicyTx::from_recovered_tx(&first, Address::ZERO);
    let b = PolicyTx::from_recovered_tx(&second, Address::ZERO);
    assert_eq!(a.environment(), b.environment());
    assert_eq!(
        a.binding(),
        Some(&ExecutionBinding::Transaction(*first.tx_hash()))
    );
    assert_ne!(a.binding(), b.binding());
    let encoded = PolicyTx::from_encoded_tx(&first, Address::ZERO, Bytes::new());
    assert_eq!(encoded.binding(), a.binding());
}

#[test]
fn changing_a_signed_transaction_environment_invalidates_its_binding() {
    let mut tx = PolicyTx::from_recovered_tx(&envelope(1), Address::ZERO);
    tx.set_gas_limit(99_000);
    assert!(tx.binding().is_none());
}

#[test]
fn setting_an_empty_access_list_cannot_change_signed_transaction_type_silently() {
    let mut tx = PolicyTx::from_recovered_tx(&envelope(1), Address::ZERO);
    tx.set_access_list(Default::default());
    assert!(tx.binding().is_none());
}
