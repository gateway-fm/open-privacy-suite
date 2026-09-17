//! Preserve exact signed transaction or simulation request identity past Reth's
//! conversion to TxEnv, which discards envelope signatures.

use crate::context::ExecutionBinding;
use alloy_consensus::{EthereumTxEnvelope, TxEip4844, transaction::RlpEcdsaEncodableTx};
use alloy_evm::{
    FromRecoveredTx, FromTxWithEncoded, IntoTxEnv,
    env::TransactionEnvMut,
    revm::{
        context::TxEnv,
        context_interface::{Transaction, transaction::AccessList},
    },
};
use alloy_primitives::{Address, B256, Bytes, TxKind, U256};

#[derive(Clone, Debug)]
pub struct PolicyTx {
    pub(crate) env: TxEnv,
    pub(crate) binding: Option<ExecutionBinding>,
}

impl PolicyTx {
    pub fn bound(env: TxEnv, binding: ExecutionBinding) -> Self {
        Self {
            env,
            binding: Some(binding),
        }
    }
    pub fn unbound(env: TxEnv) -> Self {
        Self { env, binding: None }
    }
    pub fn binding(&self) -> Option<&ExecutionBinding> {
        self.binding.as_ref()
    }
    pub fn environment(&self) -> &TxEnv {
        &self.env
    }
}

impl IntoTxEnv<Self> for PolicyTx {
    fn into_tx_env(self) -> Self {
        self
    }
}

#[cfg(feature = "reth-sdk")]
impl alloy_evm::rpc::TryIntoTxEnv<PolicyTx>
    for reth_ethereum::rpc::eth::primitives::TransactionRequest
{
    type Err = alloy_evm::rpc::EthTxEnvError;
    fn try_into_tx_env(self, environment: &alloy_evm::EvmEnv) -> Result<PolicyTx, Self::Err> {
        <Self as alloy_evm::rpc::TryIntoTxEnv<TxEnv>>::try_into_tx_env(self, environment)
            .map(PolicyTx::unbound)
    }
}

impl<T: AsRef<TxEip4844> + RlpEcdsaEncodableTx> FromRecoveredTx<EthereumTxEnvelope<T>>
    for PolicyTx
{
    fn from_recovered_tx(tx: &EthereumTxEnvelope<T>, sender: Address) -> Self {
        Self::bound(
            TxEnv::from_recovered_tx(tx, sender),
            ExecutionBinding::Transaction(*tx.tx_hash()),
        )
    }
}

impl<T: AsRef<TxEip4844> + RlpEcdsaEncodableTx> FromTxWithEncoded<EthereumTxEnvelope<T>>
    for PolicyTx
{
    fn from_encoded_tx(tx: &EthereumTxEnvelope<T>, sender: Address, _encoded: Bytes) -> Self {
        // The decoded signed envelope is authoritative. In particular, EIP-4844
        // pooled sidecar bytes are not part of its transaction hash.
        Self::from_recovered_tx(tx, sender)
    }
}

impl Transaction for PolicyTx {
    type AccessListItem<'a> = <TxEnv as Transaction>::AccessListItem<'a>;
    type Authorization<'a> = <TxEnv as Transaction>::Authorization<'a>;
    fn tx_type(&self) -> u8 {
        self.env.tx_type()
    }
    fn caller(&self) -> Address {
        self.env.caller()
    }
    fn gas_limit(&self) -> u64 {
        self.env.gas_limit()
    }
    fn value(&self) -> U256 {
        self.env.value()
    }
    fn input(&self) -> &Bytes {
        self.env.input()
    }
    fn nonce(&self) -> u64 {
        self.env.nonce()
    }
    fn kind(&self) -> TxKind {
        self.env.kind()
    }
    fn chain_id(&self) -> Option<u64> {
        self.env.chain_id()
    }
    fn gas_price(&self) -> u128 {
        self.env.gas_price()
    }
    fn access_list(&self) -> Option<impl Iterator<Item = Self::AccessListItem<'_>>> {
        self.env.access_list()
    }
    fn blob_versioned_hashes(&self) -> &[B256] {
        self.env.blob_versioned_hashes()
    }
    fn max_fee_per_blob_gas(&self) -> u128 {
        self.env.max_fee_per_blob_gas()
    }
    fn authorization_list_len(&self) -> usize {
        self.env.authorization_list_len()
    }
    fn authorization_list(&self) -> impl Iterator<Item = Self::Authorization<'_>> {
        self.env.authorization_list()
    }
    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        self.env.max_priority_fee_per_gas()
    }
}

impl PolicyTx {
    fn invalidate_transaction_binding(&mut self) {
        if matches!(self.binding, Some(ExecutionBinding::Transaction(_))) {
            self.binding = None;
        }
    }
}

impl TransactionEnvMut for PolicyTx {
    fn set_gas_limit(&mut self, value: u64) {
        if self.env.gas_limit != value {
            self.invalidate_transaction_binding();
        }
        self.env.set_gas_limit(value);
    }
    fn set_nonce(&mut self, value: u64) {
        if self.env.nonce != value {
            self.invalidate_transaction_binding();
        }
        self.env.set_nonce(value);
    }
    fn set_access_list(&mut self, value: AccessList) {
        if self.env.access_list != value || self.env.tx_type == 0 {
            self.invalidate_transaction_binding();
        }
        self.env.set_access_list(value);
    }
}
