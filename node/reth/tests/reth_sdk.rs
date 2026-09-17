#![cfg(feature = "reth-sdk")]
use ops_reth_policy::policy::PolicyFactory;
use reth_ethereum::{
    chainspec::ChainSpec,
    evm::{EthEvmConfig, primitives::ConfigureEvm},
};

#[test]
fn policy_factory_supports_reths_block_executor_contract() {
    fn assert_config<T: ConfigureEvm>() {}
    assert_config::<EthEvmConfig<ChainSpec, PolicyFactory>>();
}

#[test]
fn explicit_execution_context_supports_block_and_engine_execution() {
    fn assert_config<
        T: reth_ethereum::evm::primitives::ConfigureEngineEvm<
                reth_ethereum::rpc::types::engine::ExecutionData,
            >,
    >() {
    }
    assert_config::<ops_reth_policy::sdk::OpsEvmConfig>();
}
