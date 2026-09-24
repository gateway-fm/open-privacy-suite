use crate::{
    approvals::{Selected, Store},
    execution::ApprovalFactory,
};
use reth_basic_payload_builder::{BuildArguments, BuildOutcome, PayloadBuilder, PayloadConfig};
use reth_ethereum::{
    EthPrimitives, TransactionSigned,
    chainspec::{ChainSpec, EthChainSpec},
    evm::{
        EthEvmConfig,
        primitives::{ConfigureEvm, NextBlockEnvAttributes},
    },
    node::{
        api::{FullNodeTypes, NodeTypes},
        builder::{
            BuilderContext, PayloadBuilderConfig, PayloadTypes, components::PayloadBuilderBuilder,
        },
    },
    pool::{BestTransactions, PoolTransaction, TransactionPool},
    provider::{ChainSpecProvider, StateProviderFactory},
};
use reth_ethereum_engine_primitives::{EthBuiltPayload, EthPayloadAttributes};
use reth_ethereum_payload_builder::{
    EthereumBuilderConfig, EthereumPayloadBuilder, default_ethereum_payload,
};
use reth_payload_builder_primitives::PayloadBuilderError;
use std::{
    sync::{Arc, Mutex},
    time::Instant,
};

#[derive(Debug, Clone)]
pub struct Component {
    pub store: Option<Arc<Store>>,
}
impl<Types, Node, Pool, Evm> PayloadBuilderBuilder<Node, Pool, Evm> for Component
where
    Types: NodeTypes<ChainSpec = ChainSpec, Primitives = EthPrimitives>,
    Node: FullNodeTypes<Types = Types>,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TransactionSigned>>
        + Unpin
        + 'static,
    Evm: ConfigureEvm<Primitives = EthPrimitives, NextBlockEnvCtx = NextBlockEnvAttributes>
        + 'static,
    Types::Payload:
        PayloadTypes<BuiltPayload = EthBuiltPayload, PayloadAttributes = EthPayloadAttributes>,
{
    type PayloadBuilder = Builder<Pool, Node::Provider, Evm>;
    async fn build_payload_builder(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
        evm: Evm,
    ) -> eyre::Result<Self::PayloadBuilder> {
        let conf = ctx.payload_builder_config();
        let config = EthereumBuilderConfig::new()
            .with_gas_limit(conf.gas_limit_for(ctx.chain_spec().chain()))
            .with_max_blobs_per_block(conf.max_blobs_per_block())
            .with_extra_data(conf.extra_data())
            .with_skip_state_root(ctx.config().tree_config().skip_state_root());
        if let Some(s) = &self.store {
            s.start(pool.clone());
        }
        Ok(Builder {
            pool,
            client: ctx.provider().clone(),
            evm,
            config,
            store: self.store,
        })
    }
}
#[derive(Clone)]
pub struct Builder<Pool, Client, Evm> {
    pool: Pool,
    client: Client,
    evm: Evm,
    config: EthereumBuilderConfig,
    store: Option<Arc<Store>>,
}
impl<Pool, Client, Evm> PayloadBuilder for Builder<Pool, Client, Evm>
where
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TransactionSigned>>,
    Client: StateProviderFactory + ChainSpecProvider<ChainSpec = ChainSpec> + Clone,
    Evm: ConfigureEvm<Primitives = EthPrimitives, NextBlockEnvCtx = NextBlockEnvAttributes>,
{
    type Attributes = EthPayloadAttributes;
    type BuiltPayload = EthBuiltPayload;
    fn try_build(
        &self,
        args: BuildArguments<Self::Attributes, Self::BuiltPayload>,
    ) -> Result<BuildOutcome<Self::BuiltPayload>, PayloadBuilderError> {
        let start = Instant::now();
        let profile = (std::env::var("OPS_PROFILE").as_deref() == Ok("1"))
            .then(|| Arc::new(Mutex::new(crate::profile::Stages::default())));
        let result = if let Some(store) = &self.store {
            let selection = Arc::new(Mutex::new(None));
            let evm = EthEvmConfig::new_with_evm_factory(
                self.client.chain_spec(),
                ApprovalFactory {
                    selection: selection.clone(),
                    profile: profile.clone(),
                    legacy: std::env::var("OPS_FINGERPRINT_MODE").as_deref() == Ok("legacy"),
                    verify: std::env::var("OPS_FINGERPRINT_MODE").as_deref() == Ok("verify"),
                },
            );
            default_ethereum_payload(
                evm,
                self.client.clone(),
                self.pool.clone(),
                self.config.clone(),
                args,
                |attrs| {
                    let store = store.clone();
                    Box::new(
                        self.pool
                            .best_transactions_with_attributes(attrs)
                            .filter_transactions(move |tx| {
                                if !store.seen_at(*tx.hash(), tx.timestamp) {
                                    return false;
                                }
                                let Some(approval) = store.get(tx.hash()) else {
                                    return false;
                                };
                                *selection.lock().unwrap() = Some(Selected {
                                    approval,
                                    sender: tx.sender(),
                                    nonce: tx.nonce(),
                                });
                                true
                            }),
                    )
                },
            )
        } else {
            // Stock EVM, stock transaction selection: true module-free baseline.
            default_ethereum_payload(
                self.evm.clone(),
                self.client.clone(),
                self.pool.clone(),
                self.config.clone(),
                args,
                |attrs| self.pool.best_transactions_with_attributes(attrs),
            )
        };
        let elapsed = start.elapsed().as_nanos();
        if let Ok(ref outcome) = result
            && let Some(p) = outcome.payload()
        {
            eprintln!(
                "OPS_BUILD_TIMING {}",
                serde_json::json!({"module":self.store.is_some(),"elapsed_ns":elapsed,"transactions":p.block().body().transactions.len(),"block_hash":p.block().hash(),"approval_stats":self.store.as_ref().map(|s|s.stats()),"profile":profile.as_ref().map(crate::profile::report)})
            );
        }
        result
    }
    fn build_empty_payload(
        &self,
        config: PayloadConfig<Self::Attributes>,
    ) -> Result<Self::BuiltPayload, PayloadBuilderError> {
        EthereumPayloadBuilder::new(
            self.client.clone(),
            self.pool.clone(),
            self.evm.clone(),
            self.config.clone(),
        )
        .build_empty_payload(config)
    }
}
