//! Pinned Reth v2.5.2 integration. Context travels explicitly through block
//! execution and assembly; no mutable ambient signer or thread-local scope exists.

use crate::{
    archive::BlockDescriptor,
    policy::{PolicyEvm, PolicyFactory},
    runtime::{ExecutionHandle, PolicyRuntime},
};
use alloy_consensus::Header;
use alloy_evm::{
    EvmEnv,
    block::{BlockExecutorFactory, StateDB},
    eth::{EthBlockExecutionCtx, EthBlockExecutorFactory, EthEvmContext},
    revm::inspector::Inspector,
};
use alloy_primitives::keccak256;
use reth_ethereum::{
    Block, EthPrimitives,
    chainspec::ChainSpec,
    evm::{
        EthBlockAssembler, EthEvmConfig, RethReceiptBuilder,
        primitives::{
            ConfigureEngineEvm, ConfigureEvm, ExecutableTxIterator, NextBlockEnvAttributes,
            execute::{BlockAssembler, BlockAssemblerInput, BlockExecutionError},
        },
    },
    node::{
        api::{FullNodeTypes, NodeTypes},
        builder::{BuilderContext, components::ExecutorBuilder},
    },
    primitives::{SealedBlock, SealedHeader},
    rpc::types::engine::ExecutionData,
};
use std::{io, sync::Arc};

type InnerFactory = EthBlockExecutorFactory<RethReceiptBuilder, Arc<ChainSpec>, PolicyFactory>;

#[derive(Clone, Debug)]
pub struct ExecutionCtx<'a> {
    inner: EthBlockExecutionCtx<'a>,
    handle: Arc<ExecutionHandle>,
}

#[derive(Clone, Debug)]
pub struct OpsBlockExecutorFactory {
    inner: InnerFactory,
}
impl BlockExecutorFactory for OpsBlockExecutorFactory {
    type EvmFactory = PolicyFactory;
    type TxExecutionResult = <InnerFactory as BlockExecutorFactory>::TxExecutionResult;
    type ExecutionCtx<'a> = ExecutionCtx<'a>;
    type Transaction = <InnerFactory as BlockExecutorFactory>::Transaction;
    type Receipt = <InnerFactory as BlockExecutorFactory>::Receipt;
    type Executor<'a, DB: StateDB, I: Inspector<EthEvmContext<DB>>> =
        <InnerFactory as BlockExecutorFactory>::Executor<'a, DB, I>;
    fn evm_factory(&self) -> &Self::EvmFactory {
        self.inner.evm_factory()
    }
    fn create_executor<'a, DB: StateDB, I: Inspector<EthEvmContext<DB>>>(
        &'a self,
        mut evm: PolicyEvm<DB, I>,
        ctx: Self::ExecutionCtx<'a>,
    ) -> Self::Executor<'a, DB, I> {
        evm.install_context(ctx.handle.factory());
        self.inner.create_executor(evm, ctx.inner)
    }
}

#[derive(Clone, Debug)]
pub struct OpsBlockAssembler {
    inner: EthBlockAssembler<ChainSpec>,
    runtime: Arc<PolicyRuntime>,
}
impl BlockAssembler<OpsBlockExecutorFactory> for OpsBlockAssembler {
    type Block = Block;
    fn assemble_block(
        &self,
        input: BlockAssemblerInput<'_, '_, OpsBlockExecutorFactory>,
    ) -> Result<Block, BlockExecutionError> {
        let handle = input.execution_ctx.handle;
        let inner = BlockAssemblerInput::<InnerFactory>::new(
            input.evm_env,
            input.execution_ctx.inner,
            input.parent,
            input.transactions,
            input.output,
            input.bundle_state,
            input.state_provider,
            input.state_root,
            input.block_access_list_hash,
        );
        let block = self.inner.assemble_block(inner, None, None, None)?;
        let descriptor = BlockDescriptor {
            network: self.runtime.network().clone(),
            hash: block.header.hash_slow(),
            parent_hash: block.header.parent_hash,
            number: block.header.number,
            timestamp: block.header.timestamp,
            transactions: block
                .body
                .transactions
                .iter()
                .map(|tx| *tx.tx_hash())
                .collect(),
        };
        handle
            .persist(&self.runtime.archive, &descriptor)
            .map_err(BlockExecutionError::msg)?;
        Ok(block)
    }
}

#[derive(Clone, Debug)]
pub struct OpsEvmConfig {
    inner: EthEvmConfig<ChainSpec, PolicyFactory>,
    factory: OpsBlockExecutorFactory,
    assembler: OpsBlockAssembler,
    runtime: Arc<PolicyRuntime>,
}
impl OpsEvmConfig {
    pub fn new(chain: Arc<ChainSpec>, runtime: Arc<PolicyRuntime>) -> Self {
        let inner = EthEvmConfig::new_with_evm_factory(chain, PolicyFactory::unconfigured());
        Self {
            factory: OpsBlockExecutorFactory {
                inner: inner.executor_factory.clone(),
            },
            assembler: OpsBlockAssembler {
                inner: inner.block_assembler.clone(),
                runtime: runtime.clone(),
            },
            inner,
            runtime,
        }
    }
}
impl ConfigureEvm for OpsEvmConfig {
    type Primitives = EthPrimitives;
    type Error = io::Error;
    type NextBlockEnvCtx = NextBlockEnvAttributes;
    type BlockExecutorFactory = OpsBlockExecutorFactory;
    type BlockAssembler = OpsBlockAssembler;
    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        &self.factory
    }
    fn block_assembler(&self) -> &Self::BlockAssembler {
        &self.assembler
    }
    fn evm_env(&self, header: &Header) -> Result<EvmEnv, Self::Error> {
        Ok(self
            .inner
            .evm_env(header)
            .expect("infallible Ethereum environment"))
    }
    fn next_evm_env(
        &self,
        parent: &Header,
        attributes: &Self::NextBlockEnvCtx,
    ) -> Result<EvmEnv, Self::Error> {
        Ok(self
            .inner
            .next_evm_env(parent, attributes)
            .expect("infallible Ethereum environment"))
    }
    fn context_for_block<'a>(
        &self,
        block: &'a SealedBlock<Block>,
    ) -> Result<ExecutionCtx<'a>, Self::Error> {
        let descriptor = BlockDescriptor {
            network: self.runtime.network().clone(),
            hash: block.hash(),
            parent_hash: block.header().parent_hash,
            number: block.header().number,
            timestamp: block.header().timestamp,
            transactions: block
                .body()
                .transactions
                .iter()
                .map(|tx| *tx.tx_hash())
                .collect(),
        };
        Ok(ExecutionCtx {
            inner: self
                .inner
                .context_for_block(block)
                .expect("infallible Ethereum context"),
            handle: self.runtime.replay(&descriptor).map_err(io::Error::other)?,
        })
    }
    fn context_for_next_block(
        &self,
        parent: &SealedHeader,
        attributes: Self::NextBlockEnvCtx,
    ) -> Result<ExecutionCtx<'_>, Self::Error> {
        let at = i64::try_from(attributes.timestamp).map_err(io::Error::other)?;
        let handle = self.runtime.pin_candidate(at).map_err(io::Error::other)?;
        Ok(ExecutionCtx {
            inner: self
                .inner
                .context_for_next_block(parent, attributes)
                .expect("infallible Ethereum context"),
            handle,
        })
    }
}
impl ConfigureEngineEvm<ExecutionData> for OpsEvmConfig {
    fn evm_env_for_payload(&self, payload: &ExecutionData) -> Result<EvmEnv, Self::Error> {
        Ok(self
            .inner
            .evm_env_for_payload(payload)
            .expect("infallible Ethereum environment"))
    }
    fn context_for_payload<'a>(
        &self,
        payload: &'a ExecutionData,
    ) -> Result<ExecutionCtx<'a>, Self::Error> {
        let descriptor = BlockDescriptor {
            network: self.runtime.network().clone(),
            hash: payload.payload.block_hash(),
            parent_hash: payload.parent_hash(),
            number: payload.payload.block_number(),
            timestamp: payload.payload.timestamp(),
            transactions: payload
                .payload
                .transactions()
                .iter()
                .map(keccak256)
                .collect(),
        };
        Ok(ExecutionCtx {
            inner: self
                .inner
                .context_for_payload(payload)
                .expect("infallible Ethereum context"),
            handle: self.runtime.replay(&descriptor).map_err(io::Error::other)?,
        })
    }
    fn tx_iterator_for_payload(
        &self,
        payload: &ExecutionData,
    ) -> Result<impl ExecutableTxIterator<Self>, Self::Error> {
        Ok(self
            .inner
            .tx_iterator_for_payload(payload)
            .expect("infallible Ethereum transactions"))
    }
}

#[derive(Clone, Debug)]
pub struct OpsExecutorBuilder(pub Arc<PolicyRuntime>);
impl<Node> ExecutorBuilder<Node> for OpsExecutorBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec = ChainSpec, Primitives = EthPrimitives>>,
{
    type EVM = OpsEvmConfig;
    async fn build_evm(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::EVM> {
        if ctx.chain_spec().chain.id() != self.0.network().chain_id {
            eyre::bail!("OPS policy network does not match node chain");
        }
        Ok(OpsEvmConfig::new(ctx.chain_spec(), self.0))
    }
}
