use alloy_primitives::{B256, Bytes};
use alloy_rpc_types_trace::geth::GethDebugTracingCallOptions;
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD};
use ops_reth_policy::{
    api::{ExecutionBackend, PrivateApi, serve},
    archive::ArtifactStore,
    context::ExecutionBinding,
    runtime::PolicyRuntime,
    sdk::OpsExecutorBuilder,
    simulation,
    transaction::PolicyTx,
    wire::{Identity, Network, SimulationRequest, Verifier},
};
use reth_ethereum::{
    cli::interface::Cli,
    node::{
        EthereumNode,
        builder::rpc::{BasicEngineApiBuilder, BasicEngineValidatorBuilder, RpcAddOns},
        node::{EthereumEngineValidatorBuilder, EthereumEthApiBuilder},
    },
    rpc::{
        api::eth::helpers::{Call, EthBlocks, EthTransactions},
        eth::{
            EthApiError,
            primitives::{BlockId, TransactionRequest, state::EvmOverrides},
        },
    },
};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

type BackendFuture<T> = Pin<Box<dyn Future<Output = Result<T, String>> + Send>>;
type SubmitFn = Arc<dyn Fn(Identity, Bytes) -> BackendFuture<B256> + Send + Sync>;
type StatusFn = Arc<dyn Fn(B256) -> BackendFuture<Value> + Send + Sync>;
type SimulateFn =
    Arc<dyn Fn(Identity, SimulationRequest, Bytes) -> BackendFuture<Value> + Send + Sync>;
struct Backend {
    submit: SubmitFn,
    simulate: SimulateFn,
    status: StatusFn,
}
#[async_trait]
impl ExecutionBackend for Backend {
    fn capabilities(&self) -> Vec<String> {
        [
            "per_frame_a5",
            "signed_identity_v1",
            "fact_stream_v1",
            "simulation_v1",
            "archive_v1",
            "candidate_simulation_v1",
            "scoped_diagnostics_v1",
            "finalized_status_v1",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }
    async fn submit(&self, identity: Identity, raw: Bytes) -> Result<B256, String> {
        (self.submit)(identity, raw).await
    }
    async fn transaction_status(&self, hash: B256) -> Result<Value, String> {
        (self.status)(hash).await
    }
    async fn simulate(
        &self,
        identity: Identity,
        request: SimulationRequest,
        exact: Bytes,
    ) -> Result<Value, String> {
        (self.simulate)(identity, request, exact).await
    }
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs() as i64)
        .unwrap_or_default()
}
fn required(name: &str) -> eyre::Result<String> {
    std::env::var(name).map_err(|_| eyre::eyre!("{name} is required"))
}

fn main() -> eyre::Result<()> {
    Cli::parse_args().run(move |mut builder, _| async move {
        let network=Network {chain_id:required("OPS_NODE_POLICY_CHAIN_ID")?.parse()?,deployment_id:required("OPS_NODE_POLICY_DEPLOYMENT_ID")?};
        let encoded:BTreeMap<String,String>=serde_json::from_str(&required("OPS_NODE_POLICY_PUBLIC_KEYS")?)?;
        if encoded.is_empty() || network.chain_id==0 || network.deployment_id.is_empty() {eyre::bail!("invalid OPS policy trust configuration");}
        let mut keys=BTreeMap::new();
        for (id,encoded) in encoded {
            let bytes:[u8;32]=STANDARD.decode(encoded)?.try_into().map_err(|_|eyre::eyre!("invalid Ed25519 public key length"))?;
            keys.insert(id,ed25519_dalek::VerifyingKey::from_bytes(&bytes)?);
        }
        let archive=Arc::new(ArtifactStore::open(required("OPS_NODE_POLICY_STATE_DIR")?).map_err(eyre::Report::msg)?);
        let capacity=std::env::var("OPS_NODE_POLICY_CAPACITY").unwrap_or_else(|_|"100000".into()).parse()?;
        let runtime=Arc::new(PolicyRuntime::open(Verifier::new(network,keys),archive,capacity,now()).map_err(eyre::Report::msg)?);
        for selection in [&builder.config().rpc.http_api,&builder.config().rpc.ws_api].into_iter().flatten() {
            if selection.to_string().split(',').any(|s|matches!(s,"all"|"debug"|"trace")) {eyre::bail!("historical debug/trace RPC is reserved for authenticated forensic replay; use ops_simulate for calls");}
        }
        builder.config_mut().rpc.ipcdisable=true;
        let listener=tokio::net::TcpListener::bind(required("OPS_NODE_POLICY_LISTEN")?).await?;
        let token=required("OPS_NODE_POLICY_TOKEN")?;
        let eth_builder:EthereumEthApiBuilder=Default::default();
        let engine_builder:BasicEngineApiBuilder<EthereumEngineValidatorBuilder>=Default::default();
        let validator_builder:BasicEngineValidatorBuilder<EthereumEngineValidatorBuilder>=Default::default();
        let addons=RpcAddOns::new(eth_builder,EthereumEngineValidatorBuilder::default(),engine_builder,validator_builder,tower::layer::util::Identity::new(),tower::layer::util::Identity::new());
        let handle=builder.with_types::<EthereumNode>().with_components(EthereumNode::components().executor(OpsExecutorBuilder(runtime.clone()))).with_add_ons(addons).launch_with_debug_capabilities().await?;
        let eth_submit=handle.node.rpc_registry.eth_api().clone();
        let eth_simulate=eth_submit.clone();
        let eth_status=eth_submit.clone();
        let status_runtime=runtime.clone();
        let status:StatusFn=Arc::new(move |hash| {
            let eth=eth_status.clone(); let runtime=status_runtime.clone();
            Box::pin(async move {
                let identity=runtime.retained_identity(hash)?;
                let status=if let Some(receipt)=eth.transaction_receipt(hash).await.map_err(|_|"receipt lookup failed")? {
                    let receipt=serde_json::to_value(receipt).map_err(|_|"invalid canonical receipt")?;
                    let block:B256=receipt.get("blockHash").and_then(Value::as_str).ok_or("receipt block unavailable")?.parse().map_err(|_|"invalid receipt block")?;
                    let mut status=runtime.transaction_status(hash,Some(block))?.ok_or("canonical execution evidence unavailable")?;
                    runtime.reconcile_included(hash,block)?;
                    status.status=if receipt.get("status").and_then(Value::as_str)==Some("0x1") {"included"} else {"reverted"}.into();
                    if let Some(finalized)=eth.rpc_block_header(BlockId::finalized()).await.map_err(|_|"finalized head lookup failed")? {
                        let finalized=serde_json::to_value(finalized).map_err(|_|"invalid finalized head")?;
                        let final_hash:B256=finalized["hash"].as_str().ok_or("finalized hash unavailable")?.parse().map_err(|_|"invalid finalized hash")?;
                        let final_number=u64::from_str_radix(finalized["number"].as_str().ok_or("finalized number unavailable")?.trim_start_matches("0x"),16).map_err(|_|"invalid finalized number")?;
                        let included=status.block_number.ok_or("included block number unavailable")?;
                        if let Some(canonical)=eth.rpc_block_header(BlockId::number(included)).await.map_err(|_|"canonical block lookup failed")? {
                            let canonical=serde_json::to_value(canonical).map_err(|_|"invalid canonical header")?;
                            let canonical_hash:B256=canonical["hash"].as_str().ok_or("canonical hash unavailable")?.parse().map_err(|_|"invalid canonical hash")?;
                            if let Some(final_canonical)=eth.rpc_block_header(BlockId::number(final_number)).await.map_err(|_|"canonical finalized lookup failed")? {
                                let final_canonical=serde_json::to_value(final_canonical).map_err(|_|"invalid canonical finalized header")?;
                                if final_canonical["hash"].as_str()==Some(&format!("{final_hash:#x}")) {status.observe_finality(canonical_hash,final_number,final_hash);}
                            }
                        }
                    }
                    status
                } else if identity.header.expires_at <= now() {
                    // This describes the current ticket only. An already pinned
                    // candidate can still settle; OPS continues receipt polling.
                    ops_reth_policy::runtime::TransactionStatus {status:"expired".into(),facts_version:identity.min_snapshot_version,block_hash:None,block_number:None,reason_code:"IDENTITY_EXPIRED".into(),created:Vec::new(),finalized:false,finalized_block_hash:None,finalized_block_number:None}
                } else {
                    runtime.transaction_status(hash,None)?.unwrap_or(ops_reth_policy::runtime::TransactionStatus {status:"pending".into(),facts_version:identity.min_snapshot_version,block_hash:None,block_number:None,reason_code:String::new(),created:Vec::new(),finalized:false,finalized_block_hash:None,finalized_block_number:None})
                };
                serde_json::to_value(status).map_err(|_|"invalid execution status".into())
            })
        });
        let submit:SubmitFn=Arc::new(move |_,raw| {let eth=eth_submit.clone();Box::pin(async move {eth.send_raw_transaction(raw).await.map_err(|_|"transaction pool rejected submission".into())})});
        let simulation_runtime=runtime.clone();
        let simulate:SimulateFn=Arc::new(move |identity,request,_exact| {
            let eth=eth_simulate.clone();
            let org=identity.org_id.clone();
            let binding=ExecutionBinding::Simulation {digest:identity.binding_hash.parse().unwrap_or_default(),context_id:identity.context_id.clone()};
            let pinned=simulation_runtime.pin_simulation(identity,now());
            Box::pin(async move {
                let pinned=pinned?;
                let (factory,candidate_report)=if let Some(candidate)=&request.candidate_policy {let (factory,report)=pinned.candidate_factory(candidate,&org)?;(factory,Some(report))} else {(pinned.factory(),None)};
                let transaction:TransactionRequest=serde_json::from_value(request.params[0].clone()).map_err(|_|"invalid simulation transaction")?;
                let block:BlockId=request.params.get(1).filter(|v|!v.is_null()).map(|v|serde_json::from_value(v.clone())).transpose().map_err(|_|"invalid simulation block")?.unwrap_or_default();
                // A signed principal authorizes execution of existing code,
                // never replacement code/storage supplied by an RPC caller.
                let overrides=EvmOverrides::default();
                let mut trace=None;
                if request.method=="debug_traceCall" {
                    let options:GethDebugTracingCallOptions=serde_json::from_value(request.params.get(2).cloned().unwrap_or_else(||serde_json::json!({}))).map_err(|_|"invalid tracing options")?;
                    if options.tx_index.is_some() {return Err("transaction-index simulation is unsupported".into());}
                    if options.state_overrides.as_ref().is_some_and(|state|!state.is_empty()) {return Err("simulation state overrides are unsupported".into());}
                    trace=Some(options.tracing_options);
                }
                eth.spawn_with_call_at(transaction,block,overrides,move |db,env,tx| {
                    let tx=PolicyTx::bound(tx.environment().clone(),binding);
                    let result=if let Some(report)=candidate_report {
                        let factory=if request.dry_run {factory.diagnostic().0} else {factory};
                        simulation::run(factory,db,env,tx,&request.method,trace).and_then(|result|Ok(serde_json::json!({"result":result,"policy":report.value()?})))
                    } else if request.dry_run {simulation::run_diagnostic(factory,db,env,tx,&request.method,trace)} else {simulation::run(factory,db,env,tx,&request.method,trace)};
                    result.map_err(EthApiError::InvalidParams)
                }).await.map_err(|_|"simulation denied or failed".into())
            })
        });
        let api=Arc::new(PrivateApi::new(runtime,Arc::new(Backend {submit,simulate,status}),token,Arc::new(now)).map_err(eyre::Report::msg)?);
        let (stop,stopped)=tokio::sync::oneshot::channel::<()>();
        let mut private=tokio::spawn(serve(listener,api,async move {let _=stopped.await;}));
        tokio::select! {
            exit=handle.wait_for_node_exit()=> {let _=stop.send(());private.await??;exit},
            result=&mut private=> {result??;eyre::bail!("private OPS policy listener stopped")},
        }
    })
}
