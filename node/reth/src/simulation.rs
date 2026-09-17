//! Simulation executes with an explicit authenticated handle. Gas search never
//! bypasses policy for plain transfers and never commits any application state.

use crate::{
    context::ExecutionBinding,
    policy::{PolicyFactory, PolicyTxError},
    transaction::PolicyTx,
};
use alloy_evm::{
    Database, Evm, EvmEnv, EvmFactory,
    revm::context_interface::result::{EVMError, InvalidTransaction},
};
use alloy_primitives::U256;
use alloy_rpc_types_trace::geth::{
    GethDebugBuiltInTracerType, GethDebugTracerType, GethDebugTracingOptions,
};
use revm_inspectors::tracing::{TracingInspector, TracingInspectorConfig};
use serde_json::{Value, json};

/// The private signed admin request is the trust boundary for this mode. It
/// retains a mandatory organization guard and never applies to real transactions.
pub fn run_diagnostic<DB: Database>(
    factory: PolicyFactory,
    db: DB,
    env: EvmEnv,
    tx: PolicyTx,
    method: &str,
    trace: Option<GethDebugTracingOptions>,
) -> Result<Value, String> {
    let (factory, report) = factory.diagnostic();
    let result = run(factory, db, env, tx, method, trace)?;
    Ok(json!({"result":result,"policy":report.value()?}))
}

pub fn run<DB: Database>(
    factory: PolicyFactory,
    db: DB,
    env: EvmEnv,
    mut tx: PolicyTx,
    method: &str,
    trace: Option<GethDebugTracingOptions>,
) -> Result<Value, String> {
    if !matches!(tx.binding(), Some(ExecutionBinding::Simulation { .. })) {
        return Err("missing simulation binding".into());
    }
    if method == "debug_traceCall" {
        let options = trace.unwrap_or_default();
        let call_config = match options.tracer {
            None => None,
            Some(GethDebugTracerType::BuiltInTracer(GethDebugBuiltInTracerType::CallTracer)) => {
                Some(
                    options
                        .tracer_config
                        .into_call_config()
                        .map_err(|_| "invalid call tracer options")?,
                )
            }
            _ => return Err("unsupported private tracer".into()),
        };
        let config = call_config.as_ref().map_or_else(
            || TracingInspectorConfig::from_geth_config(&options.config),
            TracingInspectorConfig::from_geth_call_config,
        );
        let mut evm = factory.create_evm_with_inspector(db, env, TracingInspector::new(config));
        let result = evm.transact_raw(tx).map_err(|err| err.to_string())?;
        let gas = result.result.tx_gas_used();
        let builder = evm.components().1.geth_builder();
        return if let Some(config) = call_config {
            serde_json::to_value(builder.geth_call_traces(config, gas))
                .map_err(|_| "invalid call trace".into())
        } else {
            serde_json::to_value(builder.geth_traces(
                gas,
                result.result.output().cloned().unwrap_or_default(),
                options.config,
            ))
            .map_err(|_| "invalid execution trace".into())
        };
    }
    if !matches!(method, "eth_call" | "eth_estimateGas") {
        return Err("unsupported simulation method".into());
    }
    if method == "eth_estimateGas" {
        tx.env.gas_limit = tx.env.gas_limit.min(env.block_env.gas_limit);
    }
    let mut evm = factory.create_evm(db, env);
    let result = evm
        .transact_raw(tx.clone())
        .map_err(|err| err.to_string())?;
    if !result.result.is_success() {
        return Err("simulation reverted or halted".into());
    }
    if method == "eth_call" {
        return Ok(json!(format!(
            "0x{}",
            alloy_primitives::hex::encode(result.result.output().cloned().unwrap_or_default())
        )));
    }
    let mut high = tx.env.gas_limit;
    let mut low = result.result.tx_gas_used().saturating_sub(1);
    while low + 1 < high {
        let middle = low + (high - low) / 2;
        tx.env.gas_limit = middle;
        match evm.transact_raw(tx.clone()) {
            Ok(result) if result.result.is_success() => high = middle,
            Ok(_) => low = middle,
            Err(EVMError::Transaction(PolicyTxError::Ethereum(
                InvalidTransaction::CallGasCostMoreThanGasLimit { .. }
                | InvalidTransaction::GasFloorMoreThanGasLimit { .. },
            ))) => low = middle,
            Err(err) => return Err(err.to_string()),
        }
    }
    // Retain the report for the exact returned limit rather than an arbitrary
    // final failed binary-search probe.
    tx.env.gas_limit = high;
    let result = evm.transact_raw(tx).map_err(|err| err.to_string())?;
    if !result.result.is_success() {
        return Err("estimated execution did not succeed".into());
    }
    Ok(json!(format!("{:#x}", U256::from(high))))
}
