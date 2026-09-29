mod approvals;
mod batch;
mod call_hash;
mod delivery;
mod direct;
mod execution;
mod fingerprint;
mod hops;
mod payload;
mod profile;
mod verification;
use reth_ethereum::{
    cli::interface::Cli,
    node::{EthereumNode, node::EthereumAddOns},
};
use std::{sync::Arc, time::Instant};

fn main() -> eyre::Result<()> {
    let boot = Instant::now();
    if std::env::args().nth(1).as_deref() == Some("fingerprint") {
        let value: serde_json::Value = serde_json::from_reader(std::io::stdin())?;
        let hash = fingerprint::fingerprint(&value["calls"], &value["pre"], &value["diff"])
            .map_err(|e| eyre::eyre!(e))?;
        println!("{hash}");
        return Ok(());
    }
    let enabled = approvals_enabled(std::env::var("OPS_APPROVALS"))?;
    Cli::parse_args().run(async move |builder, _| {
        let store = if enabled {
            let settings = delivery::Settings::from_env().map_err(|e| eyre::eyre!(e))?;
            let store = Arc::new(approvals::Store::new(
                settings.wait,
                settings.capacity,
                boot,
            ));
            let boot_id = delivery::boot_id()?;
            let listener = tokio::net::TcpListener::bind(&settings.listen).await?;
            let service = delivery::Delivery::new(
                &settings,
                store.clone(),
                boot_id.clone(),
                approvals::unix_ms,
            )?;
            tracing::info!(listen = %settings.listen, %boot_id, "OPS approval delivery");
            builder
                .task_executor()
                .spawn_critical_with_graceful_shutdown_signal(
                    "ops approval delivery",
                    move |shutdown| async move {
                        // Hold the shutdown guard until the server has drained its calls.
                        let (keep, kept) = tokio::sync::oneshot::channel();
                        let signal = async move {
                            let _ = keep.send(shutdown.await);
                        };
                        if let Err(err) =
                            delivery::serve(listener, service, &settings, signal).await
                        {
                            tracing::error!(%err, "OPS approval delivery stopped");
                        }
                        drop(kept);
                    },
                );
            Some(store)
        } else {
            None
        };
        builder
            .with_types::<EthereumNode>()
            .with_components(EthereumNode::components().payload(
                reth_ethereum::node::builder::components::BasicPayloadServiceBuilder::new(
                    payload::Component { store },
                ),
            ))
            .with_add_ons(EthereumAddOns::default())
            .launch()
            .await?
            .wait_for_node_exit()
            .await
    })
}

fn approvals_enabled(value: Result<String, std::env::VarError>) -> eyre::Result<bool> {
    match value.as_deref() {
        Ok("1") => Ok(true),
        Ok("0") | Err(std::env::VarError::NotPresent) => Ok(false),
        _ => eyre::bail!("OPS_APPROVALS must be 1 (enabled) or 0 (disabled)"),
    }
}

#[cfg(test)]
mod config_tests {
    use super::*;

    #[test]
    fn an_invalid_enable_flag_must_not_silently_disable_enforcement() {
        assert!(approvals_enabled(Ok("1".into())).unwrap());
        assert!(!approvals_enabled(Ok("0".into())).unwrap());
        assert!(!approvals_enabled(Err(std::env::VarError::NotPresent)).unwrap());
        for value in ["true", "yes", "", " 1", "2"] {
            assert!(approvals_enabled(Ok(value.into())).is_err());
        }
        assert!(approvals_enabled(Err(std::env::VarError::NotUnicode("bad".into()))).is_err());
    }
}
