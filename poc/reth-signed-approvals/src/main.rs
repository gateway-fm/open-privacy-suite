mod approvals;
mod batch;
mod call_hash;
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
use std::{sync::Arc, time::Duration};

fn main() -> eyre::Result<()> {
    if std::env::args().nth(1).as_deref() == Some("fingerprint") {
        let value: serde_json::Value = serde_json::from_reader(std::io::stdin())?;
        let hash = fingerprint::fingerprint(&value["calls"], &value["pre"], &value["diff"])
            .map_err(|e| eyre::eyre!(e))?;
        println!("{hash}");
        return Ok(());
    }
    let enabled = std::env::var("OPS_APPROVALS").as_deref() == Ok("1");
    Cli::parse_args().run(async move |builder, _| {
        let store = if enabled {
            let wait = std::env::var("OPS_APPROVAL_WAIT_MS")
                .unwrap_or("5000".into())
                .parse()?;
            let capacity = std::env::var("OPS_APPROVAL_CAPACITY")
                .unwrap_or("100000".into())
                .parse()?;
            let store = Arc::new(approvals::Store::new(Duration::from_millis(wait), capacity));
            let key = alloy_primitives::hex::decode(std::env::var("OPS_APPROVAL_PUBLIC_KEY")?)?;
            let key = ed25519_dalek::VerifyingKey::from_bytes(key.as_slice().try_into()?)?;
            let chain = std::env::var("OPS_APPROVAL_CHAIN_ID")?.parse()?;
            let listener =
                tokio::net::TcpListener::bind(std::env::var("OPS_APPROVAL_LISTEN")?).await?;
            let workers = std::env::var("OPS_APPROVAL_VERIFY_WORKERS")
                .unwrap_or("2".into())
                .parse()?;
            let capacity = std::env::var("OPS_APPROVAL_VERIFY_QUEUE_BATCHES")
                .unwrap_or("64".into())
                .parse()?;
            let verifier = verification::Verifier::new(
                store.clone(),
                key,
                chain,
                workers,
                capacity,
                std::env::var("OPS_APPROVAL_INGRESS_MODE").as_deref() != Ok("queued"),
            )?;
            tokio::spawn(approvals::serve(listener, store.clone(), verifier));
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
