// csd-swarm — Compute Substrate content swarm node (L1).
//
// Follows the chain (the allowlist), acquires each confirmed Propose payload's bytes from a
// content origin, VERIFIES sha256(bytes)==payload_hash, stores them content-addressed, and
// re-serves them over an HTTP gateway (IPFS Trustless-Gateway contract). Self-certifying end to
// end: the origin/gateway are untrusted transports; bytes are only ever stored/served if they
// hash to the on-chain commitment. Replication, not permanence (see the roadmap's honest limits).
//
// Config (env):
//   CSD_RPC         node RPC base           (default http://127.0.0.1:8790)
//   CSD_ORIGIN      content origin base     (default http://127.0.0.1:7777)  → GET {origin}/content/0x<hash>
//   CSD_SWARM_LISTEN gateway bind           (default 127.0.0.1:8791)
//   CSD_SWARM_STORE  blob store dir         (default ./swarm-store)
//   CSD_MAX_OBJECT   max object bytes       (default 2097152 = 2 MiB)
//   CSD_CONFIRMATIONS confirm depth         (default 3)
//   CSD_POLL_SECS    ingest poll interval   (default 30)
use csd_swarm::acquire::{acquire, candidate_urls};
use csd_swarm::chain::Chain;
use csd_swarm::gateway::{router, GwState};
use csd_swarm::store::Store;
use std::time::Duration;

fn env(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(env("RUST_LOG", "info,csd_swarm=info"))
        .init();

    let rpc = env("CSD_RPC", "http://127.0.0.1:8790");
    let origin = env("CSD_ORIGIN", "http://127.0.0.1:7777");
    let listen = env("CSD_SWARM_LISTEN", "127.0.0.1:8791");
    let store_dir = env("CSD_SWARM_STORE", "./swarm-store");
    let max_bytes: usize = env("CSD_MAX_OBJECT", "2097152")
        .parse()
        .unwrap_or(2 * 1024 * 1024);
    let confirmations: u64 = env("CSD_CONFIRMATIONS", "3").parse().unwrap_or(3);
    let poll = Duration::from_secs(env("CSD_POLL_SECS", "30").parse().unwrap_or(30));

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()?;
    let store = Store::open(&store_dir).await?;
    let chain = Chain::new(rpc.clone(), client.clone());

    tracing::info!(%rpc, %origin, %listen, store=%store_dir, max_bytes, confirmations, "csd-swarm starting ({} already pinned)", store.count().await);

    // ── ingest loop: pin every confirmed Propose payload, acquiring+verifying what we lack ──
    {
        let store = store.clone();
        let client = client.clone();
        let origin = origin.clone();
        tokio::spawn(async move {
            loop {
                match chain.confirmed_pins(confirmations, 200).await {
                    Ok(pins) => {
                        let (mut fetched, mut failed, mut held) = (0u64, 0u64, 0u64);
                        for p in &pins {
                            if store.has(&p.payload_hash).await.is_some() {
                                held += 1;
                                continue;
                            }
                            let urls = candidate_urls(&origin, &p.payload_hash, &p.uri);
                            match acquire(&client, &p.payload_hash, &urls, max_bytes).await {
                                Ok(bytes) => match store.put(&p.payload_hash, &bytes).await {
                                    Ok(()) => {
                                        fetched += 1;
                                        tracing::info!(hash=%p.payload_hash, len=bytes.len(), "pinned");
                                    }
                                    Err(e) => {
                                        failed += 1;
                                        tracing::warn!(hash=%p.payload_hash, "store failed: {e}");
                                    }
                                },
                                Err(e) => {
                                    failed += 1;
                                    tracing::debug!(hash=%p.payload_hash, "acquire failed: {e}");
                                }
                            }
                        }
                        tracing::info!(
                            pins = pins.len(),
                            held,
                            fetched,
                            failed,
                            "ingest pass complete"
                        );
                    }
                    Err(e) => tracing::warn!("ingest poll failed: {e}"),
                }
                tokio::time::sleep(poll).await;
            }
        });
    }

    // ── gateway ──
    let app = router(GwState { store, max_bytes });
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    tracing::info!("gateway on http://{listen}  (GET /content/0x<hash> · /pins · /health)");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
