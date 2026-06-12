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
//   CSD_MAX_STORE_BYTES total store budget  (default 10 GiB; 0 = unlimited) — disk-fill guard
//   CSD_CONFIRMATIONS confirm depth         (default 3)
//   CSD_POLL_SECS    ingest poll interval   (default 30)
//   CSD_ADMIN_TOKEN  enable takedown HTTP API (default off) — DELETE /content/:hash, /admin/*
//   CSD_FOLLOW_URI_HINTS  follow attacker-supplied on-chain uri hints (default 0 = off; IP-privacy)
//   CSD_GATEWAY_MAX_CONNS  max concurrent content reads (default 64) — RAM/IO DoS guard
//
// OPERATOR SAFETY: the bytes are attacker-chosen. This node will only fetch/store/serve content
// that is NOT on the operator denylist, refuses to exceed the store budget, and (by default) does
// NOT chase attacker-supplied uri hints. To take content down: `DELETE /content/0x<hash>` with the
// admin token — it purges the blob AND blocks re-download (the chain still references it, so a
// plain `rm` would be re-fetched within one poll).
use csd_swarm::acquire::{acquire, candidate_urls};
use csd_swarm::chain::Chain;
use csd_swarm::gateway::{router, GwState};
use csd_swarm::p2p::{self, Cmd};
use csd_swarm::store::Store;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

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
    // optional L2 indexer for L3 gateway discovery (no hardcoded gateway URLs)
    let indexer = env("CSD_INDEXER", "");
    let listen = env("CSD_SWARM_LISTEN", "127.0.0.1:8791");
    let store_dir = env("CSD_SWARM_STORE", "./swarm-store");
    let max_bytes: usize = env("CSD_MAX_OBJECT", "2097152")
        .parse()
        .unwrap_or(2 * 1024 * 1024);
    let confirmations: u64 = env("CSD_CONFIRMATIONS", "3").parse().unwrap_or(3);
    // Proposals requested PER PAGE per domain (the node caps a page at 500). confirmed_pins
    // pages through ?offset= until a short page, so a domain with >500 proposals is fully
    // covered on a pagination-capable node; against an old node (no `total` in the response)
    // it keeps the loud single-page truncation warning. (E1)
    let per_domain: u32 = env("CSD_PER_DOMAIN", "500").parse().unwrap_or(500);
    let poll = Duration::from_secs(env("CSD_POLL_SECS", "30").parse().unwrap_or(30));
    // total-store disk-fill guard (default 10 GiB; 0 = unlimited)
    let store_cap: u64 = env("CSD_MAX_STORE_BYTES", "10737418240")
        .parse()
        .unwrap_or(10 * 1024 * 1024 * 1024);
    // takedown HTTP API is OFF unless the operator sets a token
    let admin_token = match env("CSD_ADMIN_TOKEN", "") {
        s if s.is_empty() => None,
        s => Some(s),
    };
    // attacker-supplied on-chain `uri` hints are NOT followed by default (the origin is always used)
    let follow_uri_hints = matches!(
        env("CSD_FOLLOW_URI_HINTS", "0").as_str(),
        "1" | "true" | "yes"
    );
    let gw_max_conns: usize = env("CSD_GATEWAY_MAX_CONNS", "64").parse().unwrap_or(64);
    let p2p_listen = env("CSD_P2P_LISTEN", "/ip4/0.0.0.0/tcp/0");
    // persisted libp2p identity (stable PeerId across restarts). Default lives in the store dir;
    // set CSD_P2P_IDENTITY=- to opt out (ephemeral identity each start).
    let identity_path = match env("CSD_P2P_IDENTITY", "") {
        s if s == "-" => None,
        s if s.is_empty() => Some(std::path::PathBuf::from(&store_dir).join("p2p-identity.key")),
        s => Some(std::path::PathBuf::from(s)),
    };
    let bootstrap: Vec<String> = env("CSD_P2P_BOOTSTRAP", "")
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // Custom redirect policy: cap at 3 hops AND refuse to follow a redirect to a non-public host
    // (a public `uri` hint could otherwise 3xx inward to 169.254.169.254 / localhost — SSRF).
    let redirect_policy = reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= 3 {
            return attempt.error("too many redirects");
        }
        if csd_swarm::acquire::host_is_public(attempt.url().as_str()) {
            attempt.follow()
        } else {
            attempt.stop()
        }
    });
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .redirect(redirect_policy)
        .build()?;
    let store = Store::open(&store_dir).await?.with_max_bytes(store_cap);
    let chain = Chain::new(rpc.clone(), client.clone());

    tracing::info!(%rpc, %origin, %listen, store=%store_dir, max_bytes, store_cap, follow_uri_hints, admin_api=admin_token.is_some(), confirmations, "csd-swarm starting ({} pinned, {} denied)", store.count().await, store.denied_count().await);
    if store_cap == 0 {
        tracing::warn!("CSD_MAX_STORE_BYTES=0 (unlimited) — an attacker paying propose fees can fill this disk; set a budget");
    }
    if admin_token.is_none() {
        tracing::warn!("CSD_ADMIN_TOKEN unset — the takedown API (DELETE /content/:hash) is DISABLED; you cannot remove abusive content over HTTP");
    }

    // our own libp2p PeerId (to self-exclude from chain-discovered peer dials + fill our record)
    let self_peer_id = identity_path
        .as_ref()
        .and_then(|p| csd_swarm::p2p::peer_id_at(p))
        .unwrap_or_default();

    // ── p2p task: serve Have/Get + announce held hashes + satisfy Want from peers ──
    let (cmd_tx, cmd_rx) = mpsc::channel::<Cmd>(64);
    let peer_status = csd_swarm::p2p::new_peer_status();
    {
        let store = store.clone();
        let listen_ma = p2p_listen
            .parse()
            .expect("CSD_P2P_LISTEN must be a multiaddr");
        // entry peers = explicit env bootstrap + chain-sourced (csd:peers via the indexer), so a
        // node can join by reading the chain instead of hardcoding any IP.
        let mut boot: Vec<libp2p::Multiaddr> = bootstrap.iter().filter_map(|s| s.parse().ok()).collect();
        boot.extend(csd_swarm::peers::discover(&client, &indexer, &self_peer_id).await);
        tracing::info!(entry_peers = boot.len(), "p2p bootstrap set (env + chain csd:peers)");
        let id_path = identity_path.clone();
        let peer_status = peer_status.clone();
        tokio::spawn(async move {
            if let Err(e) = p2p::run(store, listen_ma, boot, max_bytes, cmd_rx, None, id_path, peer_status).await
            {
                tracing::error!("p2p task exited: {e}");
            }
        });
    }

    // ── ingest loop: pin every confirmed Propose payload, acquiring+verifying what we lack ──
    {
        let store = store.clone();
        let client = client.clone();
        let origin = origin.clone();
        let indexer = indexer.clone();
        let cmd_tx = cmd_tx.clone();
        let self_peer_id = self_peer_id.clone();
        tokio::spawn(async move {
            loop {
                // L3: refresh chain-discovered gateways each pass (no hardcoded URLs)
                let gw_templates = if indexer.is_empty() {
                    Vec::new()
                } else {
                    csd_swarm::gateways::discover(&client, &indexer).await
                };
                // Re-discover entry peers from the on-chain csd:peers registry each pass and (re)dial
                // them — so the mesh tracks the chain's peer set over time (no hardcoded IPs). Dialing
                // an already-connected peer is a cheap no-op.
                for addr in csd_swarm::peers::discover(&client, &indexer, &self_peer_id).await {
                    let _ = cmd_tx.send(Cmd::Dial(addr)).await;
                }
                match chain.confirmed_pins(confirmations, per_domain).await {
                    Ok(pins) => {
                        let (mut fetched, mut from_peer, mut failed, mut held) =
                            (0u64, 0u64, 0u64, 0u64);
                        for p in &pins {
                            // operator denylist: never fetch/store content the operator refused
                            if store.is_denied(&p.payload_hash).await {
                                continue;
                            }
                            if store.has(&p.payload_hash).await.is_some() {
                                held += 1;
                                continue;
                            }
                            // 1) try the content origin + any chain-discovered gateways
                            //    (all verified in acquire — gateways are untrusted transports)
                            let mut urls =
                                candidate_urls(&origin, &p.payload_hash, &p.uri, follow_uri_hints);
                            urls.extend(csd_swarm::gateways::expand(
                                &gw_templates,
                                &p.payload_hash,
                            ));
                            let mut bytes = acquire(&client, &p.payload_hash, &urls, max_bytes)
                                .await
                                .ok();
                            let mut via_peer = false;
                            // 2) origin miss → ask peers (p2p verifies sha256 before returning)
                            if bytes.is_none() {
                                let (tx, rx) = oneshot::channel();
                                if cmd_tx
                                    .send(Cmd::Want(p.payload_hash.clone(), tx))
                                    .await
                                    .is_ok()
                                {
                                    if let Ok(Some(b)) = rx.await {
                                        bytes = Some(b);
                                        via_peer = true;
                                    }
                                }
                            }
                            match bytes {
                                Some(b) => match store.put(&p.payload_hash, &b).await {
                                    Ok(()) => {
                                        if via_peer {
                                            from_peer += 1;
                                        } else {
                                            fetched += 1;
                                        }
                                        tracing::info!(hash=%p.payload_hash, len=b.len(), via_peer, "pinned");
                                    }
                                    Err(e) => {
                                        failed += 1;
                                        tracing::warn!(hash=%p.payload_hash, "store failed: {e}");
                                    }
                                },
                                None => {
                                    failed += 1;
                                    tracing::debug!(hash=%p.payload_hash, "unavailable (origin + peers)");
                                }
                            }
                        }
                        tracing::info!(
                            pins = pins.len(),
                            held,
                            fetched,
                            from_peer,
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
    let app = router(GwState {
        store,
        max_bytes,
        admin_token,
        conns: std::sync::Arc::new(tokio::sync::Semaphore::new(gw_max_conns)),
        peers: peer_status,
    });
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    tracing::info!("gateway on http://{listen}  (GET /content/0x<hash> · /pins · /health)");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
