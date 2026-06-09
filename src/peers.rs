// Chain-sourced bootstrap: discover swarm ENTRY peers from the on-chain csd:peers registry
// (via an L2 indexer's /registry/peers resolver) instead of any hardcoded IP. A new node reads
// the peer set from the chain — the chain IS the decentralized bootnode list — and dials a few.
// We are just ONE registered entry among many; as others run nodes and register, the entry set
// grows and no single host is load-bearing. Connecting to a bad/dead peer is harmless (libp2p
// just fails the dial), and bytes are always sha256-verified regardless of who we talk to.
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct RankedPeer {
    peer_id: String,
    #[serde(default)]
    multiaddrs: Vec<String>,
}

/// Fetch dialable multiaddrs (`<multiaddr>/p2p/<peer_id>`) from an L2 indexer's /registry/peers,
/// skipping our own peer id. Errors/empty → empty list (env CSD_P2P_BOOTSTRAP still applies).
pub async fn discover(
    client: &reqwest::Client,
    indexer_base: &str,
    self_peer_id: &str,
) -> Vec<libp2p::Multiaddr> {
    if indexer_base.is_empty() {
        return Vec::new();
    }
    let url = format!("{}/registry/peers", indexer_base.trim_end_matches('/'));
    let peers: Vec<RankedPeer> = match client.get(&url).send().await {
        Ok(r) if r.status().is_success() => r.json().await.unwrap_or_default(),
        _ => return Vec::new(),
    };
    let mut out = Vec::new();
    for p in peers {
        if p.peer_id == self_peer_id || p.peer_id.is_empty() {
            continue; // don't dial ourselves
        }
        for ma in &p.multiaddrs {
            // append /p2p/<peer_id> if the multiaddr doesn't already carry it
            let full = if ma.contains("/p2p/") {
                ma.clone()
            } else {
                format!("{}/p2p/{}", ma.trim_end_matches('/'), p.peer_id)
            };
            if let Ok(addr) = full.parse::<libp2p::Multiaddr>() {
                out.push(addr);
            }
        }
    }
    out
}
