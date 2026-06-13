// Peer-to-peer replication over libp2p, so content survives the origin going offline.
// A 2-verb request-response protocol — Have(hash)->{has,len}, Get(hash)->Option<bytes> — plus
// gossipsub announcements of held hashes (who-has). When the origin can't serve a hash, the
// ingest loop asks peers; bytes are VERIFIED (sha256==hash) here before they're handed back, so
// a malicious peer cannot poison us. (rust-libp2p: tcp+noise+yamux, the stack the CSD node runs.)
use crate::acquire::sha256_hex;
use crate::store::Store;
use anyhow::Result;
use futures_util::StreamExt;
use libp2p::futures::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use libp2p::{
    connection_limits, gossipsub, identify, ping, request_response,
    request_response::ProtocolSupport,
    swarm::{NetworkBehaviour, SwarmEvent},
    Multiaddr, PeerId, StreamProtocol,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

const PROTO: &str = "/csd-content/1";
const ANNOUNCE_TOPIC: &str = "csd-content/announce/v1";
// Bounds on the gossip-fed providers map (anti-DoS; a peer can't grow it without limit).
const MAX_TRACKED_HASHES: usize = 100_000;
const MAX_PEERS_PER_HASH: usize = 64;

// Anti connection-flood caps on the PUBLIC p2p socket (:8792). Without these, a peer (or the whole
// internet) can open unbounded TCP connections and exhaust our file descriptors / memory — a
// restartable DoS. These ceilings are generous vs. the real swarm size (a handful of peers) but
// hard-cap abuse. Enforced by libp2p's connection_limits behaviour BEFORE handlers are allocated.
const MAX_PENDING_INCOMING: u32 = 32; // half-open inbound handshakes (SYN/noise flood)
const MAX_PENDING_OUTGOING: u32 = 32;
const MAX_ESTABLISHED_PER_PEER: u32 = 4; // one peer can't hog all the slots
const MAX_ESTABLISHED_INCOMING: u32 = 256;
const MAX_ESTABLISHED_OUTGOING: u32 = 128;
const MAX_ESTABLISHED_TOTAL: u32 = 384;

// Max p2p `Get` serves in flight at once (M11 — mirrors the HTTP gateway's read semaphore). Each
// serve buffers up to one max-object from disk, so peak serve memory ≈ this × CSD_MAX_OBJECT.
// Past the budget a Get is answered `None` cheaply (the peer treats it as not-held and moves on).
const MAX_CONCURRENT_SERVES: usize = 16;

/// Live view of currently-connected peers (PeerId → remote multiaddr), shared with the gateway
/// so operators can SEE who's connected (GET /health p2p_peers, GET /p2p). Updated by the p2p
/// task on connect/disconnect.
pub type PeerStatus = std::sync::Arc<tokio::sync::RwLock<HashMap<PeerId, String>>>;
pub fn new_peer_status() -> PeerStatus {
    std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new()))
}

/// Load a persisted ed25519 keypair (so our PeerId is STABLE across restarts), or generate one
/// and save it. Without this the node draws a fresh random identity each start — which breaks
/// bootstrap multiaddrs (`/p2p/<id>`) and stales any `csd:peers` registry announcement that
/// names this peer. The key is the node's network identity, not a wallet key, but still secret:
/// written 0600. `None` path → ephemeral identity (tests / throwaway nodes).
fn load_or_create_identity(path: Option<std::path::PathBuf>) -> Result<libp2p::identity::Keypair> {
    use libp2p::identity::Keypair;
    let Some(path) = path else {
        return Ok(Keypair::generate_ed25519());
    };
    if let Ok(bytes) = std::fs::read(&path) {
        match Keypair::from_protobuf_encoding(&bytes) {
            Ok(kp) => {
                tracing::info!(?path, "loaded persisted p2p identity");
                return Ok(kp);
            }
            Err(e) => tracing::warn!(?path, %e, "p2p identity file unreadable — regenerating"),
        }
    }
    let kp = Keypair::generate_ed25519();
    let enc = kp.to_protobuf_encoding()?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // Create with 0600 ATOMICALLY (O_CREAT|O_EXCL + mode) so the private identity is never briefly
    // world-readable between write and chmod. Exclusive create also avoids clobbering a key that
    // appeared concurrently.
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        f.write_all(&enc)?;
    }
    #[cfg(not(unix))]
    std::fs::write(&path, &enc)?;
    tracing::info!(?path, "generated + persisted new p2p identity");
    Ok(kp)
}

/// Read the PeerId of a persisted identity file WITHOUT creating one. Used by the binary to
/// self-exclude from chain-discovered peer dials and to fill its own csd:peers announcement.
pub fn peer_id_at(path: &std::path::Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let kp = libp2p::identity::Keypair::from_protobuf_encoding(&bytes).ok()?;
    Some(PeerId::from(kp.public()).to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Req {
    Have(String),
    Get(String),
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Resp {
    Have { has: bool, len: u64 },
    Get(Option<Vec<u8>>),
}

// Transport ceilings for the request-response codec. Requests are tiny (a Have/Get of one hash);
// a response carries at most one object, so its ceiling is CSD_MAX_OBJECT plus slack for the cbor
// envelope (enum tag + byte-string header) — NOT the stock codec's 10 MiB.
const P2P_MAX_REQUEST: u64 = 64 * 1024;
const P2P_RESPONSE_SLACK: u64 = 64 * 1024;

/// cbor codec with an EXPLICIT response-size ceiling tied to `CSD_MAX_OBJECT` (L11). The stock
/// `request_response::cbor` codec hard-codes `RESPONSE_SIZE_MAXIMUM = 10 MiB`, so a lying peer
/// could make us buffer 5x more than the 2 MiB object cap before `accept_get()` even ran. This
/// codec is wire-compatible with the stock one (same cbor4ii serde encoding, same EOF framing) —
/// only the read ceilings differ.
#[derive(Clone)]
struct CappedCbor {
    /// max bytes read for one response = CSD_MAX_OBJECT + P2P_RESPONSE_SLACK
    max_response: u64,
}

#[async_trait::async_trait]
impl request_response::Codec for CappedCbor {
    type Protocol = StreamProtocol;
    type Request = Req;
    type Response = Resp;

    async fn read_request<T>(&mut self, _: &StreamProtocol, io: &mut T) -> std::io::Result<Req>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut vec = Vec::new();
        io.take(P2P_MAX_REQUEST).read_to_end(&mut vec).await?;
        cbor4ii::serde::from_slice(vec.as_slice())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{e:?}")))
    }

    async fn read_response<T>(&mut self, _: &StreamProtocol, io: &mut T) -> std::io::Result<Resp>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut vec = Vec::new();
        io.take(self.max_response).read_to_end(&mut vec).await?;
        cbor4ii::serde::from_slice(vec.as_slice())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{e:?}")))
    }

    async fn write_request<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        req: Req,
    ) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let data = cbor4ii::serde::to_vec(Vec::new(), &req)
            .map_err(|e| std::io::Error::other(format!("{e:?}")))?;
        io.write_all(&data).await
    }

    async fn write_response<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        resp: Resp,
    ) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let data = cbor4ii::serde::to_vec(Vec::new(), &resp)
            .map_err(|e| std::io::Error::other(format!("{e:?}")))?;
        io.write_all(&data).await
    }
}

/// A request from the rest of the node to the p2p task.
pub enum Cmd {
    /// "try to fetch `hash` from peers".
    Want(String, oneshot::Sender<Option<Vec<u8>>>),
    /// "dial this peer" — used for chain-sourced bootstrap (entry peers read from csd:peers).
    Dial(Multiaddr),
}

/// In-flight outbound Get requests: request id → (wanted hash, where to deliver verified bytes).
type Pending =
    HashMap<request_response::OutboundRequestId, (String, oneshot::Sender<Option<Vec<u8>>>)>;

#[derive(NetworkBehaviour)]
struct Behaviour {
    // FIRST so connection limits are checked before any other behaviour allocates a handler.
    connection_limits: connection_limits::Behaviour,
    rr: request_response::Behaviour<CappedCbor>,
    gossipsub: gossipsub::Behaviour,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
}

fn norm(hash: &str) -> String {
    hash.strip_prefix("0x").unwrap_or(hash).to_lowercase()
}

/// The anti-poisoning gate for peer-served bytes: accept a Get response ONLY if it carries bytes
/// that are within the size cap AND whose sha256 equals the hash we asked for. A peer that lies
/// (wrong bytes, oversized, or doesn't actually hold it) gets rejected — it can never poison us.
/// (The wire is capped too: `CappedCbor` stops reading a response past CSD_MAX_OBJECT + slack,
/// so an oversized body never gets buffered up to the stock codec's 10 MiB before this check.)
pub fn accept_get(want_hash: &str, resp: Resp, max_bytes: usize) -> Option<Vec<u8>> {
    let want = norm(want_hash);
    match resp {
        Resp::Get(Some(bytes)) if bytes.len() <= max_bytes && sha256_hex(&bytes) == want => {
            Some(bytes)
        }
        _ => None,
    }
}

/// Announce the hashes we hold over gossipsub (newline-joined hex) so peers learn who-has.
fn publish_held(
    swarm: &mut libp2p::Swarm<Behaviour>,
    topic: &gossipsub::IdentTopic,
    held: &[(String, u64)],
) {
    if held.is_empty() {
        return;
    }
    let body = held
        .iter()
        .map(|(h, _)| norm(h))
        .collect::<Vec<_>>()
        .join("\n");
    let _ = swarm
        .behaviour_mut()
        .gossipsub
        .publish(topic.clone(), body.into_bytes());
}

/// Run the p2p task: listen, dial bootstrap peers, announce held hashes, serve Have/Get, and
/// satisfy `Want` commands from peers (verifying bytes before returning them).
#[allow(clippy::too_many_arguments)] // wiring all the loop's collaborators in one place is clearer than a config struct
pub async fn run(
    store: Store,
    listen: Multiaddr,
    bootstrap: Vec<Multiaddr>,
    max_bytes: usize,
    mut cmd_rx: mpsc::Receiver<Cmd>,
    mut listen_report: Option<oneshot::Sender<Multiaddr>>,
    identity_path: Option<std::path::PathBuf>,
    peer_status: PeerStatus,
) -> Result<()> {
    let keypair = load_or_create_identity(identity_path)?;
    let local_peer_id = PeerId::from(keypair.public());
    tracing::info!(peer_id=%local_peer_id, "p2p local identity (use in csd:peers as /p2p/<this>)");
    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_behaviour(|key| {
            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub::Config::default(),
            )
            .map_err(|e| std::io::Error::other(e.to_string()))?;
            // explicit codec ceilings: a response can never make us buffer past the object cap
            // (+ envelope slack) — the stock cbor codec would have allowed 10 MiB (L11)
            let rr = request_response::Behaviour::with_codec(
                CappedCbor {
                    max_response: max_bytes as u64 + P2P_RESPONSE_SLACK,
                },
                [(StreamProtocol::new(PROTO), ProtocolSupport::Full)],
                request_response::Config::default(),
            );
            let identify =
                identify::Behaviour::new(identify::Config::new(PROTO.into(), key.public()));
            let connection_limits = connection_limits::Behaviour::new(
                connection_limits::ConnectionLimits::default()
                    .with_max_pending_incoming(Some(MAX_PENDING_INCOMING))
                    .with_max_pending_outgoing(Some(MAX_PENDING_OUTGOING))
                    .with_max_established_per_peer(Some(MAX_ESTABLISHED_PER_PEER))
                    .with_max_established_incoming(Some(MAX_ESTABLISHED_INCOMING))
                    .with_max_established_outgoing(Some(MAX_ESTABLISHED_OUTGOING))
                    .with_max_established(Some(MAX_ESTABLISHED_TOTAL)),
            );
            Ok(Behaviour {
                connection_limits,
                rr,
                gossipsub,
                identify,
                ping: ping::Behaviour::default(),
            })
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(120)))
        .build();
    tracing::info!(
        max_established = MAX_ESTABLISHED_TOTAL,
        max_incoming = MAX_ESTABLISHED_INCOMING,
        per_peer = MAX_ESTABLISHED_PER_PEER,
        pending_incoming = MAX_PENDING_INCOMING,
        "p2p connection limits active (anti connection-flood DoS)"
    );

    let topic = gossipsub::IdentTopic::new(ANNOUNCE_TOPIC);
    swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
    swarm.listen_on(listen)?;
    for addr in bootstrap {
        if let Err(e) = swarm.dial(addr.clone()) {
            tracing::warn!("dial {addr} failed: {e}");
        }
    }

    let mut providers: HashMap<String, HashSet<PeerId>> = HashMap::new();
    let mut pending: Pending = HashMap::new();
    let mut announce = tokio::time::interval(Duration::from_secs(20));

    // M11: bound concurrent p2p Get serves AND do the disk read in a spawned task, so an
    // unauthenticated Get flood can never monopolize this select! loop (which also drives
    // gossip/dials/replication). Finished reads come back through `serve_rx` to be answered
    // here — send_response needs `&mut swarm`, which only this task holds.
    let serve_permits = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SERVES));
    let (serve_tx, mut serve_rx) =
        mpsc::channel::<(request_response::ResponseChannel<Resp>, Resp)>(MAX_CONCURRENT_SERVES);

    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(Cmd::Want(hash, reply)) => {
                        let h = norm(&hash);
                        let peer = providers.get(&h).and_then(|s| s.iter().next().copied());
                        match peer {
                            Some(p) => {
                                let rid = swarm.behaviour_mut().rr.send_request(&p, Req::Get(format!("0x{h}")));
                                pending.insert(rid, (h, reply));
                            }
                            None => { let _ = reply.send(None); } // no known provider yet; caller retries next poll
                        }
                    }
                    // chain-sourced bootstrap: dial an entry peer discovered from csd:peers. Dialing
                    // an already-connected/self peer is a cheap no-op, so periodic re-dials are safe.
                    Some(Cmd::Dial(addr)) => {
                        if let Err(e) = swarm.dial(addr.clone()) { tracing::debug!("chain-peer dial {addr} failed: {e}"); }
                    }
                    None => break Ok(()),
                }
            }
            _ = announce.tick() => {
                let held = store.list().await;
                publish_held(&mut swarm, &topic, &held);
            }
            // a spawned Get serve finished → answer it (M11; serve_tx lives in this scope, so
            // recv() never yields None while the loop runs)
            Some((channel, resp)) = serve_rx.recv() => {
                let _ = swarm.behaviour_mut().rr.send_response(channel, resp);
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    tracing::info!("p2p listening on {address}");
                    if let Some(tx) = listen_report.take() { let _ = tx.send(address); }
                }
                // a new peer connected → record it (monitoring) + announce what we hold right away
                SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                    peer_status.write().await.insert(peer_id, endpoint.get_remote_address().to_string());
                    tracing::info!(%peer_id, addr=%endpoint.get_remote_address(), "peer connected");
                    let held = store.list().await;
                    publish_held(&mut swarm, &topic, &held);
                }
                SwarmEvent::ConnectionClosed { peer_id, num_established, .. } => {
                    // only forget the peer when its LAST connection closes
                    if num_established == 0 {
                        peer_status.write().await.remove(&peer_id);
                        tracing::info!(%peer_id, "peer disconnected");
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message { message, .. })) => {
                    if let Some(src) = message.source {
                        for line in String::from_utf8_lossy(&message.data).lines() {
                            let h = norm(line);
                            // Bound the providers map: a malicious peer can otherwise gossip
                            // unlimited fake hashes and grow it without limit (OOM DoS). Require
                            // valid 64-hex, cap total tracked hashes, and cap peers-per-hash.
                            let valid = h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit());
                            if !valid { continue; }
                            if providers.contains_key(&h) || providers.len() < MAX_TRACKED_HASHES {
                                let set = providers.entry(h).or_default();
                                if set.len() < MAX_PEERS_PER_HASH { set.insert(src); }
                            }
                        }
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Rr(request_response::Event::Message { message, .. })) => match message {
                    request_response::Message::Request { request, channel, .. } => match request {
                        Req::Have(h) => {
                            let n = norm(&h);
                            let has = !store.is_denied(&n).await && store.has(&n).await.is_some();
                            let len = if has { store.has(&n).await.unwrap_or(0) } else { 0 };
                            let _ = swarm.behaviour_mut().rr.send_response(channel, Resp::Have { has, len });
                        }
                        // serve only bytes we hold that aren't on the operator denylist — so a
                        // takedown also stops peer replication. The store holds ONLY verified bytes
                        // (sha256 checked before every put; see store.rs), so no per-Get recompute.
                        // Bounded + off-loop (M11): past the permit budget a Get is refused with
                        // None instead of queueing disk reads on the event loop.
                        Req::Get(h) => {
                            let n = norm(&h);
                            match serve_permits.clone().try_acquire_owned() {
                                Ok(permit) => {
                                    let store = store.clone();
                                    let tx = serve_tx.clone();
                                    tokio::spawn(async move {
                                        let body = if store.is_denied(&n).await { None } else { store.get(&n).await };
                                        let _ = tx.send((channel, Resp::Get(body))).await;
                                        drop(permit); // released only after the response is handed back
                                    });
                                }
                                Err(_) => { let _ = swarm.behaviour_mut().rr.send_response(channel, Resp::Get(None)); }
                            }
                        }
                    },
                    request_response::Message::Response { request_id, response } => {
                        if let Some((want, reply)) = pending.remove(&request_id) {
                            let _ = reply.send(accept_get(&want, response, max_bytes));
                        }
                    }
                },
                SwarmEvent::Behaviour(BehaviourEvent::Rr(request_response::Event::OutboundFailure { request_id, .. })) => {
                    if let Some((_, reply)) = pending.remove(&request_id) { let _ = reply.send(None); }
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const GOOD: &[u8] = b"{\"v\":1}";
    #[test]
    fn accept_get_is_the_anti_poisoning_gate() {
        let h = sha256_hex(GOOD);
        // correct, in-size bytes → accepted (0x-prefixed want also works)
        assert_eq!(
            accept_get(&h, Resp::Get(Some(GOOD.to_vec())), 1 << 20),
            Some(GOOD.to_vec())
        );
        assert_eq!(
            accept_get(&format!("0x{h}"), Resp::Get(Some(GOOD.to_vec())), 1 << 20),
            Some(GOOD.to_vec())
        );
        // a LYING peer: wrong bytes for the requested hash → rejected
        assert_eq!(
            accept_get(&h, Resp::Get(Some(b"TAMPERED".to_vec())), 1 << 20),
            None
        );
        // oversized → rejected
        assert_eq!(accept_get(&h, Resp::Get(Some(GOOD.to_vec())), 3), None);
        // peer doesn't hold it / wrong variant → rejected
        assert_eq!(accept_get(&h, Resp::Get(None), 1 << 20), None);
        assert_eq!(
            accept_get(&h, Resp::Have { has: true, len: 9 }, 1 << 20),
            None
        );
    }
}
