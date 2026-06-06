// Peer-to-peer replication over libp2p, so content survives the origin going offline.
// A 2-verb request-response protocol — Have(hash)->{has,len}, Get(hash)->Option<bytes> — plus
// gossipsub announcements of held hashes (who-has). When the origin can't serve a hash, the
// ingest loop asks peers; bytes are VERIFIED (sha256==hash) here before they're handed back, so
// a malicious peer cannot poison us. (rust-libp2p: tcp+noise+yamux, the stack the CSD node runs.)
use crate::acquire::sha256_hex;
use crate::store::Store;
use anyhow::Result;
use futures_util::StreamExt;
use libp2p::{
    gossipsub, identify, ping, request_response,
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

/// A request from the rest of the node to the p2p task: "try to fetch `hash` from peers".
pub enum Cmd {
    Want(String, oneshot::Sender<Option<Vec<u8>>>),
}

/// In-flight outbound Get requests: request id → (wanted hash, where to deliver verified bytes).
type Pending =
    HashMap<request_response::OutboundRequestId, (String, oneshot::Sender<Option<Vec<u8>>>)>;

#[derive(NetworkBehaviour)]
struct Behaviour {
    rr: request_response::cbor::Behaviour<Req, Resp>,
    gossipsub: gossipsub::Behaviour,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
}

fn norm(hash: &str) -> String {
    hash.strip_prefix("0x").unwrap_or(hash).to_lowercase()
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
pub async fn run(
    store: Store,
    listen: Multiaddr,
    bootstrap: Vec<Multiaddr>,
    max_bytes: usize,
    mut cmd_rx: mpsc::Receiver<Cmd>,
    mut listen_report: Option<oneshot::Sender<Multiaddr>>,
) -> Result<()> {
    let mut swarm = libp2p::SwarmBuilder::with_new_identity()
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
            let rr = request_response::cbor::Behaviour::<Req, Resp>::new(
                [(StreamProtocol::new(PROTO), ProtocolSupport::Full)],
                request_response::Config::default(),
            );
            let identify =
                identify::Behaviour::new(identify::Config::new(PROTO.into(), key.public()));
            Ok(Behaviour {
                rr,
                gossipsub,
                identify,
                ping: ping::Behaviour::default(),
            })
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(120)))
        .build();

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

    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                let Some(Cmd::Want(hash, reply)) = cmd else { break Ok(()); };
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
            _ = announce.tick() => {
                let held = store.list().await;
                publish_held(&mut swarm, &topic, &held);
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    tracing::info!("p2p listening on {address}");
                    if let Some(tx) = listen_report.take() { let _ = tx.send(address); }
                }
                // a new peer connected → announce what we hold right away (don't wait for the tick)
                SwarmEvent::ConnectionEstablished { .. } => {
                    let held = store.list().await;
                    publish_held(&mut swarm, &topic, &held);
                }
                SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message { message, .. })) => {
                    if let Some(src) = message.source {
                        for line in String::from_utf8_lossy(&message.data).lines() {
                            let h = norm(line);
                            if h.len() == 64 { providers.entry(h).or_default().insert(src); }
                        }
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Rr(request_response::Event::Message { message, .. })) => match message {
                    request_response::Message::Request { request, channel, .. } => {
                        let resp = match request {
                            Req::Have(h) => { let n = norm(&h); Resp::Have { has: store.has(&n).await.is_some(), len: store.has(&n).await.unwrap_or(0) } }
                            Req::Get(h) => Resp::Get(store.get(&norm(&h)).await), // only bytes we hold (verified at store time)
                        };
                        let _ = swarm.behaviour_mut().rr.send_response(channel, resp);
                    }
                    request_response::Message::Response { request_id, response } => {
                        if let Some((want, reply)) = pending.remove(&request_id) {
                            let out = match response {
                                Resp::Get(Some(bytes)) if bytes.len() <= max_bytes && sha256_hex(&bytes) == want => Some(bytes),
                                _ => None, // wrong bytes / oversize / not held → reject (no poisoning)
                            };
                            let _ = reply.send(out);
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
