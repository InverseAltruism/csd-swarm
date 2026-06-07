// Peer replication: TWO real libp2p nodes over loopback. Node A holds content; node B has an
// EMPTY store and NO origin — it discovers A via bootstrap (gossipsub who-has) and fetches the
// bytes peer-to-peer, VERIFIED. Proves the swarm is origin-optional and that a peer cannot
// poison a fetch (B independently re-hashes). The strong P2.3 gate.
use csd_swarm::acquire::sha256_hex;
use csd_swarm::p2p::{self, Cmd};
use csd_swarm::store::Store;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

const GOOD: &[u8] = b"{\"body\":\"peer-replicated\",\"v\":1}";

#[tokio::test]
async fn node_b_fetches_from_node_a_without_an_origin() {
    let h = sha256_hex(GOOD);

    // Node A: holds the content
    let dir_a = tempfile::tempdir().unwrap();
    let store_a = Store::open(dir_a.path()).await.unwrap();
    store_a.put(&h, GOOD).await.unwrap();
    let (_cmd_a_tx, cmd_a_rx) = mpsc::channel::<Cmd>(8);
    let (laddr_tx, laddr_rx) = oneshot::channel();
    tokio::spawn(async move {
        let _ = p2p::run(
            store_a,
            "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            vec![],
            1 << 20,
            cmd_a_rx,
            Some(laddr_tx),
            None,
        )
        .await;
    });
    let a_addr = tokio::time::timeout(Duration::from_secs(5), laddr_rx)
        .await
        .expect("A should report a listen addr")
        .unwrap();

    // Node B: empty store, NO origin, bootstraps to A
    let dir_b = tempfile::tempdir().unwrap();
    let store_b = Store::open(dir_b.path()).await.unwrap();
    assert!(store_b.has(&h).await.is_none());
    let (cmd_b_tx, cmd_b_rx) = mpsc::channel::<Cmd>(8);
    {
        let store_b = store_b.clone();
        tokio::spawn(async move {
            let _ = p2p::run(
                store_b,
                "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
                vec![a_addr],
                1 << 20,
                cmd_b_rx,
                None,
                None,
            )
            .await;
        });
    }

    // B asks peers for the hash; retry while the gossipsub mesh forms + A's announce propagates
    let mut got: Option<Vec<u8>> = None;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let (tx, rx) = oneshot::channel();
        if cmd_b_tx
            .send(Cmd::Want(format!("0x{h}"), tx))
            .await
            .is_err()
        {
            break;
        }
        if let Ok(Some(bytes)) = rx.await {
            got = Some(bytes);
            break;
        }
    }
    assert_eq!(
        got.as_deref(),
        Some(GOOD),
        "node B should fetch the verified bytes from A peer-to-peer"
    );
    // and the fetched bytes self-certify
    assert_eq!(sha256_hex(got.as_ref().unwrap()), h);
}

#[tokio::test]
async fn want_for_an_unknown_hash_returns_none() {
    // a lone node with no peers/providers must answer None (never hang) for an unknown hash
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let (cmd_tx, cmd_rx) = mpsc::channel::<Cmd>(8);
    tokio::spawn(async move {
        let _ = p2p::run(
            store,
            "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            vec![],
            1 << 20,
            cmd_rx,
            None,
            None,
        )
        .await;
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    let (tx, rx) = oneshot::channel();
    cmd_tx
        .send(Cmd::Want(format!("0x{}", "ab".repeat(32)), tx))
        .await
        .unwrap();
    let res = tokio::time::timeout(Duration::from_secs(3), rx)
        .await
        .expect("must answer, not hang")
        .unwrap();
    assert_eq!(res, None);
}
