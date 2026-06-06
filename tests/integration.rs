// Integration tests: a mock content origin (independent of the swarm) + the real gateway.
// Non-self-fulfilling — acquire's verification is checked against an independently-computed
// sha256, and the gateway's self-certification is checked by re-hashing what it serves.
use axum::{extract::Path, http::StatusCode, response::IntoResponse, routing::get, Router};
use csd_swarm::acquire::{acquire, sha256_hex};
use csd_swarm::gateway::{router, GwState};
use csd_swarm::store::Store;

async fn spawn(app: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    format!("http://{addr}")
}

const GOOD: &[u8] = b"{\"body\":\"gm\",\"v\":1}";

// mock origin: serves correct bytes at the real hash, WRONG bytes at any other path, and a big
// blob at /big — so we can prove acquire accepts only hash-matching bytes and caps size.
async fn origin_app() -> Router {
    Router::new()
        .route(
            "/content/:h",
            get(|Path(h): Path<String>| async move {
                let want = sha256_hex(GOOD);
                if h.trim_start_matches("0x") == want {
                    (StatusCode::OK, GOOD.to_vec()).into_response()
                } else {
                    (StatusCode::OK, b"TAMPERED-DIFFERENT-BYTES".to_vec()).into_response()
                } // wrong bytes for any other hash
            }),
        )
        .route(
            "/big",
            get(|| async { (StatusCode::OK, vec![0u8; 10_000]) }),
        )
}

#[tokio::test]
async fn acquire_accepts_only_hash_matching_bytes() {
    let origin = spawn(origin_app().await).await;
    let client = reqwest::Client::new();
    let good_hash = sha256_hex(GOOD);

    // correct hash → bytes verify and are returned
    let urls = vec![format!("{origin}/content/0x{good_hash}")];
    let got = acquire(&client, &good_hash, &urls, 1 << 20).await.unwrap();
    assert_eq!(got, GOOD);

    // a DIFFERENT hash → origin returns tampered bytes → acquire MUST reject (no poisoning)
    let bogus = "ab".repeat(32);
    let urls2 = vec![format!("{origin}/content/0x{bogus}")];
    assert!(acquire(&client, &bogus, &urls2, 1 << 20).await.is_err());

    // size cap enforced (the 10k blob exceeds a 1k max)
    let urls3 = vec![format!("{origin}/big")];
    assert!(acquire(&client, &good_hash, &urls3, 1024).await.is_err());
}

#[tokio::test]
async fn gateway_self_certifies_and_handles_errors() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let h = sha256_hex(GOOD);
    store.put(&h, GOOD).await.unwrap();

    let gw = spawn(router(GwState {
        store,
        max_bytes: 1 << 20,
    }))
    .await;
    let client = reqwest::Client::new();

    // GET held → 200, body re-hashes to the requested hash
    let r = client
        .get(format!("{gw}/content/0x{h}"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(
        r.headers().get("etag").unwrap().to_str().unwrap(),
        format!("\"0x{h}\"")
    );
    let body = r.bytes().await.unwrap();
    assert_eq!(sha256_hex(&body), h);

    // unheld → 404, bad hash → 400
    let bogus = "00".repeat(32);
    assert_eq!(
        client
            .get(format!("{gw}/content/0x{bogus}"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(
        client
            .get(format!("{gw}/content/0xnothex"))
            .send()
            .await
            .unwrap()
            .status(),
        400
    );

    // HEAD → 200 with no body; Range → 206
    assert_eq!(
        client
            .head(format!("{gw}/content/0x{h}"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let rr = client
        .get(format!("{gw}/content/0x{h}"))
        .header("Range", "bytes=0-3")
        .send()
        .await
        .unwrap();
    assert_eq!(rr.status(), 206);
    assert_eq!(rr.bytes().await.unwrap().len(), 4);

    // /health + /pins
    let health: serde_json::Value = client
        .get(format!("{gw}/health"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(health["pinned"], 1);
}
