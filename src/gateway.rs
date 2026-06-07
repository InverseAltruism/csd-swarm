// HTTP gateway implementing the IPFS Trustless-Gateway contract for CSD content:
//   GET/HEAD /content/0x<64-hex>  → the body's sha256 MUST equal the requested hash (the gateway
//                                   is an UNTRUSTED transport; clients re-verify). Immutable cache,
//                                   strong ETag = the hash, Range honored for fully-local objects.
// Plus a Pinning-Service-shaped admin read and health.
use crate::acquire::sha256_hex;
use crate::store::Store;
use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use serde_json::json;
use std::sync::Arc;
use tokio::sync::Semaphore;

#[derive(Clone)]
pub struct GwState {
    pub store: Store,
    pub max_bytes: usize,
    /// If set, the takedown API (DELETE /content/:hash, /admin/*) is enabled and requires this
    /// bearer token. If None the API is disabled (returns 403) — content can't be removed over HTTP.
    pub admin_token: Option<String>,
    /// Bounds concurrent content reads so a flood of GET/Range can't blow up RAM/IO (each read
    /// buffers up to one max-object, so peak ≈ permits × max_object).
    pub conns: Arc<Semaphore>,
}

pub fn router(state: GwState) -> Router {
    Router::new()
        .route("/content/:hash", get(get_content).head(head_content))
        // takedown: remove a blob AND block its re-download (admin-token gated)
        .route("/content/:hash", delete(purge_content))
        .route("/admin/deny/:hash", post(deny_content))
        .route("/admin/allow/:hash", post(allow_content))
        .route("/pins", get(pins))
        .route("/health", get(health))
        .with_state(state)
}

/// Constant-time-ish bearer-token check for the admin endpoints.
fn admin_ok(st: &GwState, headers: &HeaderMap) -> bool {
    let Some(want) = st.admin_token.as_deref() else {
        return false; // API disabled
    };
    let got = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .or_else(|| headers.get("x-admin-token").and_then(|v| v.to_str().ok()));
    got.map(|g| g.as_bytes().ct_eq(want.as_bytes()))
        .unwrap_or(false)
}

// minimal constant-time compare (avoid pulling a crate for one use)
trait CtEq {
    fn ct_eq(&self, other: &[u8]) -> bool;
}
impl CtEq for [u8] {
    fn ct_eq(&self, other: &[u8]) -> bool {
        if self.len() != other.len() {
            return false;
        }
        let mut d = 0u8;
        for (a, b) in self.iter().zip(other) {
            d |= a ^ b;
        }
        d == 0
    }
}

async fn purge_content(
    State(st): State<GwState>,
    headers: HeaderMap,
    Path(hash): Path<String>,
) -> Response {
    if !admin_ok(&st, &headers) {
        return (StatusCode::FORBIDDEN, "admin token required").into_response();
    }
    let Some(h) = norm(&hash) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match st.store.deny(&h).await {
        Ok(purged) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "denied": true, "purged": purged })),
        )
            .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn deny_content(
    State(st): State<GwState>,
    headers: HeaderMap,
    Path(hash): Path<String>,
) -> Response {
    if !admin_ok(&st, &headers) {
        return (StatusCode::FORBIDDEN, "admin token required").into_response();
    }
    let Some(h) = norm(&hash) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match st.store.deny(&h).await {
        Ok(purged) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "denied": true, "purged": purged })),
        )
            .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn allow_content(
    State(st): State<GwState>,
    headers: HeaderMap,
    Path(hash): Path<String>,
) -> Response {
    if !admin_ok(&st, &headers) {
        return (StatusCode::FORBIDDEN, "admin token required").into_response();
    }
    let Some(h) = norm(&hash) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match st.store.allow(&h).await {
        Ok(removed) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "removed": removed })),
        )
            .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

fn norm(hash: &str) -> Option<String> {
    let h = hash.strip_prefix("0x").unwrap_or(hash).to_lowercase();
    if h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(h)
    } else {
        None
    }
}

fn content_headers(h: &str, len: u64) -> HeaderMap {
    let mut hm = HeaderMap::new();
    hm.insert(
        header::CONTENT_TYPE,
        "application/json; charset=utf-8".parse().unwrap(),
    );
    hm.insert(header::ETAG, format!("\"0x{h}\"").parse().unwrap());
    hm.insert(
        header::CACHE_CONTROL,
        "public, max-age=31536000, immutable".parse().unwrap(),
    );
    hm.insert(header::ACCEPT_RANGES, "bytes".parse().unwrap());
    hm.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*".parse().unwrap());
    hm.insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    // Defense-in-depth: declare it a non-renderable download + a restrictive CSP, so even if a
    // browser is pointed straight at attacker bytes it can't render/execute them.
    hm.insert(header::CONTENT_DISPOSITION, "attachment".parse().unwrap());
    hm.insert(
        header::CONTENT_SECURITY_POLICY,
        "default-src 'none'; sandbox".parse().unwrap(),
    );
    hm.insert(header::CONTENT_LENGTH, len.to_string().parse().unwrap());
    hm.insert("x-csd-payload-hash", format!("0x{h}").parse().unwrap());
    hm
}

async fn head_content(State(st): State<GwState>, Path(hash): Path<String>) -> Response {
    match norm(&hash) {
        None => StatusCode::BAD_REQUEST.into_response(),
        Some(h) if st.store.is_denied(&h).await => {
            (StatusCode::GONE, "content removed by the operator").into_response()
        }
        Some(h) => match st.store.has(&h).await {
            Some(len) => (StatusCode::OK, content_headers(&h, len)).into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        },
    }
}

async fn get_content(
    State(st): State<GwState>,
    headers: HeaderMap,
    Path(hash): Path<String>,
) -> Response {
    let Some(h) = norm(&hash) else {
        return (
            StatusCode::BAD_REQUEST,
            "want /content/0x<64-hex payload_hash>",
        )
            .into_response();
    };
    // operator takedown: never serve denied content
    if st.store.is_denied(&h).await {
        return (StatusCode::GONE, "content removed by the operator").into_response();
    }
    // bound concurrent reads (each buffers up to one max-object) so a flood can't exhaust RAM/IO
    let _permit = match st.conns.try_acquire() {
        Ok(p) => p,
        Err(_) => {
            return (StatusCode::SERVICE_UNAVAILABLE, "gateway busy").into_response();
        }
    };
    let Some(bytes) = st.store.get(&h).await else {
        return (StatusCode::NOT_FOUND, "not held by this gateway").into_response();
    };
    // self-check: never serve bytes whose hash doesn't match (defends against a corrupted store)
    if sha256_hex(&bytes) != h {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "stored bytes failed self-verification",
        )
            .into_response();
    }
    let total = bytes.len() as u64;
    // Range — only for fully-verified local objects (we hold the whole object, so this is safe)
    if let Some(rng) = headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_range)
    {
        let (start, end) = clamp_range(rng, total);
        // `start >= total` also catches the empty-object case (total==0 → start 0 >= 0): without
        // it, `bytes[0..=0]` panics on an empty Vec (DoS, and a crash under panic=abort).
        if start > end || start >= total {
            let mut hm = HeaderMap::new();
            hm.insert(
                header::CONTENT_RANGE,
                format!("bytes */{total}").parse().unwrap(),
            );
            return (StatusCode::RANGE_NOT_SATISFIABLE, hm).into_response();
        }
        let slice = bytes[start as usize..=end as usize].to_vec();
        let mut hm = content_headers(&h, slice.len() as u64);
        hm.insert(
            header::CONTENT_RANGE,
            format!("bytes {start}-{end}/{total}").parse().unwrap(),
        );
        return (StatusCode::PARTIAL_CONTENT, hm, Body::from(slice)).into_response();
    }
    (
        StatusCode::OK,
        content_headers(&h, total),
        Body::from(bytes),
    )
        .into_response()
}

fn parse_range(s: &str) -> Option<(Option<u64>, Option<u64>)> {
    let s = s.strip_prefix("bytes=")?;
    let (a, b) = s.split_once('-')?;
    Some((a.parse().ok(), b.parse().ok()))
}
fn clamp_range((a, b): (Option<u64>, Option<u64>), total: u64) -> (u64, u64) {
    match (a, b) {
        (Some(s), Some(e)) => (s, e.min(total.saturating_sub(1))),
        (Some(s), None) => (s, total.saturating_sub(1)),
        (None, Some(n)) => (total.saturating_sub(n), total.saturating_sub(1)), // suffix
        (None, None) => (0, total.saturating_sub(1)),
    }
}

async fn pins(State(st): State<GwState>) -> impl IntoResponse {
    let mut list = st.store.list().await;
    list.sort();
    let pins: Vec<_> = list
        .into_iter()
        .map(|(h, len)| json!({ "hash": h, "status": "pinned", "bytes": len }))
        .collect();
    Json(json!({ "ok": true, "count": pins.len(), "pins": pins }))
}

async fn health(State(st): State<GwState>) -> impl IntoResponse {
    Json(json!({
        "ok": true,
        "pinned": st.store.count().await,
        "bytes": st.store.total_bytes().await,
        "max_object_bytes": st.max_bytes,
        "max_store_bytes": st.store.max_bytes(),
        "denied": st.store.denied_count().await,
        "admin_api": st.admin_token.is_some(),
    }))
}
