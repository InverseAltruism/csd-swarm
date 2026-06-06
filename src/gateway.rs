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
    routing::get,
    Json, Router,
};
use serde_json::json;

#[derive(Clone)]
pub struct GwState {
    pub store: Store,
    pub max_bytes: usize,
}

pub fn router(state: GwState) -> Router {
    Router::new()
        .route("/content/:hash", get(get_content).head(head_content))
        .route("/pins", get(pins))
        .route("/health", get(health))
        .with_state(state)
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
    hm.insert(header::CONTENT_LENGTH, len.to_string().parse().unwrap());
    hm.insert("x-csd-payload-hash", format!("0x{h}").parse().unwrap());
    hm
}

async fn head_content(State(st): State<GwState>, Path(hash): Path<String>) -> Response {
    match norm(&hash) {
        None => StatusCode::BAD_REQUEST.into_response(),
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
        if start > end {
            return StatusCode::RANGE_NOT_SATISFIABLE.into_response();
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
    Json(
        json!({ "ok": true, "pinned": st.store.count().await, "bytes": st.store.total_bytes().await, "max_object_bytes": st.max_bytes }),
    )
}
