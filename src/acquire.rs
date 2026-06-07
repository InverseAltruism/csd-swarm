// ACQUIRE + VERIFY: fetch the bytes for a payload_hash and prove sha256(bytes)==hash before it
// is ever stored or served. A malicious origin/peer physically cannot poison the store — wrong
// bytes fail the hash. Enforces a max-object size WHILE STREAMING and aborts on overflow (the
// chain doesn't bound off-chain content, so we must).
use anyhow::{anyhow, bail, Result};
use futures_util::StreamExt;
use sha2::{Digest, Sha256};

fn norm(hash: &str) -> String {
    hash.strip_prefix("0x").unwrap_or(hash).to_lowercase()
}

/// SSRF guard for UNTRUSTED fetch targets (on-chain `uri` hints, chain-discovered gateway
/// templates). Rejects non-http(s) and any host that is a private/loopback/link-local/CGNAT/
/// metadata IP literal or a known-internal hostname. The operator-configured origin is exempt
/// (it is trusted config, often 127.0.0.1). Note: a hostname that *resolves* to a private IP is
/// not caught here without DNS resolution — content is hash-verified so this is blind SSRF only.
pub fn host_is_public(url: &str) -> bool {
    let Ok(u) = reqwest::Url::parse(url) else {
        return false;
    };
    if u.scheme() != "http" && u.scheme() != "https" {
        return false;
    }
    let Some(host) = u.host_str() else {
        return false;
    };
    let h = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = h.parse::<std::net::IpAddr>() {
        return ip_is_public(ip);
    }
    let hl = host.to_lowercase();
    !(hl == "localhost"
        || hl.ends_with(".localhost")
        || hl.ends_with(".local")
        || hl.ends_with(".internal")
        || hl == "metadata.google.internal")
}

fn ip_is_public(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(a) => {
            let o = a.octets();
            !(a.is_private()
                || a.is_loopback()
                || a.is_link_local()
                || a.is_unspecified()
                || a.is_multicast()
                || a.is_broadcast()
                || o[0] == 0
                || (o[0] == 100 && (64..=127).contains(&o[1])) // CGNAT 100.64.0.0/10
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)) // IETF protocol assignments
        }
        std::net::IpAddr::V6(a) => {
            let s = a.segments();
            !(a.is_loopback()
                || a.is_unspecified()
                || a.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // ULA fc00::/7
                || (s[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
                || a.to_ipv4_mapped().is_some_and(|v4| !ip_is_public(std::net::IpAddr::V4(v4))))
        }
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Try to acquire `hash` from a list of candidate URLs (origin /content/0x… first, then any
/// http(s) uri hint). Returns verified bytes or an error. Never returns unverified bytes.
pub async fn acquire(
    client: &reqwest::Client,
    hash: &str,
    urls: &[String],
    max_bytes: usize,
) -> Result<Vec<u8>> {
    let want = norm(hash);
    let mut last_err = anyhow!("no candidate urls");
    for url in urls {
        match fetch_capped(client, url, max_bytes).await {
            Ok(bytes) => {
                let got = sha256_hex(&bytes);
                if got == want {
                    return Ok(bytes);
                }
                last_err = anyhow!("hash mismatch from {url}: got {got}");
            }
            Err(e) => last_err = anyhow!("{url}: {e}"),
        }
    }
    Err(last_err)
}

/// Stream a URL, enforcing the size cap as bytes arrive (abort before buffering an oversized body).
async fn fetch_capped(client: &reqwest::Client, url: &str, max_bytes: usize) -> Result<Vec<u8>> {
    let resp = client.get(url).send().await?;
    if !resp.status().is_success() {
        bail!("HTTP {}", resp.status());
    }
    if let Some(len) = resp.content_length() {
        if len as usize > max_bytes {
            bail!("content-length {len} > max {max_bytes}");
        }
    }
    let mut out = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if out.len() + chunk.len() > max_bytes {
            bail!("body exceeded max {max_bytes} while streaming");
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// Candidate URLs for a (hash, uri): the configured origin's convention endpoint first, then the
/// on-chain `uri` if it is itself an http(s) URL (an origin hint for other apps).
pub fn candidate_urls(origin: &str, hash: &str, uri: &str) -> Vec<String> {
    // the origin is operator-configured (trusted) — used verbatim. The on-chain uri hint is
    // attacker-controlled, so it is only used if it points at a PUBLIC host (SSRF guard).
    let mut v = vec![format!("{}/content/{}", origin.trim_end_matches('/'), hash)];
    if (uri.starts_with("http://") || uri.starts_with("https://")) && host_is_public(uri) {
        v.push(uri.to_string());
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sha256_known_vector() {
        // sha256("") = e3b0c442...
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
    #[test]
    fn candidate_urls_origin_first_then_http_uri() {
        let v = candidate_urls(
            "http://o:7777/",
            "0xabc",
            "https://obs.example.com/payload/9",
        );
        assert_eq!(v[0], "http://o:7777/content/0xabc");
        assert_eq!(v[1], "https://obs.example.com/payload/9");
        // opaque (non-http) uri is NOT used as a fetch url
        let v2 = candidate_urls("http://o", "0xabc", "cairn:v1:deadbeef");
        assert_eq!(v2.len(), 1);
    }

    #[test]
    fn ssrf_guard_blocks_internal_uri_hints() {
        // A public uri is allowed; internal/loopback/metadata targets are dropped from candidates.
        for bad in [
            "http://127.0.0.1:8790/x",
            "http://169.254.169.254/latest/meta-data",
            "http://localhost/x",
            "http://10.0.0.1/x",
            "http://192.168.1.1/x",
            "http://172.16.0.1/x",
            "http://[::1]/x",
            "http://metadata.google.internal/x",
            "http://100.64.0.1/x",
            "file:///etc/passwd",
            "gopher://x/y",
        ] {
            assert!(!host_is_public(bad), "{bad} must be rejected");
            let v = candidate_urls("http://origin:7777", "0xabc", bad);
            assert_eq!(v.len(), 1, "internal uri {bad} must not become a candidate");
        }
        for good in [
            "https://gist.githubusercontent.com/u/raw",
            "https://example.com/c",
            "http://8.8.8.8/x",
        ] {
            assert!(host_is_public(good), "{good} must be allowed");
        }
    }
}
