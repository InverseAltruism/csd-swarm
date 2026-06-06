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
    let mut v = vec![format!("{}/content/{}", origin.trim_end_matches('/'), hash)];
    if uri.starts_with("http://") || uri.starts_with("https://") {
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
        let v = candidate_urls("http://o:7777/", "0xabc", "https://obs/payload/9");
        assert_eq!(v[0], "http://o:7777/content/0xabc");
        assert_eq!(v[1], "https://obs/payload/9");
        // opaque (non-http) uri is NOT used as a fetch url
        let v2 = candidate_urls("http://o", "0xabc", "cairn:v1:deadbeef");
        assert_eq!(v2.len(), 1);
    }
}
