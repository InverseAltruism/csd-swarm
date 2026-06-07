// L3 wiring: discover additional content gateways from the chain (via an L2 indexer's
// /registry/gateways resolver) instead of relying only on a hardcoded origin. Each
// discovered gateway is a URL TEMPLATE containing `{hash}`; we expand it per payload.
// Bytes from any gateway are still VERIFIED (sha256==hash) in acquire — a gateway is an
// untrusted transport, exactly like the origin. So adding gateways can never poison us;
// it only improves availability and removes the single-origin dependency.
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct RankedGateway {
    url: String,
}

/// Fetch the ranked gateway URL templates from an L2 indexer. Returns only well-formed
/// templates (must contain `{hash}`). Errors/empty → an empty list (origin still works).
pub async fn discover(client: &reqwest::Client, indexer_base: &str) -> Vec<String> {
    let url = format!("{}/registry/gateways", indexer_base.trim_end_matches('/'));
    let gws: Vec<RankedGateway> = match client.get(&url).send().await {
        Ok(r) if r.status().is_success() => r.json().await.unwrap_or_default(),
        _ => return Vec::new(),
    };
    gws.into_iter()
        .map(|g| g.url)
        .filter(|u| u.contains("{hash}") && (u.starts_with("http://") || u.starts_with("https://")))
        .collect()
}

/// Expand discovered gateway templates for a specific payload hash. `{hash}` is the
/// BARE hex — templates carry their own `0x` (e.g. `…/content/0x{hash}`).
pub fn expand(templates: &[String], hash: &str) -> Vec<String> {
    // chain-discovered gateway URLs are untrusted → expand then drop any whose host is not public
    // (SSRF guard); bytes are still hash-verified in acquire on top of this.
    let bare = hash.trim_start_matches("0x");
    templates
        .iter()
        .map(|t| t.replace("{hash}", bare))
        .filter(|u| crate::acquire::host_is_public(u))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn expand_substitutes_bare_hex_into_the_template() {
        let t = vec![
            "https://gw1/content/0x{hash}".to_string(),
            "https://gw2/ipfs/{hash}".to_string(),
        ];
        let out = expand(&t, "0xabc"); // 0x-prefixed input is normalized to bare hex
        assert_eq!(out[0], "https://gw1/content/0xabc");
        assert_eq!(out[1], "https://gw2/ipfs/abc");
    }
}
