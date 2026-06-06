// The chain is the allowlist. We read CONFIRMED proposals from the node RPC and treat their
// payload_hashes as the pin set — you never fetch a hash that didn't cost ≥0.25 CSD to post
// (a built-in spam filter + DoS bound). v1 enumerates domains → /proposals/:domain/:n (yields
// payload_hash + uri + height); incremental block-scan is a later refinement.
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct PinItem {
    pub payload_hash: String,
    pub uri: String,
    pub height: u64,
}

#[derive(Deserialize)]
struct Tip {
    height: u64,
}
#[derive(Deserialize)]
struct DomainsResp {
    domains: Vec<DomainItem>,
}
#[derive(Deserialize)]
struct DomainItem {
    domain: String,
}
#[derive(Deserialize)]
struct ProposalsResp {
    proposals: Vec<ProposalItem>,
}
#[derive(Deserialize)]
struct ProposalItem {
    payload_hash: String,
    uri: String,
    height: u64,
}

#[derive(Clone)]
pub struct Chain {
    rpc: String,
    client: reqwest::Client,
}

impl Chain {
    pub fn new(rpc: String, client: reqwest::Client) -> Self {
        Self {
            rpc: rpc.trim_end_matches('/').to_string(),
            client,
        }
    }

    async fn get<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T> {
        let url = format!("{}{}", self.rpc, path);
        let r = self
            .client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;
        if !r.status().is_success() {
            anyhow::bail!("GET {path} -> HTTP {}", r.status());
        }
        r.json::<T>()
            .await
            .with_context(|| format!("decode {path}"))
    }

    pub async fn tip_height(&self) -> Result<u64> {
        Ok(self.get::<Tip>("/tip").await?.height)
    }

    /// All CONFIRMED, currently-listed proposals (the pin set), deduped by payload_hash.
    pub async fn confirmed_pins(
        &self,
        confirmations: u64,
        per_domain: u32,
    ) -> Result<Vec<PinItem>> {
        let tip = self.tip_height().await?;
        let max_h = tip.saturating_sub(confirmations);
        let domains = self.get::<DomainsResp>("/domains").await?.domains;
        let mut by_hash: HashMap<String, PinItem> = HashMap::new();
        for d in domains {
            let path = format!("/proposals/{}/{}", urlencode(&d.domain), per_domain);
            let ps = match self.get::<ProposalsResp>(&path).await {
                Ok(p) => p.proposals,
                Err(e) => {
                    tracing::warn!("list {} failed: {e}", d.domain);
                    continue;
                }
            };
            for p in ps {
                if p.height > max_h {
                    continue;
                } // not yet confirmed
                let h = p.payload_hash.to_lowercase();
                by_hash.entry(h.clone()).or_insert(PinItem {
                    payload_hash: h,
                    uri: p.uri,
                    height: p.height,
                });
            }
        }
        let mut out: Vec<PinItem> = by_hash.into_values().collect();
        out.sort_by_key(|p| p.height);
        Ok(out)
    }
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{:02X}", b),
        })
        .collect()
}
