// Flat content-addressed blob store, keyed by hex(payload_hash). On disk: <dir>/<hex>.bin.
// ONLY verified bytes are ever written (acquire.rs checks sha256 before put), so the store is
// self-certifying by construction. An in-memory index tracks held hashes + sizes for O(1) Have?.
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct Store {
    dir: PathBuf,
    index: Arc<RwLock<HashMap<String, u64>>>, // hex(no 0x) -> length
}

fn norm(hash: &str) -> String {
    hash.strip_prefix("0x").unwrap_or(hash).to_lowercase()
}

/// True only for a canonical 64-char lowercase-hex content hash. The store key is interpolated
/// into a filename, so this is the guard that makes path traversal (`../…`) structurally
/// impossible even if a caller ever passed an unvalidated hash.
fn is_valid_hash(h: &str) -> bool {
    h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit())
}

impl Store {
    pub async fn open(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        tokio::fs::create_dir_all(&dir)
            .await
            .context("create store dir")?;
        let mut index = HashMap::new();
        let mut rd = tokio::fs::read_dir(&dir).await?;
        while let Some(e) = rd.next_entry().await? {
            let name = e.file_name().to_string_lossy().to_string();
            if let Some(h) = name.strip_suffix(".bin") {
                if h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()) {
                    let len = e.metadata().await.map(|m| m.len()).unwrap_or(0);
                    index.insert(h.to_string(), len);
                }
            }
        }
        Ok(Self {
            dir,
            index: Arc::new(RwLock::new(index)),
        })
    }

    fn path(&self, h: &str) -> PathBuf {
        self.dir.join(format!("{}.bin", h))
    }

    pub async fn has(&self, hash: &str) -> Option<u64> {
        self.index.read().await.get(&norm(hash)).copied()
    }

    pub async fn get(&self, hash: &str) -> Option<Vec<u8>> {
        let h = norm(hash);
        if !is_valid_hash(&h) {
            return None;
        }
        if !self.index.read().await.contains_key(&h) {
            return None;
        }
        tokio::fs::read(self.path(&h)).await.ok()
    }

    /// Persist bytes under `hash`. Caller MUST have verified sha256(bytes)==hash first.
    pub async fn put(&self, hash: &str, bytes: &[u8]) -> Result<()> {
        let h = norm(hash);
        if !is_valid_hash(&h) {
            anyhow::bail!("refusing to store under a non-hex key");
        }
        let tmp = self.dir.join(format!("{}.tmp", h));
        tokio::fs::write(&tmp, bytes).await.context("write tmp")?;
        tokio::fs::rename(&tmp, self.path(&h))
            .await
            .context("rename into place")?; // atomic
        self.index.write().await.insert(h, bytes.len() as u64);
        Ok(())
    }

    pub async fn count(&self) -> usize {
        self.index.read().await.len()
    }
    pub async fn total_bytes(&self) -> u64 {
        self.index.read().await.values().sum()
    }
    pub async fn list(&self) -> Vec<(String, u64)> {
        self.index
            .read()
            .await
            .iter()
            .map(|(k, v)| (format!("0x{}", k), *v))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn put_get_has_roundtrip_and_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(dir.path()).await.unwrap();
        let bytes = b"{\"v\":1}".to_vec();
        let h = crate::acquire::sha256_hex(&bytes);
        assert!(s.has(&h).await.is_none());
        s.put(&h, &bytes).await.unwrap();
        assert_eq!(s.has(&h).await, Some(bytes.len() as u64));
        assert_eq!(s.get(&h).await.unwrap(), bytes);
        assert_eq!(s.count().await, 1);
        // 0x-prefixed lookups normalize to the same key
        assert_eq!(s.has(&format!("0x{h}")).await, Some(bytes.len() as u64));
        // reopening rebuilds the index from disk
        let s2 = Store::open(dir.path()).await.unwrap();
        assert_eq!(s2.count().await, 1);
        assert_eq!(s2.get(&h).await.unwrap(), bytes);
    }
}
