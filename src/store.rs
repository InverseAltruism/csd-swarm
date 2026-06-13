// Flat content-addressed blob store, keyed by hex(payload_hash). On disk: <dir>/<hex>.bin.
// ONLY verified bytes are ever written (acquire.rs checks sha256 before put), so the store is
// self-certifying by construction. An in-memory index tracks held hashes + sizes for O(1) Have?.
//
// OPERATOR SAFETY: the bytes are attacker-chosen (anyone can post anything to the chain), so the
// store also gives an operator the controls a content host needs:
//   • a persistent DENYLIST — hashes that must never be fetched, stored, or served (illegal/abusive
//     content). Denied content is purged on load and refused on put, so a takedown STAYS down even
//     though the chain still references it (otherwise the ingest loop would re-download it).
//   • a total-size CAP — refuse new content past a configured budget so attacker- or organic-driven
//     growth can't fill the operator's disk and take down the whole host.
use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct Store {
    dir: PathBuf,
    index: Arc<RwLock<HashMap<String, u64>>>, // hex(no 0x) -> length
    total: Arc<RwLock<u64>>,                  // cached sum of index values (O(1) cap checks)
    denied: Arc<RwLock<HashSet<String>>>,     // hashes the operator refuses to host
    denylist_path: PathBuf,
    max_bytes: u64, // 0 = unlimited; set once before cloning
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

/// Atomically rewrite the denylist file from the in-memory set (tmp + rename). The caller MUST hold
/// the `denied` write lock for the whole insert/remove + write, so deny()/allow() can never
/// interleave such that one's atomic rename clobbers the other's update and silently loses a
/// takedown (the previous append-then-separate-rename design had exactly that race).
async fn write_denylist(path: &Path, set: &HashSet<String>) -> Result<()> {
    let body: String = set.iter().map(|x| format!("{x}\n")).collect();
    let tmp = path.with_file_name("denylist.txt.tmp");
    tokio::fs::write(&tmp, body)
        .await
        .context("write denylist tmp")?;
    tokio::fs::rename(&tmp, path)
        .await
        .context("rename denylist into place")?; // atomic
    Ok(())
}

impl Store {
    pub async fn open(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        tokio::fs::create_dir_all(&dir)
            .await
            .context("create store dir")?;
        let denylist_path = dir.join("denylist.txt");
        let denied = load_denylist(&denylist_path).await;

        let mut index = HashMap::new();
        let mut total = 0u64;
        let mut rd = tokio::fs::read_dir(&dir).await?;
        while let Some(e) = rd.next_entry().await? {
            let name = e.file_name().to_string_lossy().to_string();
            if let Some(h) = name.strip_suffix(".bin") {
                if is_valid_hash(h) {
                    // PURGE on load anything that is denied (so a takedown survives a restart even
                    // if the file was somehow re-created).
                    if denied.contains(h) {
                        let _ = tokio::fs::remove_file(e.path()).await;
                        continue;
                    }
                    let len = e.metadata().await.map(|m| m.len()).unwrap_or(0);
                    index.insert(h.to_string(), len);
                    total += len;
                }
            }
        }
        Ok(Self {
            dir,
            index: Arc::new(RwLock::new(index)),
            total: Arc::new(RwLock::new(total)),
            denied: Arc::new(RwLock::new(denied)),
            denylist_path,
            max_bytes: 0,
        })
    }

    /// Set the total-store byte budget (0 = unlimited). Call before cloning the store into tasks.
    pub fn with_max_bytes(mut self, max_bytes: u64) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    fn path(&self, h: &str) -> PathBuf {
        self.dir.join(format!("{}.bin", h))
    }

    /// Is this hash on the operator's denylist? Checked by ingest (don't fetch), put (don't store),
    /// and the gateway (don't serve → 410 Gone).
    pub async fn is_denied(&self, hash: &str) -> bool {
        self.denied.read().await.contains(&norm(hash))
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
    /// Refuses denied hashes and refuses to exceed the total-size budget.
    pub async fn put(&self, hash: &str, bytes: &[u8]) -> Result<()> {
        let h = norm(hash);
        if !is_valid_hash(&h) {
            anyhow::bail!("refusing to store under a non-hex key");
        }
        if self.denied.read().await.contains(&h) {
            anyhow::bail!("hash is on the operator denylist — refusing to store");
        }
        if self.max_bytes > 0 {
            let cur = *self.total.read().await;
            // already held? a re-put of the same hash doesn't grow the store
            let already = self.index.read().await.get(&h).copied().unwrap_or(0);
            if already == 0 && cur.saturating_add(bytes.len() as u64) > self.max_bytes {
                anyhow::bail!(
                    "store budget {} exceeded ({} + {} bytes) — not pinning",
                    self.max_bytes,
                    cur,
                    bytes.len()
                );
            }
        }
        let tmp = self.dir.join(format!("{}.tmp", h));
        tokio::fs::write(&tmp, bytes).await.context("write tmp")?;
        tokio::fs::rename(&tmp, self.path(&h))
            .await
            .context("rename into place")?; // atomic
        let mut idx = self.index.write().await;
        let prev = idx.insert(h, bytes.len() as u64).unwrap_or(0);
        let mut tot = self.total.write().await;
        *tot = tot.saturating_sub(prev).saturating_add(bytes.len() as u64);
        Ok(())
    }

    /// Remove a blob from disk + index (no denylist change). Returns whether something was removed.
    pub async fn purge(&self, hash: &str) -> bool {
        let h = norm(hash);
        if !is_valid_hash(&h) {
            return false;
        }
        let _ = tokio::fs::remove_file(self.path(&h)).await;
        let mut idx = self.index.write().await;
        if let Some(len) = idx.remove(&h) {
            let mut tot = self.total.write().await;
            *tot = tot.saturating_sub(len);
            true
        } else {
            false
        }
    }

    /// Add a hash to the persistent denylist AND purge it. After this the ingest loop will never
    /// re-download it, the store will never write it, and the gateway will 410 it — a takedown that
    /// stays down. Returns whether a blob was purged.
    pub async fn deny(&self, hash: &str) -> Result<bool> {
        let h = norm(hash);
        if !is_valid_hash(&h) {
            anyhow::bail!("not a valid content hash");
        }
        {
            // Hold the write lock across BOTH the set insert AND the file write (rewrite-from-set,
            // not append) so a concurrent allow() can't rename the file out from under us and drop
            // this takedown. Roll the set back on an I/O error so memory and file stay consistent.
            let mut set = self.denied.write().await;
            if set.insert(h.clone()) {
                if let Err(e) = write_denylist(&self.denylist_path, &set).await {
                    set.remove(&h);
                    return Err(e);
                }
            }
        }
        Ok(self.purge(&h).await)
    }

    /// Remove a hash from the denylist (re-allow). Rewrites the denylist file ATOMICALLY (write a
    /// .tmp then rename), so a crash mid-rewrite can never truncate the denylist and silently
    /// re-allow other banned hashes (C-W4) — the same tmp+rename discipline as `put`.
    pub async fn allow(&self, hash: &str) -> Result<bool> {
        let h = norm(hash);
        // Same single-lock discipline as deny(): remove + rewrite under one held write lock, with
        // rollback on I/O error, so deny()/allow() can't race and lose an entry.
        let mut set = self.denied.write().await;
        if set.remove(&h) {
            if let Err(e) = write_denylist(&self.denylist_path, &set).await {
                set.insert(h.clone());
                return Err(e);
            }
            return Ok(true);
        }
        Ok(false)
    }

    pub async fn count(&self) -> usize {
        self.index.read().await.len()
    }
    pub async fn total_bytes(&self) -> u64 {
        *self.total.read().await
    }
    pub async fn denied_count(&self) -> usize {
        self.denied.read().await.len()
    }
    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
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

async fn load_denylist(path: &Path) -> HashSet<String> {
    let mut set = HashSet::new();
    if let Ok(body) = tokio::fs::read_to_string(path).await {
        for line in body.lines() {
            let l = line.trim();
            if l.is_empty() || l.starts_with('#') {
                continue;
            }
            let h = norm(l);
            if is_valid_hash(&h) {
                set.insert(h);
            }
        }
    }
    set
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
        assert_eq!(s.total_bytes().await, bytes.len() as u64);
        // 0x-prefixed lookups normalize to the same key
        assert_eq!(s.has(&format!("0x{h}")).await, Some(bytes.len() as u64));
        // reopening rebuilds the index from disk
        let s2 = Store::open(dir.path()).await.unwrap();
        assert_eq!(s2.count().await, 1);
        assert_eq!(s2.get(&h).await.unwrap(), bytes);
    }

    #[tokio::test]
    async fn denylist_blocks_store_purges_and_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(dir.path()).await.unwrap();
        let bytes = b"abusive".to_vec();
        let h = crate::acquire::sha256_hex(&bytes);
        s.put(&h, &bytes).await.unwrap();
        assert!(s.has(&h).await.is_some());
        // deny → purges the blob and persists the block
        assert!(s.deny(&h).await.unwrap());
        assert!(s.has(&h).await.is_none(), "denied blob purged");
        assert!(s.is_denied(&h).await);
        // a re-put (e.g. the ingest loop re-fetching) is REFUSED
        assert!(
            s.put(&h, &bytes).await.is_err(),
            "denied hash refused on put"
        );
        assert!(s.has(&h).await.is_none());
        // and the denylist survives a restart (takedown stays down)
        let s2 = Store::open(dir.path()).await.unwrap();
        assert!(s2.is_denied(&h).await);
        assert!(s2.put(&h, &bytes).await.is_err());
    }

    #[tokio::test]
    async fn allow_rewrite_preserves_other_denied_and_survives_reopen() {
        // C-W4: re-allowing one hash must atomically rewrite the denylist WITHOUT dropping the others.
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(dir.path()).await.unwrap();
        let h1 = crate::acquire::sha256_hex(b"one");
        let h2 = crate::acquire::sha256_hex(b"two");
        let h3 = crate::acquire::sha256_hex(b"three");
        // deny() returns whether a blob was purged (none here — no put), so assert the denylist state
        s.deny(&h1).await.unwrap();
        s.deny(&h2).await.unwrap();
        s.deny(&h3).await.unwrap();
        assert!(s.is_denied(&h1).await && s.is_denied(&h2).await && s.is_denied(&h3).await);
        assert!(s.allow(&h2).await.unwrap(), "h2 re-allowed");
        assert!(!s.is_denied(&h2).await);
        assert!(
            s.is_denied(&h1).await && s.is_denied(&h3).await,
            "others stay denied"
        );
        // the rewritten denylist is correct + durable across a restart
        let s2 = Store::open(dir.path()).await.unwrap();
        assert!(s2.is_denied(&h1).await, "h1 still denied after reopen");
        assert!(!s2.is_denied(&h2).await, "h2 allowed after reopen");
        assert!(s2.is_denied(&h3).await, "h3 still denied after reopen");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_deny_allow_never_loses_a_takedown() {
        // Regression for the deny()/allow() race: a concurrent allow()'s atomic file rewrite must
        // never orphan a concurrent deny()'s takedown. Hammer both across threads, then reopen and
        // assert the PERSISTED denylist exactly matches the final in-memory set (no lost entries).
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(dir.path()).await.unwrap();
        let hashes: Vec<String> = (0..64u32)
            .map(|i| crate::acquire::sha256_hex(format!("h{i}").as_bytes()))
            .collect();
        let mut tasks = Vec::new();
        for (i, h) in hashes.iter().cloned().enumerate() {
            let s = s.clone();
            tasks.push(tokio::spawn(async move {
                s.deny(&h).await.unwrap();
                if i % 2 == 0 {
                    // even hashes are re-allowed, racing the odd hashes' denies on the shared file
                    s.allow(&h).await.unwrap();
                }
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        // the PERSISTED denylist (after a fresh reopen) must equal memory: every odd hash denied,
        // every even hash allowed — no takedown lost to the race.
        let s2 = Store::open(dir.path()).await.unwrap();
        for (i, h) in hashes.iter().enumerate() {
            assert_eq!(
                s.is_denied(h).await,
                i % 2 == 1,
                "in-memory mismatch at {i}"
            );
            assert_eq!(
                s2.is_denied(h).await,
                i % 2 == 1,
                "persisted denylist lost/kept the wrong takedown at {i}"
            );
        }
    }

    #[tokio::test]
    async fn size_cap_refuses_new_content_when_full() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(dir.path()).await.unwrap().with_max_bytes(10);
        let a = b"12345".to_vec(); // 5 bytes
        let b = b"678901".to_vec(); // 6 bytes → 5+6=11 > 10
        let ha = crate::acquire::sha256_hex(&a);
        let hb = crate::acquire::sha256_hex(&b);
        s.put(&ha, &a).await.unwrap();
        assert!(s.put(&hb, &b).await.is_err(), "over-budget put refused");
        assert_eq!(s.total_bytes().await, 5);
        // re-putting an already-held hash is allowed (doesn't grow the store)
        s.put(&ha, &a).await.unwrap();
        assert_eq!(s.count().await, 1);
    }
}
