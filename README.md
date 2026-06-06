# csd-swarm — Compute Substrate Content Swarm (L1)

> A self-certifying replication overlay so the bytes CSD points to survive any single server.
> **L1** of the [no-fork ecosystem roadmap](../cairn/docs/ecosystem/02-content-swarm.md). No fork, no token, no new on-chain data.

Every `Propose` puts only `payload_hash` on-chain; the bytes live off-chain on one box. This node
**follows the chain (the allowlist), acquires each confirmed Propose payload, verifies
`sha256(bytes) == payload_hash`, stores it content-addressed, and re-serves it** over an HTTP
gateway (the [CSD Content Convention v1](./CONVENTION.md) / IPFS Trustless-Gateway contract).
Run a few and the content no longer depends on any single disk.

## How it works

```
CSD node (RPC)  ──confirmed Propose──▶  INGEST  (the chain is the allowlist; pin set = live hashes)
                                        ACQUIRE (fetch from the content origin / uri hint)
                                        VERIFY  (sha256(bytes)==payload_hash, size-capped)
                                        STORE   (flat content-addressed blobs)
browser / app  ◀── GET /content/0x… ──  SERVE   (untrusted transport; client re-verifies)
```

**Only verified bytes are ever stored or served** — a malicious origin/peer physically cannot
poison the store (wrong bytes fail the hash).

## Run

```
cargo build --release
CSD_RPC=http://127.0.0.1:8790 \
CSD_ORIGIN=http://127.0.0.1:7777 \
CSD_SWARM_LISTEN=127.0.0.1:8791 \
CSD_SWARM_STORE=./swarm-store \
  ./target/release/csd-swarm
```

| env | default | meaning |
|---|---|---|
| `CSD_RPC` | `http://127.0.0.1:8790` | node RPC (the chain = allowlist) |
| `CSD_ORIGIN` | `http://127.0.0.1:7777` | content origin (`GET {origin}/content/0x<hash>`) |
| `CSD_SWARM_LISTEN` | `127.0.0.1:8791` | gateway bind |
| `CSD_SWARM_STORE` | `./swarm-store` | blob store dir |
| `CSD_MAX_OBJECT` | `2097152` | max object bytes (DoS bound) |
| `CSD_CONFIRMATIONS` | `3` | confirm depth before pinning |
| `CSD_P2P_LISTEN` | `/ip4/0.0.0.0/tcp/0` | libp2p listen multiaddr (peer replication) |
| `CSD_P2P_BOOTSTRAP` | _(none)_ | comma-separated peer multiaddrs to dial |

### Peer replication (libp2p)
Nodes announce held hashes over **gossipsub** (who-has) and serve a 2-verb **request-response**
protocol — `Have(hash)` / `Get(hash)`. When the origin can't serve a hash, the ingest loop asks
peers and **verifies `sha256==hash` before storing** (a peer can't poison you). Point a second
node's `CSD_P2P_BOOTSTRAP` at the first and content replicates peer-to-peer — **the origin can go
offline and the content survives**.

### Endpoints
- `GET|HEAD /content/0x<64-hex>` — canonical bytes; body hash MUST equal the requested hash; immutable cache; `Range` for held objects.
- `GET /pins` — Pinning-Service-shaped status of held hashes.
- `GET /health` — pinned count + bytes.

## Tests

`cargo test` — unit (store roundtrip+reload, acquire hash/size/url logic), integration (a mock
origin proves acquire **rejects tampered + oversized** bytes; the gateway **self-certifies**), and
**p2p** (two real libp2p nodes: node B with an empty store + no origin fetches verified bytes from
node A peer-to-peer; unknown-hash returns None, never hangs). Verified live: ingested 59 confirmed
pins → 18 Cairn payloads; gateway contract 10/10; and a **two-binary run where node B with a DEAD
origin replicated all 18 payloads peer-to-peer from node A** (byte-identical, self-certifying).

## Honest limits (replication ≠ permanence)

Without a token/endowment this is **best-effort replication**, not guaranteed permanence — if every
node holding a hash goes offline *and* the origin drops it, the bytes are gone. **Integrity is never
at risk** (bytes are self-certifying); only availability is. Nodes replicate from a content origin
**and from each other** (libp2p) — the origin is not load-bearing. Content from origins that don't
yet serve canonical bytes by `payload_hash` (e.g. the Observatory) is skipped until they adopt the
[convention](./CONVENTION.md). Peer discovery is via explicit `CSD_P2P_BOOTSTRAP` today; automatic
discovery via the `csd:gateways`/`csd:peers` registries arrives with L3. MIT.
