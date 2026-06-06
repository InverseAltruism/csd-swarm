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

### Endpoints
- `GET|HEAD /content/0x<64-hex>` — canonical bytes; body hash MUST equal the requested hash; immutable cache; `Range` for held objects.
- `GET /pins` — Pinning-Service-shaped status of held hashes.
- `GET /health` — pinned count + bytes.

## Tests

`cargo test` — unit (store roundtrip+reload, acquire hash/size/url logic) + integration (a mock
origin proves acquire **rejects tampered + oversized** bytes; the gateway **self-certifies** what
it serves). Verified live: ingested 59 confirmed pins, fetched+verified 18 Cairn payloads, gateway
contract 10/10.

## Honest limits (replication ≠ permanence)

Without a token/endowment this is **best-effort replication**, not guaranteed permanence — if every
node holding a hash goes offline *and* the origin drops it, the bytes are gone. **Integrity is never
at risk** (bytes are self-certifying); only availability is. v1 is **origin-fed** (each node mirrors
+ verifies from a content origin); **peer-to-peer replication** (libp2p `Have?`/`Get` + gossipsub,
so the origin can go offline) is the next milestone (P2.3). Content from origins that don't yet
serve canonical bytes by `payload_hash` (e.g. the Observatory) is skipped until they adopt the
[convention](./CONVENTION.md). MIT.
