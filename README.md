# csd-swarm - keep Compute Substrate's content alive

When something is posted to Compute Substrate (CSD), only a short **hash** of the content goes on
the blockchain - the actual bytes (a message, a document, a profile) live off-chain on a server. If
that one server goes down, the bytes are gone even though the hash is still on-chain forever.

**csd-swarm fixes that.** It's a small server you run that watches the chain, downloads the content
for every post, checks that the bytes really match the on-chain hash, stores them, and serves them
back over a simple HTTP URL. Run a few of these and the content no longer depends on any single
machine - and because every byte is checked against its hash, **nobody can serve you fake content**:
wrong bytes simply fail the check and are thrown away.

It speaks the same `GET /content/0x<hash>` contract as IPFS gateways, so anything that can fetch a
URL can use it, and the bytes are self-verifying - the person fetching can re-check the hash too.

## How it works

```
CSD node ──new post (a hash)──▶  watch the chain for confirmed posts
                                 fetch the bytes (from a content server, a peer, or a hint URL)
                                 check sha256(bytes) == the on-chain hash   ← wrong bytes rejected here
                                 store them, addressed by their hash
browser/app ◀── GET /content/0x… ── serve them back (and the fetcher can re-verify the hash)
```

Nodes also gossip what they hold to each other over a peer-to-peer network, so content replicates
**node-to-node** - the original server can go offline and the content survives. A peer can't poison
you either: bytes are re-checked against the hash before anything is stored.

## Run one

```
cargo build --release
CSD_RPC=http://127.0.0.1:8790 \
CSD_ORIGIN=http://127.0.0.1:7777 \
CSD_SWARM_LISTEN=127.0.0.1:8791 \
CSD_SWARM_STORE=./swarm-store \
  ./target/release/csd-swarm
```

| Setting | Default | Meaning |
|---|---|---|
| `CSD_RPC` | `http://127.0.0.1:8790` | the CSD node to follow |
| `CSD_ORIGIN` | `http://127.0.0.1:7777` | where to fetch content from (`GET {origin}/content/0x<hash>`) |
| `CSD_SWARM_LISTEN` | `127.0.0.1:8791` | the HTTP gateway address |
| `CSD_SWARM_STORE` | `./swarm-store` | where to keep the stored content |
| `CSD_MAX_OBJECT` | `2097152` | biggest single object to accept (2 MiB) |
| `CSD_MAX_STORE_BYTES` | `10737418240` | total disk budget (10 GiB; `0` = unlimited). New content past this is not pinned - prevents disk-fill |
| `CSD_CONFIRMATIONS` | `3` | how many confirmations before storing a post's content |
| `CSD_ADMIN_TOKEN` | _(off)_ | set a secret to enable the **takedown API**; unset = you cannot remove content over HTTP |
| `CSD_FOLLOW_URI_HINTS` | `0` | follow attacker-supplied on-chain "hint" URLs (off by default - keeps your IP private) |
| `CSD_GATEWAY_MAX_CONNS` | `64` | max concurrent content reads (RAM/IO abuse guard) |
| `CSD_P2P_LISTEN` | `/ip4/0.0.0.0/tcp/0` | peer-to-peer listen address (use a fixed port, e.g. `/ip4/0.0.0.0/tcp/8792`, to be reachable) |
| `CSD_P2P_BOOTSTRAP` | _(none)_ | optional explicit peer(s) to dial (comma-separated multiaddrs) |
| `CSD_INDEXER` | _(none)_ | an L2 indexer URL — the node reads ENTRY PEERS from the on-chain `csd:peers` registry here and dials them |

### Joining the mesh — no hardcoded server

You do **not** point your node at one server. Like the CSD chain node (which uses a bootnode list),
the swarm discovers entry peers from the **on-chain `csd:peers` registry** — the chain *is* the
decentralized, permissionless bootnode list. Set `CSD_INDEXER` to any L2 indexer (e.g.
`https://cairn-substrate.com/explorer/api`) and on startup the node reads the registered peers and
dials a few; from there gossipsub meshes you with the rest. The node keeps a **stable identity**
across restarts (a key saved in the store dir).

To become discoverable yourself, **announce your node on-chain** (one Propose to `csd:peers` with your
PeerId + public multiaddr) — see `examples/register-swarm-peer.mjs` in the cairn-sdk. You then become
one more permissionless entry point; no single host is load-bearing. (`CSD_P2P_BOOTSTRAP` still works
for a private/explicit peer.)

### What it serves
- `GET /content/0x<hash>` (and `HEAD`) - the bytes for that hash; the body always matches the hash,
  cached as immutable, served as a non-renderable download, with HTTP range support.
- `GET /pins` - what this node is holding.
- `GET /health` - count, total size, store budget, denylist size, **`p2p_peers`** (live connected count).
- `GET /p2p` - **monitoring**: the currently-connected peers (peer_id + remote multiaddr).

## ⚠️ Running a node means hosting public content - read this

Anyone can post anything to the chain for a small fee, and this node will fetch and **re-serve** it.
That means you could end up hosting content you object to (or that's illegal where you live). The
node gives you the controls to deal with that:

**Take content down (and keep it down):**
```bash
# set CSD_ADMIN_TOKEN=<secret> first, then:
curl -X DELETE  http://127.0.0.1:8791/content/0x<hash> -H "Authorization: Bearer <secret>"
```
This **purges the blob and adds the hash to a denylist** (`<store>/denylist.txt`), so the node will
never fetch, store, or serve it again - even though the chain still references it. (A plain `rm`
wouldn't work: the node would re-download it on the next pass. The denylist is what makes a takedown
*stick*.) `POST /admin/allow/0x<hash>` reverses it; the denylist survives restarts. You can also
pre-seed `denylist.txt` (one hash per line) before starting.

**Other operator protections (on by default):**
- **Disk can't be filled** - total storage is capped (`CSD_MAX_STORE_BYTES`); past the budget, new
  content simply isn't pinned, so an attacker can't fill your disk and crash the host.
- **Your IP stays private** - the node only fetches from your configured content server, not from
  attacker-supplied "hint" URLs, unless you opt in (`CSD_FOLLOW_URI_HINTS=1`).
- **Served safely** - content is sent as `application/json` + `nosniff` + `Content-Disposition:
  attachment` + a locked-down CSP, so a browser pointed at attacker bytes can't render or run them.
  The gateway also caps concurrent reads to bound memory/CPU.

**Recommended deployment:** keep the store on its own disk/partition, run behind a reverse proxy
with TLS + rate limiting if you expose the gateway publicly, and set an admin token so you can
respond to abuse reports.

## Security notes (integrity & network)

- **Content is self-certifying.** Bytes are only stored/served if `sha256(bytes)` equals the
  on-chain hash, so a hostile content server or peer can never feed you fake bytes.
- **No fetching internal addresses.** Any URL the node fetches must point at a **public** host -
  localhost, private networks, and cloud-metadata addresses are refused (no server-side request
  forgery), and redirects are re-checked the same way.
- **Bounded everywhere.** Per-object size, total disk, concurrent reads, and the peer-discovery
  table are all capped.

## Honest limit

Without any payment or staking, this is **best-effort replication, not guaranteed permanence**: if
*every* node holding a hash goes offline, those bytes are lost. What's never at risk is
**integrity** - you can always tell genuine bytes from fake ones, because they're checked against
the on-chain hash. MIT licensed.
