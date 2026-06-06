# CSD Content Convention v1

> One rule so every Compute Substrate app's off-chain content is mutually hostable and
> self-certifying, keyed uniformly by the on-chain `payload_hash`.

A `Propose` transaction commits `payload_hash` (+ a `uri` hint) on-chain; the bytes live
off-chain. Integrity is already decentralized — anyone can check `sha256(bytes) == payload_hash`.
This convention makes that checkable *uniformly across apps* so a shared swarm can host them all.

## Rules

1. **Address = the on-chain `payload_hash`.** `payload_hash = sha256(canonical_bytes)`. The swarm
   and gateways key on this and nothing else.

2. **Canonicalization is deterministic so raw served bytes verify.** The canonical preimage is
   the content record serialized as **canonical JSON**: UTF-8, object keys sorted recursively
   (lexicographic by UTF-16 code unit, matching `JSON.stringify` key order), no insignificant
   whitespace, arrays in declaration order. (Reference impl: `canonicalJson` /
   `payloadHash` in [`@inversealtruism/csd-codec`](https://www.npmjs.com/package/@inversealtruism/csd-codec).)
   Apps MUST serve the **exact canonical bytes**, never a pretty-printed re-render.

3. **`uri` is a hint, not the locator.** Existing schemes (`cairn:v1:…`,
   `https://…/payload/…`) stay valid as *origin hints*; resolution prefers the swarm by
   `payload_hash` and falls back to the `uri` origin.

4. **Gateway contract** (IPFS Trustless-Gateway profile):
   - `GET /content/0x<64-hex payload_hash>` → the canonical bytes.
   - The response body's `sha256` **MUST** equal the requested hash. The gateway is an
     **untrusted transport** — clients re-verify.
   - `ETag: "0x<hash>"`, `Cache-Control: public, max-age=31536000, immutable`, `Accept-Ranges: bytes`.
   - `HEAD` mirrors `GET`. `Range` is honored only for fully-held (already-verified) objects.
   - `400` for a malformed hash, `404` if not held — never serve unverified bytes.

## Conformance

A content origin is conformant if, for every `payload_hash` it serves,
`sha256(GET /content/0x<hash>) == hash`. The Cairn server (`/content/0x<hash>`) and this swarm
both implement it; verify with:

```
curl -s http://HOST/content/0x<hash> | sha256sum   # → <hash>
```

## Honest limit

This convention guarantees **integrity** (self-certification), not **availability**. Replication
across many nodes is the swarm's job; permanence is not guaranteed without a token/endowment
(advocacy track). See the swarm README.
