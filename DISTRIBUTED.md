# Distributed Chain of Custody — DNS-Based Federation

## Overview

The current system is single-node: one server holds all signing keys, all
database records, and performs all verifications. This document describes a
federated architecture where any number of independent nodes form a globally
distributed verification network, needing only DNS for discovery.

Every node is autonomous. Each chooses its own signing algorithm, its own
hash salt, its own database, and its own storage policy. No shared secrets.
No blockchain. No consensus protocol.

## Signature Format

Every signed file embeds a **node identifier** alongside the signature hash.
The identifier tells any verifier which node owns that signature.

```
[ 4 bytes: identifier length (N) ]
[ N bytes: node identifier — e.g. "ewefshjkska" ]
[ 1 byte : 0x24 — dollar sign delimiter ]
[ remaining bytes: file signature — opaque to other nodes ]
```

The exact binary layout is format-specific (TIFF tag, JPEG APP8, PNG chunk,
CR3 box), but every format carries the same logical payload:

```
node_id:$signature_data
```

Where `node_id` is a short, globally unique string (8–16 bytes) and
`signature_data` is any data the node chooses to embed — a salted hash,
an asymmetric signature, a block reference, or any future format.

### Node identifier

Each node generates a random identifier at setup time (e.g. 8 random bytes
encoded as hex, giving a 16-character string). This identifier never changes
for the lifetime of the node. It serves as:

- A routable address via DNS (`<id>.photo-verify.org`).
- A stable key for signature attribution.
- A namespace anchor — no two nodes should share an identifier.

## DNS Discovery

Each node publishes a DNS record mapping its identifier to its verification
endpoint:

```
ewefshjkska.photo-verify.org  IN  CNAME  api.mynode.org
```

Or, for nodes that prefer not to delegate:

```
ewefshjkska.photo-verify.org  IN  A      203.0.113.42
```

A resolver reads the node identifier from the file, constructs
`<id>.photo-verify.org`, looks up the CNAME or A record, and discovers the
node's IP address. The node's verification API is at:

```
https://<resolved-host>/verify
```

### Root domain governance

The `photo-verify.org` domain controls the identifier namespace. Registering
an identifier is a lightweight process — generate a random ID, submit a proof
of ownership (sign a challenge with the domain's TLS key or hosted zone), and
have the `CNAME` record added. The domain operator has no access to any node's
database, salt, or signing keys — only the mapping from identifier to hostname.

Nodes can also be discovered out-of-band (QR code, NFC, static file on a
website) without using the DNS root at all. DNS is the default discovery
mechanism, not the only one.

## API Endpoints

Every node exposes two endpoints:

### POST /verify

Verify a file that was signed by this node.

Request: `multipart/form-data` with field `file`.

Response 200 (valid):
```json
{
  "status":    "ok",
  "valid":     true,
  "node_id":   "ewefshjkska",
  "hash":      "abc123...",
  "signature": { "author_name": "Alice", ... },
  "chain":     [ ... ]
}
```

Response 200 (invalid):
```json
{
  "status": "ok",
  "valid":  false,
  "reason": "hash_mismatch"
}
```

### POST /forward

Forward a verification request to the owning node and return the result.

Request: `multipart/form-data` with fields `file` and `node_id`.

The responding node:
1. Extracts `node_id` from the request.
2. Looks up `<node_id>.photo-verify.org` via DNS.
3. POSTs the file to the resolved node's `/verify` endpoint.
4. Returns the result verbatim (optionally signed with the proxy's API key
   for cacheability).

This endpoint is the federation primitive — any node can act as a proxy
for any other node. A user never needs to resolve DNS themselves.

## Verification Flow

```
User uploads a signed file to Node A
  ↓
Node A reads the embedded node_id from the file
  ↓
Is node_id mine?
  ├─ YES → verify locally using my salt/my algorithm
  │         return result
  └─ NO  → DNS lookup: <node_id>.photo-verify.org
            ↓
            POST /verify to resolved node
            ↓
            Return result to user
```

A node can transparently chain through multiple proxies. If the resolved
node is unreachable, the proxy tries a configurable number of retries and
fallback endpoints before reporting failure.

### Self-verifying files (optional)

A node may optionally publish its verification parameters via a
`/.well-known/chain-of-custody` JSON endpoint:

```json
{
  "node_id":     "ewefshjkska",
  "algorithm":   "SHA-256",
  "salt":        null,
  "public_key":  "MCowBQYD...",
  "signature":   "abc123..."
}
```

The `signature` field is a self-signature over the metadata, proving the
node controls its identifier. A verifier can fetch this document once and
verify files offline without querying the node — but the node is never
required to publish this information. Offline verifiability is opt-in.

## Security Model

### Trust assumptions

- **The DNS root** (`photo-verify.org`) is trusted for node discovery. A
  compromised root can redirect lookups to a malicious node. Mitigation:
  verifiers pin known node identifiers, use DNSSEC, or accept out-of-band
  discovery as an alternative.
- **Each node is trusted for its own signatures.** No node can forge
  another node's signatures because it doesn't know the other node's salt or
  private key.
- **Malicious nodes can only affect their own signatures.** A compromised
  node can sign arbitrary files under its own identifier, but those
  signatures are trivially identified as belonging to that node. The damage
  is contained to that node's reputation.

### Attack vectors

| Attack | Impact | Mitigation |
|--------|--------|------------|
| DNS spoofing | Redirect lookups to attacker's node | DNSSEC, identifier pinning, out-of-band discovery |
| Node compromise | Forge signatures for that node | Node-level security; reputation-based revocation |
| Malicious proxy | Lie about verification results | Verify via multiple independent nodes |
| Sybil attack | Create many fake nodes | Rate-limit identifier registration; reputation scoring |
| Salt leak | Pre-compute hashes for that node | Rotate salt; notify verifiers via /.well-known |

## Autonomy and Algorithm Freedom

Every node chooses its own signing mechanism. The system defines only the
wiring protocol (signature format, DNS discovery, API endpoints), not the
cryptography.

A node might use:
- **SHA-256 with a secret salt** (the current system — simplest, no key
  management).
- **Ed25519 signatures** (asymmetric, publicly verifiable if the public key
  is published).
- **Argon2 with a per-file pepper** (memory-hard, resists GPU-based attacks).
- **A future quantum-resistant algorithm** (upgraded without coordinating
  with anyone).

The `signature_data` portion of the embedded signature is opaque. Only the
owning node needs to parse and verify it. Other nodes store and forward it
verbatim.

## GDPR and Legal Separation

Each node is a separate data controller. A user who signs files on their
own node keeps all data — database records, signing keys, salt — on
infrastructure they control. No other node has a copy.

- A verification request to another node is a transient API call, not a data
  transfer. The verifying node receives the file hash and responds with a
  boolean and chain metadata — it doesn't store the file or the signature.
- A user who wants to delete all signature records deletes them from their
  own node. No other node is affected.
- A court order directed at one node cannot compel disclosure of data
  belonging to another node.

## Redundancy and High Availability

The per-node architecture does not mandate redundancy, but individual nodes
can achieve it in standard ways:

- **Database replication** (MySQL Group Replication, read replicas).
- **Load-balanced API endpoints** behind a single DNS name.
- **Backup and restore procedures** for the salt and database.

A node whose identifier DNS points to a load balancer appears as a single
node to the rest of the system. Internally, it can be a cluster of any size.

## Comparison to Other Approaches

| Dimension | Current (single-node) | Gossip replication | Blockchain | DNS Federation |
|---|---|---|---|---|
| Shared secret | Yes (one salt) | Yes (shared salt) | No (asymmetric) | No (per-node salt) |
| Offline verification | No (needs salt) | No (needs salt) | Yes (public keys) | Optional (/well-known) |
| Node autonomy | None | None | None (same chain) | Complete |
| Infrastructure | One server | Cluster | Full node or L2 | One server + DNS |
| GDPR complexity | One controller | All nodes replicate | Immutable public data | Per-node controller |
| Algorithm flexibility | Fixed | Fixed | Fixed | Unlimited |

## Open Questions

- **Identifier revocation.** If a node goes offline permanently, its
  signatures become unverifiable. A revocation mechanism (transferring the
  identifier to an archive node that stores the old salt) would address this
  but introduces trust in the archive operator.
- **Reputation tracking.** A federated system naturally supports reputation —
  nodes that respond quickly and truthfully are trusted more. This could be
  formalised into a simple scoring protocol where verifiers share feedback.
- **DNS root governance.** Who runs `photo-verify.org`? What happens if the
  domain expires? A multi-signatory governance model or a fallback to
  ENS/Handshake (blockchain-based DNS) would eliminate this single point of
  failure.
- **Caching verified responses.** A verified result from a node could be
  signed and cached by proxies, reducing load on popular nodes. The cache
  invalidation protocol needs to be specified (time-based TTL, or explicit
  revocation via the node's /.well-known endpoint).
