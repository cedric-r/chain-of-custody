# Distributed Chain of Custody — Implementation Plan

## Overview

Transform the single-node system into a DNS-federated network where each
node is autonomous, chooses its own signing algorithm, and is discoverable
via DNS. Files embed a node identifier so any verifier can route the
verification request to the node that created the signature.

The plan is organised in three phases, each delivering a working, deployable
increment.

---

## Phase 1 — Node Identity and Signature Format

Goal: every signed file carries a stable node identifier alongside the
signature hash. The local system still works as before, but the new
format lays the foundation for federation.

### 1a. Node identifier generation

Add `node_id` to the config. If absent, generate one on first run and
write it back to the config file (or a sidecar file).

```php
// In ChainOfCustody constructor
$this->nodeId = $config['node_id'] ?? $this->generateNodeId();
```

The node ID is 8 random bytes encoded as 16 hex chars.
e.g. `a1b2c3d4e5f67890`

**Files to modify:**
- `config.example.php` — add `node_id` with an empty default
- `www/config.php` — same
- `api/config.php` — same

### 1b. Flexible signature payload in all four handlers

Each handler currently embeds 65 fixed bytes (64 hex + NUL). Change this
to a variable-length payload:

```
[ 1 byte : node_id length (N) ]
[ N bytes: node_id ]
[ 1 byte : 0x3A — colon delimiter ]
[ remaining bytes: opaque signature data ]
```

The old 65-byte format (no leading length byte) is still accepted on
read — backward compatible.

**Concrete changes per handler:**

| Handler | Current storage | New payload size | Backward compat |
|---------|----------------|-----------------|----------------|
| TIFF | Tag value = 65 bytes | Tag value = 19 + sig_data | Tag length check |
| JPEG | APP8 data = 65 bytes | APP8 data = 19 + sig_data | Marker length check |
| PNG | chunk data = 65 bytes | chunk data = 19 + sig_data | Chunk length check |
| CR3 | box data = 65 bytes | box data = 19 + sig_data | Box size check |

The node_id overhead is 19 bytes (1 + 16 + 1 + 1 padding) per file.
Total overhead increase per format: TIFF +19, JPEG +19, PNG +19, CR3 +19.

**Files to modify:**
- `src/TiffSignatureHandler.php`
- `src/JpegSignatureHandler.php`
- `src/PngSignatureHandler.php`
- `src/Cr3SignatureHandler.php`
- `src/ImageSignatureHandler.php` — maybe add shared helpers

### 1c. Format detection on read

When `find()` extracts the signature, examine the first byte:
- If byte 0 == length of remaining bytes - 1 and byte N+1 == `:`, treat as
  new format. Extract node_id and signature_data.
- Otherwise treat as old format (legacy, node_id = `""`, signature_data =
  full 65 bytes).

Return both values in the info array:

```php
[
  'hash'           => '...',   // always the hash (for legacy compat)
  'node_id'        => 'a1b2...',
  'signature_data' => 'a1b2...|abc...',
  'hashDataPos'    => ...,
  ...
]
```

### 1d. ChainOfCustody changes

The `ChainOfCustody` class needs to:

1. Generate and store a node ID.
2. Pass the node ID through to `signData()` so it's embedded in the file.
3. In `checkSignature()`, after extracting the node_id and signature_data,
   handle two cases:
   - `node_id == ""` or matches local node → verify locally (current logic)
   - `node_id != local node` → this will be handled in Phase 2

Initially, if the node_id doesn't match, return a new result:

```php
[
  'authenticated' => false,
  'hash_valid'    => null,
  'hash'          => null,
  'signature'     => null,
  'node_id'       => 'a1b2...',
  'requires_remote' => true,
]
```

The website displays: "This file was signed by a different node.
Forward verification to that node?"

**Files to modify:**
- `src/ChainOfCustody.php` — add `nodeId` property, pass through signing,
  detect remote signatures

### 1e. Tests

- Unit test: embed signature with node_id, extract it, verify round-trip
- Unit test: old 65-byte format still readable
- Unit test: local node_id matches, signature verifies
- Integration test: create signature, check it (local), passes

**Files to modify:**
- `tests/run.php`

---

## Phase 2 — Remote Verification and Forwarding

Goal: a node can verify a file signed by another node by forwarding the
verification request over HTTP.

### 2a. DNS resolver

Create a simple resolver that takes a node_id and returns the node's
verification URL:

```php
class NodeResolver
{
    /**
     * Resolve a node ID to its verification endpoint.
     * Looks up <node_id>.photo-verify.org via DNS.
     */
    public static function resolve(string $nodeId): string
    {
        $host = "{$nodeId}.photo-verify.org";
        $records = dns_get_record($host, DNS_CNAME | DNS_A);

        if (empty($records)) {
            throw new RuntimeException("Unknown node: {$nodeId}");
        }

        return 'https://' . $records[0]['target'] ?? $records[0]['ip'] . '/verify';
    }
}
```

**Files to create:**
- `src/NodeResolver.php`

### 2b. API /forward endpoint

Add `/forward` to the API (`api/index.php`):

```
POST /forward
  Fields: file (multipart)
  Reads the node_id from the file → resolves via DNS → POSTs to remote
  node's /verify → returns the result
```

```php
function handleForward(): void
{
    $upload = getUploadedFile('file');
    try {
        // Use local ChainOfCustody to extract node_id
        $coc  = new ChainOfCustody(CONFIG_PATH);
        $info = $coc->extractNodeId($upload['path']);

        if (empty($info['node_id'])) {
            jsonError(400, 'No node identifier found in file.');
        }

        // Resolve and forward
        $remoteUrl = NodeResolver::resolve($info['node_id']);
        $result    = forwardToNode($remoteUrl, $upload['path']);

        jsonResponse(['status' => 'ok', 'forwarded' => true, 'result' => $result]);
    } finally {
        cleanTemp($upload['path']);
    }
}
```

The `forwardToNode()` function POSTs the file to the remote `/verify`
endpoint using curl and returns the parsed JSON response.

### 2c. Website — remote verification UI

When the website's Check or Lookup tab encounters a file with a remote
node_id, show:

- A banner: "This file was signed by node `<node_id>`"
- A button: "Verify via `<node_id>.photo-verify.org`"
- The result once the remote node responds (or an error if unreachable)

**Files to modify:**
- `www/index.php` — add forwarding logic to `handleCheckAction()` and
  `handleLookupAction()`

### 2d. Website — cross-node verification from API Keys

If the user has API keys on multiple nodes, they could submit a file to
any node's `/forward` endpoint directly via curl. The website's API Keys
tab should document this:

```bash
curl -X POST https://api.photo-verify.org/forward \
  -H "Authorization: Bearer <key>" \
  -F "file=@signed.jpg"
```

**Files to modify:**
- `api/index.php` — register the `/forward` route
- `api/CLAUDE.md` — document the endpoint

### 2e. Tests

- Unit test: `NodeResolver::resolve()` with mock DNS
- Integration test: start a second node on a different port, sign a file,
  verify it via `/forward` on the first node
- Integration test: `/forward` returns proper error for unknown node_id

**Files to modify:**
- `tests/run.php`

---

## Phase 3 — Self-Verifiability and Ecosystem

Goal: nodes can optionally publish their verification parameters for
offline verification. An identifier registration process is documented.

### 3a. /.well-known endpoint

Each node exposes:

```
GET /.well-known/chain-of-custody
```

```json
{
  "node_id":           "a1b2c3d4e5f67890",
  "algorithm":         "SHA-256",
  "salt":              null,
  "public_key":        "MCowBQYD...",
  "public_key_type":   "Ed25519",
  "verification_url":  "https://api.mynode.org/verify",
  "signature":         "abc123..."
}
```

The `signature` is the node's self-signature over this metadata using the
node's private key (if `public_key` is set). Verifiers can cache this
document and verify files offline if the node publishes its key and salt.

**Files to create:**
- `api/well-known.php` — serves the metadata
- Or just add a route in `api/index.php`

### 3b. Offline verification support

When a node publishes `salt` in its `.well-known` document (null = not
published, empty string = no salt), any verifier can compute
`SHA-256(innerHash || salt)` and compare to the embedded hash without
querying the node.

For asymmetric keys, the verifier checks `verify(hash, signature, publicKey)`.

This is entirely opt-in. Nodes that don't publish stay opaque — verification
always requires a live query.

**Files to modify:**
- `src/ChainOfCustody.php` — optional `setRemoteNodeParams(nodeId, salt, publicKey)`

### 3c. Identifier registration process

Document how to register a node identifier on `photo-verify.org`:

1. Generate a node ID: `php -r "echo bin2hex(random_bytes(8));"`
2. Submit a pull request adding a CNAME record to the zone file:
   `<node_id>.photo-verify.org  IN  CNAME  your-server.com`
3. Prove ownership: serve a challenge token at
   `https://your-server.com/.well-known/coc-challenge`
4. The zone file is updated and signed. The identifier is live.

Provide a script (`register-node.sh`) that automates the challenge step.

### 3d. Ecosystem documentation

- `DISTRIBUTED.md` — already written, refine with Phase 1–3 details
- `CLAUDE.md` — mention distributed mode in the project overview
- `api/CLAUDE.md` — document `/forward` and `.well-known` endpoints

---

## Summary of Files

### New files

| File | Phase | Purpose |
|---|---|---|
| `src/NodeResolver.php` | 2 | DNS lookup for node identifiers |
| `register-node.sh` | 3 | Automated identifier registration |

### Modified files

| File | Phase | Change |
|---|---|---|
| `src/ChainOfCustody.php` | 1, 3 | Node ID generation, remote detection, offline params |
| `src/ImageSignatureHandler.php` | 1 | Shared helpers for node_id encoding/decoding |
| `src/TiffSignatureHandler.php` | 1 | Variable-length signature payload |
| `src/JpegSignatureHandler.php` | 1 | Same |
| `src/PngSignatureHandler.php` | 1 | Same |
| `src/Cr3SignatureHandler.php` | 1 | Same |
| `api/index.php` | 2 | `/forward` route and handler |
| `www/index.php` | 2 | Remote verification UI |
| `config.example.php` | 1 | `node_id` setting |
| `www/config.php` | 1 | `node_id` setting |
| `api/config.php` | 1 | `node_id` setting |
| `tests/run.php` | 1, 2 | Node ID and forwarding tests |
| `CLAUDE.md` | 3 | Distributed mode mention |
| `api/CLAUDE.md` | 3 | `/forward`, `.well-known` docs |

---

## Backward Compatibility

| Scenario | Phase 1 | Phase 2 | Phase 3 |
|---|---|---|---|
| Old file, old node | ✅ Works (local verify) | ✅ Works | ✅ Works |
| Old file, new node | ✅ Works (no node_id) | ✅ Works | ✅ Works |
| New file, new node (same) | ✅ Works (local verify) | ✅ Works | ✅ Works |
| New file, different node | ✅ Detected (remote flag) | ✅ Forwarded | ✅ Optional offline |
| New file, node not in DNS | ⚠️ Unknown node_id | ❌ Forward fails | ❌ Forward fails |

## Verification by Phase

- **Phase 1:** `php tests/run.php` — all existing tests pass + new node_id tests
- **Phase 2:** Two instances of the API running on different ports. Sign on
  instance A, verify via `/forward` on instance B.
- **Phase 3:** Publish `.well-known` on instance A, verify offline from
  instance B using the published salt.
