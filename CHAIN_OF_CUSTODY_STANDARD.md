# Chain of Custody — Image Authentication Standard

## Overview

Chain of Custody is a lightweight standard for authenticating raster image and
raw camera files by embedding SHA-256 checksums using format-specific metadata
mechanisms and recording them in a MySQL database with user attribution.
Successive signatures are linked to form an auditable chain of custody.

**Reference implementation:** PHP library in this repository.
**Website:** https://photo-verify.org

---

## Supported Formats

| Format | Mechanism | Overhead | Status |
|--------|-----------|----------|--------|
| TIFF   | Private tag 65000 in appended IFD | 101 bytes | ✅ Supported |
| CR2    | Same as TIFF (same magic number 42) | 101 bytes | ✅ Via TIFF handler |
| NEF    | Same as TIFF (same magic number 42) | 101 bytes | ✅ Via TIFF handler |
| JPEG   | APP8 marker with `CoC\0` identifier | 91 bytes | ✅ Supported |
| PNG    | Private ancillary chunk `coCs` | 95 bytes | ✅ Supported |
| CR3    | ISOBMFF box `CoC\0` appended at end | 91 bytes | ✅ Supported |
| BigTIFF| — | — | ❌ Not supported (64-bit offsets) |

---

## TIFF / CR2 / NEF Format

### Storage

Tag 65000 falls within the **developer private range** (65000–65535) and
should not conflict with any registered public tags.

| Property    | Value        |
|-------------|--------------|
| Tag ID      | 65000        |
| Name        | ChainOfCustodySignature |
| Type        | 2 (ASCII)    |
| Count       | 83 bytes     |
| Data format | Node_id prefix (1 byte length + 16 bytes hex + 1 byte colon) + 64-character hex-encoded SHA-256 digest + NUL byte |

The signature is stored by appending a new Image File Directory (IFD) at the
end of the TIFF file's IFD chain. This is valid per the TIFF 6.0 specification,
which allows multiple IFDs chained via the `next IFD offset` field.

### File Layout (signed)

```
+-----------------------------+
| Original TIFF data          |  ← unchanged
|   ... IFD 1                 |
|   ... IFD N  (last original)|
|     next_ifd_offset: 0      |  ← changed to point at CoC IFD
+-----------------------------+
| CoC Signature IFD           |  ← appended (18 bytes)
|   entry_count: 1            |
|   tag 65000, type=ASCII,    |
|     count=83, offset → data |
|   next_ifd_offset: 0        |
+-----------------------------+
| CoC Signature Data          |  ← appended (83 bytes)
|   node_id_prefix + hash\0   |
+-----------------------------+
```

Total overhead per signing: **101 bytes**.

### Verification

The original file content is reconstructed in-memory by:

1. Zeroing the 4-byte `next_ifd_offset` pointer of the IFD that previously
   pointed to the CoC IFD (restoring the original "no further IFD" state).
2. Truncating the data at the start of the CoC IFD (excluding the appended
   IFD and its data).

SHA-256 is then computed on the reconstructed bytes and compared to the
hash stored in the tag.

---

## JPEG Format

### Storage

The signature is stored in a custom APP8 marker (0xFFE8) placed right after
the SOI marker:

```
FF D8             SOI
FF E8 00 5B      APP8 marker + length (89 = 2 + 4 + 83)
43 6F 43 00      "CoC\0" identifier
[node_id:1+16]    1 byte length + 16 hex chars node ID
3A                ":" colon delimiter
[64 hex chars]    SHA-256 hex digest
00                NUL terminator
...               remaining JPEG markers and data
FF D9             EOI
```

### Verification

The APP8 segment (91 bytes total) is removed from the file and SHA-256 is
computed on the remainder. The computed hash is compared to the stored hash.

### Rationale

JPEG's EXIF TIFF IFD structure could be used, but the APP8 marker approach
is simpler — no byte-order handling, no offset tables, and insertion/removal
are simple splice operations.

---

## PNG Format

### Storage

The signature is stored in a private ancillary chunk `coCs` (type code uses
lowercase for private and safe-to-copy conventions per the PNG specification).
The chunk is inserted right after the required IHDR chunk.

```
┌─ PNG file layout ────────────────────────────────────┐
│ PNG signature (8 bytes)                               │
│ IHDR chunk                                            │
│ coCs chunk (77 bytes)  ← private ancillary chunk      │
│ ... other chunks ...                                  │
│ IEND chunk                                            │
└───────────────────────────────────────────────────────┘

┌─ coCs chunk structure ────────────────┐
│  4 bytes: data length = 83            │
│  4 bytes: type = "coCs"              │
│ 83 bytes: node_id prefix + hash + NUL│
│  4 bytes: CRC-32 over type + data    │
└───────────────────────────────────────┘
```

### CRC-32

The chunk CRC is computed and stored when the chunk is created or updated.
If the hash is modified in-place (`updateSignature`), the CRC is recalculated
to maintain chunk integrity. PNG decoders that encounter an invalid CRC may
reject the file, so correct CRC values are required.

### Verification

The entire `coCs` chunk (95 bytes) is removed from the file. SHA-256 is
computed on the remaining data and compared to the stored hash.

---

## CR3 Format (Canon Raw v3)

### Storage

CR3 is based on ISO Base Media File Format (ISOBMFF / ISO 14496-12). The
signature is stored in a private top-level box with type `CoC\0` appended
at the end of the file.

```
┌─ Box structure ──────────────────────────────────────┐
│  4 bytes: big-endian box size (91)                    │
│  4 bytes: box type = "CoC\0"                         │
│ 83 bytes: node_id prefix + hash + NUL                │
└───────────────────────────────────────────────────────┘
```

### Detection

The handler probes the file for an `ftyp` box with the major brand `crx `,
which identifies CR3 files.

### Verification

The `CoC\0` box (91 bytes) is removed from the file. SHA-256 is computed on
the remaining data and compared to the stored hash.

---

## Hash Computation

The hash stored in both the file and the database is:

```
innerHash = SHA-256(fileContent)
storedHash = SHA-256(innerHash || salt)
```

The salt is configured via the `hash_salt` key in the configuration file.
When the salt is empty, `storedHash` equals `innerHash` (backward-compatible).
The salt prevents pre-computed hash lookups against the database.

### Signature payload format

The hash stored in the file (and used as `previous_hash` for chain linking)
includes an optional node identifier prefix:

```
[1 byte: node_id length (N)]
[N bytes: node_id hex string]  
[1 byte: colon delimiter]
[64 bytes: salted SHA-256 hex]
[1 byte: NUL terminator]
```

When no node_id is configured, the payload is just the 64-char hex + NUL
(65 bytes, legacy format). When configured, the payload is 83 bytes.
The node_id makes each payload self-describing — any verifier can parse
it to determine which node owns the signature.

---

## Database Schema

### Users table

```sql
CREATE TABLE users (
    id                        BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    email                     VARCHAR(255) NOT NULL UNIQUE,
    password_hash             VARCHAR(255) NOT NULL,
    name                      VARCHAR(255) NOT NULL,
    email_verified            TINYINT(1) NOT NULL DEFAULT 0,
    verification_token        VARCHAR(64) DEFAULT NULL,
    verification_token_expires DATETIME DEFAULT NULL,
    created_at                TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Signatures table

```sql
CREATE TABLE chain_of_custody_signatures (
    id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id         BIGINT UNSIGNED NOT NULL,
    signature_hash  CHAR(64) NOT NULL,
    author_name     VARCHAR(255) NOT NULL,
    file_name       VARCHAR(1024) NOT NULL,
    previous_id     BIGINT UNSIGNED NULL,
    previous_hash   VARCHAR(128) NULL,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_signature_hash (signature_hash),
    INDEX idx_previous_hash (previous_hash),
    INDEX idx_user_id (user_id),

    CONSTRAINT fk_previous_signature
        FOREIGN KEY (previous_id)
        REFERENCES chain_of_custody_signatures(id)
        ON DELETE SET NULL,
    CONSTRAINT fk_user_signature
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE RESTRICT
);
```

- `signature_hash` — SHA-256 digest of the file content (excluding the CoC
  metadata) at the time of signing, optionally salted.
- `user_id` — references the user who created the signature.
- `author_name` — denormalized copy of the user's display name at signing time.
- `previous_id` — links to the previous signature in the chain; `NULL` for
  the first signature.

Unique on `signature_hash` is deliberately NOT enforced because re-signing an
unchanged file produces the same hash but represents a separate signing event.

---

## Signature Lifecycle

### First signature

```
File (unsigned) → innerHash = SHA-256(data)
                → storedHash = SHA-256(innerHash || salt)
                → embed storedHash in file metadata
                → store storedHash + userId + fileName in DB
```

### Re-signature

```
File (signed) → verify existing signature
              → innerHash = computeOriginalHash()
              → storedHash = SHA-256(innerHash || salt)
              → update file metadata with storedHash
              → store new record linked to previous via previous_id
```

### Two-file update

```
Original (signed) → verify signature
Modified (unsigned) → innerHash = SHA-256(data)
                    → storedHash = SHA-256(innerHash || salt)
                    → embed storedHash in modified file
                    → store new record with previous_id → original's ID
                    → store previous_hash = original's full signature payload
```

### Cross-node chain resolution

When a file is checked, the chain follows `previous_hash` links backward.
If a `previous_hash` contains a node_id different from the local node,
the system forwards the hash to that node's `/chain` endpoint. The remote
node resolves its own chain segment (recursively forwarding if needed)
and returns the result. Segments are concatenated to form the complete
chain regardless of how many nodes the file has passed through.

```
Sign on Node A → signature X
Update on Node B (original: X) → signature Y
Update on Node C (original: Y) → signature Z

Check Z on Node C:
  → C finds Z (local), previous_hash → Node B
  → C forwards hash_Y to B's /chain
  → B finds Y (local), previous_hash → Node A
  → B forwards hash_X to A's /chain
  → A finds X, no previous_hash → returns [X]
  → B concatenates [Y, X] → returns to C
  → C concatenates [Z, Y, X] → displays full chain
```

### Known limitations

**Same server, same file, same hash.** If the same file is signed on the
same server twice (e.g. A → B → A), the two signatures produce identical
hashes (same content, same salt). The chain resolution detects this via
`findEarliestByHash()` which returns the original record to break the
cycle. However, the chain segment on server A will only show the original
signature, not the re-sign. This is a fundamental consequence of
hash-based linking — two records with the same hash cannot be
distinguished in the backward chain traversal. The workaround is to use
three nodes (A → B → C) when demonstrating distributed chain resolution.

### Lookup

```
Unsigned file → innerHash = SHA-256(data)
              → storedHash = SHA-256(innerHash || salt)
              → search DB for storedHash
              → if found: return record + chain
              → if not found: return "unknown"
```

---

## checkSignature Return Values

| Condition | authenticated | hash_valid | hash | signature |
|-----------|--------------|------------|------|-----------|
| Hash matches + DB record exists | true | true | hash | record |
| Hash matches + no DB record | false | true | hash | null |
| Hash doesn't match | false | false | hash | null |
| No embedded signature | false | null | null | null |

---

## Demo Scripts

```
demo/
├── sign.php      # php demo/sign.php <file>               → <base>-signed.<ext>
├── check.php     # php demo/check.php <file>              → verify + show chain
├── update.php    # php demo/update.php <signed> <modified>  → <base>-updated.<ext>
```

The test suite covers all handlers and integration flows:

```bash
php tests/run.php
```

Example workflow:

```bash
# 1. Sign an image
php demo/sign.php demo/image.jpg

# 2. Verify the signed copy
php demo/check.php demo/image-signed.jpg

# 3. Edit the image, then update the chain
php demo/update.php demo/image-signed.jpg demo/image-signed.jpg

# 4. Inspect the full chain (now 2 entries)
php demo/check.php demo/image-signed-updated.jpg
```

---

## Web Interface

The `www/` directory hosts a single-page PHP application with user
authentication and the following tabs:

| Tab | Auth | Description |
|-----|------|-------------|
| Home | Public | Project description + quick file verification |
| Sign | Required | Upload and sign a file |
| Check | Public | Verify a signed file + view chain of custody |
| Lookup | Public | Upload an unsigned file to search the database by hash |
| Update | Required | Two-file update to extend the chain |
| Feedback | Public | Send a message to the site admin via a form with simple captcha |

Email verification during registration uses an SMTP relay configured in the
config file. The feedback form also uses the same relay to deliver messages
to the `smtp.feedback_recipient` address.

## Captcha

The feedback form includes a simple captcha to deter automated submissions.
A random question is selected from the `CAPTCHA_QUESTIONS` array (e.g.
"What is 2 + 2?", "What colour are tomatoes?"). The expected answer is
stored server-side in the session. On submission the answer is compared
case-insensitively. A new question is picked after each attempt.

---

## Security Considerations

- **Hash:** SHA-256 with optional configurable salt.
- **Salt:** When configured, `hash_salt` prevents pre-computed hash lookups.
- **Tag placement:** Appended IFD — does not modify existing TIFF structure
  beyond updating one 4-byte offset pointer.
- **Database trust:** The chain of custody is only as trustworthy as the
  database. Protect the database with access controls and backups.
- **Verification:** Uses `hash_equals()` for timing-safe comparison.
- **File integrity:** Any modification to the file between the header and the
  CoC metadata (exclusive) will cause verification to fail.
- **Authentication:** `authenticated=true` requires both a valid hash AND a
  matching database record.

## License

GNU General Public License v3.0 or later.
