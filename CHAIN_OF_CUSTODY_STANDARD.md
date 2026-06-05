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
| TIFF   | Private tag 65000 in appended IFD | 83 bytes | ✅ Supported |
| CR2    | Same as TIFF (same magic number 42) | 83 bytes | ✅ Via TIFF handler |
| NEF    | Same as TIFF (same magic number 42) | 83 bytes | ✅ Via TIFF handler |
| JPEG   | APP8 marker with `CoC\0` identifier | 73 bytes | ✅ Supported |
| PNG    | Private ancillary chunk `coCs` | 77 bytes | ✅ Supported |
| CR3    | ISOBMFF box `CoC\0` appended at end | 73 bytes | ✅ Supported |
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
| Count       | 65 bytes     |
| Data format | 64-character hex-encoded SHA-256 digest followed by a NUL byte |

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
|     count=65, offset → data |
|   next_ifd_offset: 0        |
+-----------------------------+
| CoC Signature Data          |  ← appended (65 bytes)
|   "abc123...def\0"          |
+-----------------------------+
```

Total overhead per signing: **83 bytes**.

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
FF E8 00 47      APP8 marker + length (71 = 2 + 4 + 65)
43 6F 43 00      "CoC\0" identifier
[64 hex chars]    SHA-256 hex digest
00                NUL terminator
...               remaining JPEG markers and data
FF D9             EOI
```

### Verification

The APP8 segment (73 bytes total) is removed from the file and SHA-256 is
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
│  4 bytes: data length = 65            │
│  4 bytes: type = "coCs"              │
│ 65 bytes: SHA-256 hex + NUL          │
│  4 bytes: CRC-32 over type + data    │
└───────────────────────────────────────┘
```

### CRC-32

The chunk CRC is computed and stored when the chunk is created or updated.
If the hash is modified in-place (`updateSignature`), the CRC is recalculated
to maintain chunk integrity. PNG decoders that encounter an invalid CRC may
reject the file, so correct CRC values are required.

### Verification

The entire `coCs` chunk (77 bytes) is removed from the file. SHA-256 is
computed on the remaining data and compared to the stored hash.

---

## CR3 Format (Canon Raw v3)

### Storage

CR3 is based on ISO Base Media File Format (ISOBMFF / ISO 14496-12). The
signature is stored in a private top-level box with type `CoC\0` appended
at the end of the file.

```
┌─ Box structure ──────────────────────────────────────┐
│  4 bytes: big-endian box size (73)                    │
│  4 bytes: box type = "CoC\0"                         │
│ 65 bytes: SHA-256 hex + NUL                          │
└───────────────────────────────────────────────────────┘
```

### Detection

The handler probes the file for an `ftyp` box with the major brand `crx `,
which identifies CR3 files.

### Verification

The `CoC\0` box (73 bytes) is removed from the file. SHA-256 is computed on
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
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_signature_hash (signature_hash),
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
```

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

Email verification during registration uses an SMTP relay configured in the
config file.

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
