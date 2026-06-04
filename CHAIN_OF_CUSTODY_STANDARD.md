# Chain of Custody — Image Authentication Standard

## Overview

Chain of Custody is a lightweight standard for authenticating raster image
files by embedding SHA-256 checksums as private TIFF tags and recording them
in a database with author attribution. Successive signatures are linked to
form an auditable chain of custody.

**Reference implementation:** PHP library in this repository.

---

## Private TIFF Tag

| Property    | Value        |
|-------------|--------------|
| Tag ID      | 65000        |
| Name        | ChainOfCustodySignature |
| Type        | 2 (ASCII)    |
| Count       | 65 bytes     |
| Data format | 64-character hex-encoded SHA-256 digest followed by a NUL byte |

Tag 65000 falls within the **developer private range** (65000–65535) and
should not conflict with any registered public tags.

---

## Signature Storage

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

## Database Schema

The chain of custody is recorded in a self-referencing table:

```sql
CREATE TABLE chain_of_custody_signatures (
    id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    signature_hash  CHAR(64)     NOT NULL COMMENT 'SHA-256 hex',
    author_name     VARCHAR(255) NOT NULL,
    file_name       VARCHAR(1024) NOT NULL,
    previous_id     BIGINT UNSIGNED NULL,
    created_at      TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_signature_hash (signature_hash),
    CONSTRAINT fk_previous_signature
        FOREIGN KEY (previous_id) REFERENCES chain_of_custody_signatures(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

- `signature_hash` — SHA-256 digest of the file content (excluding the CoC
  IFD) at the time of signing.
- `previous_id` — links to the previous signature in the chain; `NULL` for
  the first signature.

Unique on `signature_hash` is deliberately NOT enforced because re-signing an
unchanged file produces the same hash but represents a separate signing event.

---

## Signature Lifecycle

### First signature

```
File (unsigned) → SHA-256 → H₁ → embed H₁ as tag 65000 → store H₁ + author in DB
```

### Re-signature

```
File (signed with H₁) → verify H₁ → SHA-256 → H₂ → update tag with H₂
                                                          → store H₂ → H₁ in DB
```

If the file content has not changed since H₁, then H₂ = H₁ and the file tag
need not be updated (the DB chain entry is still recorded).

---

## Supported Formats

| Format | Mechanism | Overhead | Status |
|--------|-----------|----------|--------|
| TIFF   | Private tag 65000 in appended IFD | 83 bytes | ✅ Supported |
| JPEG   | APP8 marker with `CoC\0` identifier | 73 bytes | ✅ Supported |
| PNG    | Private ancillary chunk `coCs` | 77 bytes | ✅ Supported |
| BigTIFF| — | — | ❌ Not supported (64-bit offsets) |

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

## Demo Scripts

The repository ships with demo scripts in the `demo/` directory for all
three supported formats:

| Script | Arguments | Reads | Writes | Action |
|--------|-----------|-------|--------|--------|
| `sign.php` | `<file>` | any image | `<base>-signed.<ext>` | First-time signature |
| `check.php` | `<file>` | signed image | — | Verify + show chain |
| `update.php` | `<file>` | signed image | `<base>-signed-signed.<ext>` | Re-sign + verify + show chain |

The format is auto-detected from the file content — no extension-based
switching is needed.

Quick-start examples (hardcoded paths) are also provided as `sign-jpg.php`,
`check-jpg.php`, `update-jpg.php`, and their `-png` counterparts.

### Example workflow

```bash
# 1. Sign an image
php demo/sign.php demo/image.jpg

# 2. Verify the signed copy
php demo/check.php demo/image-signed.jpg

# 3. Re-sign with a new author (extends the chain)
php demo/update.php demo/image-signed.jpg

# 4. Inspect the full chain (now 3 entries)
php demo/check.php demo/image-signed-signed.jpg
```

---

## Security Considerations

- **Hash:** SHA-256 (collision-resistant for practical purposes).
- **Tag placement:** Appended IFD — does not modify existing TIFF structure
  beyond updating one 4-byte offset pointer.
- **Database trust:** The chain of custody is only as trustworthy as the
  database. Protect the database with access controls and backups.
- **Verification:** Uses `hash_equals()` for timing-safe comparison.
- **File integrity:** Any modification to the file between the TIFF header
  and the CoC IFD (exclusive) will cause verification to fail.
