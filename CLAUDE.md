# Chain of Custody — PHP Library

PHP library that authenticates image and raw camera files (TIFF, JPEG, PNG, CR3,
plus CR2 and NEF via the TIFF handler) by embedding SHA-256 checksums using
format-specific metadata mechanisms and recording them with user attribution in
a MySQL database. Successive signatures form an auditable chain of custody.

Refer to `CHAIN_OF_CUSTODY_STANDARD.md` for the full tag and protocol spec.

## Project Structure

```
src/
├── ChainOfCustody.php          # Main API — format-agnostic dispatch
├── ImageSignatureHandler.php   # Abstract base class + exceptions
├── TiffSignatureHandler.php    # TIFF handler (tag 65000, appended IFD) — also handles CR2, NEF
├── JpegSignatureHandler.php    # JPEG handler (APP8 marker)
├── PngSignatureHandler.php     # PNG handler (coCs chunk)
├── Cr3SignatureHandler.php     # CR3 (Canon Raw v3) handler (ISOBMFF box)
├── SignatureStore.php          # PDO/MySQL store for signature records
config.example.php              # Template DB configuration (copy to config.php)
schema.sql                      # Database DDL
CLAUDE.md                       # This file
CHAIN_OF_CUSTODY_STANDARD.md    # Tag and protocol specification
```

## Architecture

```
ImageSignatureHandler (abstract)
  ├── TiffSignatureHandler   TIFF tag 65000, appended IFD (also CR2, NEF)
  ├── JpegSignatureHandler   JPEG APP8 marker "CoC\0"
  ├── PngSignatureHandler    PNG private chunk "coCs"
  └── Cr3SignatureHandler    CR3 ISOBMFF box "CoC\0"
```

`ChainOfCustody` auto-detects the format and delegates to the matching
handler. Adding a new image format means implementing the 7 abstract methods
and registering the handler in the constructor.

## Format Storage Details

| Format | Mechanism | Overhead |
|--------|-----------|----------|
| TIFF / CR2 / NEF | Private tag 65000 in appended IFD | 83 bytes |
| JPEG   | APP8 marker `FF E8 "CoC\0"` | 73 bytes |
| PNG    | Private ancillary chunk `coCs` | 77 bytes |
| CR3    | ISOBMFF box `CoC\0` appended at end | 73 bytes |

## Key Design Decisions

- **Format auto-detection** — each handler's `detect()` probes the file header.
- **Verification** — reconstructs the original file in memory by removing the
  signature metadata. No temporary files are created.
- **Re-signing** — when a signed file is signed again, the existing signature
  is updated with the new hash and linked to the previous record in the DB.
- **Multi-format** — `ChainOfCustody` dispatches to the correct handler.

## Usage

```php
require_once 'src/ChainOfCustody.php';

$coc = new ChainOfCustody('config.php');

// Sign a file (TIFF, JPEG, or PNG)
$hash = $coc->createSignature('/path/to/image.tif', 1);       // userId

// Sign and return binary data without writing to disk
$signedData = $coc->createSignedFile('/path/to/image.jpg', 1); // userId

// Update chain of custody (original signed + modified file)
$result = $coc->updateChainOfCustody(
    '/path/to/original-signed.tif',
    '/path/to/modified.tif',
    1                                     // userId — must match original signer
);
$signedModified = $result['data'];

// Verify
$result = $coc->checkSignature('/path/to/image.tif');
if ($result['authenticated']) {
    echo "File is authentic. Signed by: " . $result['signature']['author_name'];
}

// checkSignature returns:
//   authenticated=true  — hash matches AND DB record exists
//   hash_valid=true     — hash matches (even without DB record)
//   hash=null           — no embedded signature found

// Check the chain
$chain = $coc->checkChainOfCustody('/path/to/image.tif');
foreach ($chain['chain'] as $link) {
    echo "{$link['author_name']} — {$link['created_at']} ({$link['signature_hash']})";
}
```

## Setup

1. Copy `config.example.php` to `config.php` and fill in MySQL credentials.
2. Run `schema.sql` against your MySQL database.
3. `require_once 'src/ChainOfCustody.php'` — the autoload chain loads all
   dependencies.

## Demo Scripts

```
demo/
├── sign.php      # Sign any file:   php demo/sign.php <file>
├── check.php     # Verify a signed file + show chain
├── update.php    # Two-file update: php demo/update.php <signed> <modified>
│
├── image.jpg     # Sample images shipped with the repo
├── image.png
└── image.tif
```

The three main scripts work with any supported format (JPEG, PNG, TIFF),
auto-detected from the file content.

Examples:

```bash
# Sign a file
php demo/sign.php demo/image.jpg        # → demo/image-signed.jpg

# Verify a signed file and show its chain of custody
php demo/check.php demo/image-signed.jpg

# Update chain of custody: verify original, sign modified, link records
php demo/sign.php demo/image.jpg                          # first sign it
# edit demo/image-signed.jpg in an image editor
php demo/update.php demo/image-signed.jpg demo/image-signed.jpg  # → demo/image-signed-updated.jpg
```
