# Chain of Custody — PHP Library

PHP library that authenticates image files (TIFF, JPEG, PNG) by embedding
SHA-256 checksums using format-specific metadata mechanisms and recording them
with author attribution in a MySQL database. Successive signatures form an
auditable chain of custody.

Refer to `CHAIN_OF_CUSTODY_STANDARD.md` for the full tag and protocol spec.

## Project Structure

```
src/
├── ChainOfCustody.php          # Main API — format-agnostic dispatch
├── ImageSignatureHandler.php   # Abstract base class + exceptions
├── TiffSignatureHandler.php    # TIFF handler (tag 65000, appended IFD)
├── JpegSignatureHandler.php    # JPEG handler (APP8 marker)
├── PngSignatureHandler.php     # PNG handler (coCs chunk)
├── SignatureStore.php          # PDO/MySQL store for signature records
config.example.php              # Template DB configuration (copy to config.php)
schema.sql                      # Database DDL
CLAUDE.md                       # This file
CHAIN_OF_CUSTODY_STANDARD.md    # Tag and protocol specification
```

## Architecture

```
ImageSignatureHandler (abstract)
  ├── TiffSignatureHandler   TIFF tag 65000, appended IFD
  ├── JpegSignatureHandler   JPEG APP8 marker "CoC\0"
  └── PngSignatureHandler    PNG private chunk "coCs"
```

`ChainOfCustody` auto-detects the format and delegates to the matching
handler. Adding a new image format means implementing the 7 abstract methods
and registering the handler in the constructor.

## Format Storage Details

| Format | Mechanism | Overhead |
|--------|-----------|----------|
| TIFF   | Private tag 65000 in appended IFD | 83 bytes |
| JPEG   | APP8 marker `FF E8 "CoC\0"` | 73 bytes |
| PNG    | Private ancillary chunk `coCs` | 77 bytes |

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
$hash = $coc->createSignature('/path/to/image.tif', 'Alice');

// Sign and return binary data without writing to disk
$signedData = $coc->createSignedFile('/path/to/image.jpg', 'Bob');

// Verify
$result = $coc->checkSignature('/path/to/image.tif');
if ($result['authenticated']) {
    echo "File is authentic. Signed by: " . $result['signature']['author_name'];
}

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
├── sign.php      # Sign any file:   php demo/sign.php <file> → <base>-signed.<ext>
├── check.php     # Verify a signed file + show chain
├── update.php    # Re-sign a signed file: <base>-signed- signed.<ext>
│
├── sign-jpg.php  # Quick demos with hardcoded paths (no arguments needed)
├── check-jpg.php
├── update-jpg.php
├── sign-png.php
├── check-png.php
├── update-png.php
│
├── image.jpg     # Sample images shipped with the repo
├── image.png
└── image.tif
```

The three main scripts (`sign.php`, `check.php`, `update.php`) accept a file
path as their first argument and work with any supported format (JPEG, PNG,
TIFF). The format is auto-detected from the file content.

Examples:

```bash
# Sign a JPEG
php demo/sign.php demo/image.jpg        # → demo/image-signed.jpg

# Sign a PNG
php demo/sign.php demo/image.png        # → demo/image-signed.png

# Sign a TIFF
php demo/sign.php demo/image.tif        # → demo/image-signed.tif

# Verify a signed file and show its chain of custody
php demo/check.php demo/image-signed.jpg

# Re-sign an already-signed file
php demo/update.php demo/image-signed.jpg  # → demo/image-signed-signed.jpg

# Quick demo without typing arguments (uses image.jpg)
php demo/sign-jpg.php
php demo/check-jpg.php
php demo/update-jpg.php
```
