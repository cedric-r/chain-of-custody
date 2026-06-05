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
├── SignatureStore.php          # PDO/MySQL store for signature records + user accounts
config.example.php              # Template DB configuration (copy to config.php)
schema.sql                      # Database DDL (users + signatures)
migrate.sql                     # Migration script for existing installations
CHAIN_OF_CUSTODY_STANDARD.md    # Tag and protocol specification
PROJECT.txt                     # Project description
www/
├── index.php                   # Web interface (single-page app with auth)
├── config.php                  # Website DB + SMTP configuration
├── photo-verify-logo-transparent.png
├── CLAUDE.md                   # Website documentation
└── GOAL.md                     # Original requirements
demo/
├── sign.php                    # Sign any file
├── check.php                   # Verify + show chain
├── update.php                  # Two-file update: <signed> <modified>
├── image.jpg, .png, .tif       # Sample images
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
- **Salt** — a configurable `hash_salt` is appended to the inner hash before
  the final SHA-256, preventing pre-computed hash lookups.
- **Authentication** — `checkSignature()` returns `authenticated=true` only
  when BOTH the embedded hash matches the file content AND a matching record
  exists in the database. The `hash_valid` field indicates whether the content
  hash matches independently of the DB record.

## Usage

```php
require_once 'src/ChainOfCustody.php';

$coc = new ChainOfCustody('config.php');

// Sign a file — returns the stored hash
$hash = $coc->createSignature('/path/to/image.tif', 1);       // userId

// Sign and return binary data without writing to disk
$signedData = $coc->createSignedFile('/path/to/image.jpg', 1); // userId

// Update chain of custody (original signed + modified file)
$result = $coc->updateChainOfCustody(
    '/path/to/original-signed.tif',
    '/path/to/modified.tif',
    1                                     // userId
);
$signedModified = $result['data'];

// Verify a signed file
$result = $coc->checkSignature('/path/to/image.tif');
if ($result['authenticated']) {
    echo "File is authentic. Signed by: " . $result['signature']['author_name'];
}

// checkSignature returns:
//   authenticated=true  — hash matches AND DB record exists
//   hash_valid=true     — hash matches (even without DB record)
//   hash=null           — no embedded signature found

// Check the full chain
$chain = $coc->checkChainOfCustody('/path/to/image.tif');
foreach ($chain['chain'] as $link) {
    echo "{$link['author_name']} — {$link['created_at']} ({$link['signature_hash']})";
}

// Look up an unsigned file by content hash
$lookup = $coc->lookupSignature('/path/to/unsigned.jpg');
if ($lookup['found']) {
    echo "Matched signed file by: " . $lookup['record']['author_name'];
}
```

## Setup

1. Copy `config.example.php` to `config.php` and fill in MySQL credentials.
   Set `hash_salt` to a random hex string (generate with
   `php -r "echo bin2hex(random_bytes(16));"`).
2. Run `schema.sql` against your MySQL database for a fresh install, or
   `migrate.sql` to upgrade an existing installation.
3. `require_once 'src/ChainOfCustody.php'` — the autoload chain loads all
   dependencies.

## Demo Scripts

```
demo/
├── sign.php      # Sign any file:   php demo/sign.php <file>
├── check.php     # Verify a signed file + show chain
├── update.php    # Two-file update: php demo/update.php <signed> <modified>
├── image.jpg     # Sample images shipped with the repo
├── image.png
└── image.tif
```

Examples:

```bash
# Sign a file
php demo/sign.php demo/image.jpg        # → demo/image-signed.jpg

# Verify a signed file and show its chain of custody
php demo/check.php demo/image-signed.jpg

# Update chain of custody: verify original, sign modified, link records
php demo/sign.php demo/image.jpg                          # first sign it
php demo/update.php demo/image-signed.jpg demo/image-signed.jpg  # → demo/image-signed-updated.jpg
```

## Web Interface

The `www/` directory contains a single-page PHP application with user
authentication. It provides Sign, Check, Lookup, Update, and Home tabs.

- **Home** (public) — project blurb + quick file verification
- **Sign** (login required) — upload and sign a file
- **Check** (public) — verify a signed file and view its chain of custody
- **Lookup** (public) — upload an unsigned file to search the database by hash
- **Update** (login required) — two-file update to extend the chain
- Email verification via SMTP relay (configured in `www/config.php`)
- Session-based authentication with bcrypt password hashing

Run with: `php -S localhost:8000 -t www/`

## Config Reference

```php
return [
    'hash_salt' => '',           // Secret salt for hash computation
    'host'     => '127.0.0.1',   // MySQL host
    'port'     => 3306,           // MySQL port
    'dbname'   => 'chain_of_custody',
    'username' => 'root',
    'password' => '',
    'charset'  => 'utf8mb4',
    'smtp'     => [              // SMTP relay for email verification
        'host'       => '...',
        'port'       => 25,
        'auth'       => false,
        'from_email' => 'noreply@example.org',
        'from_name'  => 'Chain of Custody',
    ],
];
```

## Database

Two tables:

- **`users`** — id, email, password_hash, name, email_verified,
  verification_token, verification_token_expires, created_at
- **`chain_of_custody_signatures`** — id, user_id, signature_hash, author_name,
  file_name, previous_id, created_at

`signature_hash` is SHA-256 of the unsigned file content, optionally salted
via the `hash_salt` config value. `previous_id` links to the previous
signature in the chain.
