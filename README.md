# Chain of Custody

PHP library that authenticates image and raw camera files (JPEG, PNG, TIFF, CR2, CR3, NEF) by embedding SHA-256 checksums using format-specific metadata mechanisms and recording them with user attribution in a MySQL database. Successive signatures form an auditable chain of custody.

## Features

- **Sign** — embed a SHA-256 hash directly into image files using private TIFF tags, JPEG APP8 markers, PNG ancillary chunks, or ISOBMFF boxes
- **Verify** — check that the file content matches its embedded signature and that a database record exists
- **Lookup** — find whether an unsigned file matches any known signature by content hash
- **Update** — verify an original signed file, then sign a modified version and link the new signature to the original in the database
- **Multi-format** — auto-detects format from file content, no extension sniffing
- **Salted hashes** — optional configurable salt prevents pre-computed hash lookups
- **User accounts** — registration with email verification, session-based authentication
- **OAuth login** — sign in with Google or GitHub (optional, configured in config)
- **Auth provenance** — authentication method (local/google/github) shown next to user name in signature records
- **REST API** — remote signing, verification, and lookup with API key authentication
- **Distributed** — per-node identifiers for federated verification across independent servers
- **Recursive chain resolution** — cross-node chains are resolved automatically by forwarding to each node's `/chain` endpoint
- **Password reset** — forgot/reset flow via email
- **API key management** — generate and revoke API keys for remote access
- **Web interface** — single-page PHP application with Sign, Check, Lookup, Update, API Keys, Feedback, GDPR, and Home tabs
- **Captcha** — feedback form protected by simple Q&A captcha

## Supported Formats

| Format | Mechanism | Overhead |
|--------|-----------|----------|
| TIFF | Private tag 65000 in appended IFD | 101 bytes |
| CR2 | Same as TIFF (same magic number) | 101 bytes |
| NEF | Same as TIFF (same magic number) | 101 bytes |
| JPEG | APP8 marker `FF E8 "CoC\0"` | 91 bytes |
| PNG | Private ancillary chunk `coCs` | 95 bytes |
| CR3 | ISOBMFF box `CoC\0` appended at end | 91 bytes |

## Quick Start

### Requirements

- PHP 8.0+
- MySQL 8.0+
- PHP PDO MySQL extension (`pdo_mysql`)

### Installation

```bash
git clone https://github.com/your-org/chain-of-custody.git
cd chain-of-custody

# Create the database
mysql -u root -p < schema.sql

# Copy and edit configuration
cp config.example.php config.php
# Set your MySQL credentials and a random hash_salt

# Or for the web interface
cp config.example.php www/config.php
```

### CLI Demos

```bash
# Sign a file
php demo/sign.php demo/image.jpg         # → demo/image-signed.jpg

# Verify a signed file
php demo/check.php demo/image-signed.jpg

# Update the chain (sign a modified file, linked to the original)
php demo/update.php demo/image-signed.jpg demo/image-signed.jpg
```

### Web Interface

```bash
php -S localhost:8000 -t www/
```

Open http://localhost:8000 in a browser.

### Production Deployment — Apache

**Web interface** (`/etc/apache2/sites-enabled/photo-verify.org.conf`):

```apache
<VirtualHost *:443>
    ServerName photo-verify.org
    DocumentRoot /var/www/photo-verify.org/www

    RewriteEngine On
    # Pass Authorization header for API calls from the website
    RewriteCond %{HTTP:Authorization} ^(.+)$
    RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]

    ErrorLog ${APACHE_LOG_DIR}/photo-verify.org-error.log
    CustomLog ${APACHE_LOG_DIR}/photo-verify.org-access.log combined

    SSLCertificateFile /etc/letsencrypt/live/photo-verify.org/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/photo-verify.org/privkey.pem
    Include /etc/letsencrypt/options-ssl-apache.conf
</VirtualHost>
```

**API** (`/etc/apache2/sites-enabled/api.photo-verify.org.conf`):

```apache
<VirtualHost *:443>
    ServerName api.photo-verify.org
    DocumentRoot /var/www/photo-verify.org/api

    # Pass Authorization header through to PHP
    SetEnvIf Authorization "(.*)" HTTP_AUTHORIZATION=$1

    RewriteEngine On
    RewriteCond %{HTTP:Authorization} ^(.+)$
    RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteRule ^(.*)$ index.php [QSA,L]

    # Node metadata (static fallback — served before the rewrite rules)
    <Location "/.well-known/chain-of-custody">
        ForceType application/json
    </Location>

    ErrorLog ${APACHE_LOG_DIR}/api.photo-verify.org-error.log
    CustomLog ${APACHE_LOG_DIR}/api.photo-verify.org-access.log combined

    SSLCertificateFile /etc/letsencrypt/live/api.photo-verify.org/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/api.photo-verify.org/privkey.pem
    Include /etc/letsencrypt/options-ssl-apache.conf
</VirtualHost>
```

### Production Deployment — Nginx

**Web interface** (`/etc/nginx/sites-enabled/photo-verify.org`):

```nginx
server {
    listen 443 ssl;
    server_name photo-verify.org;

    root /var/www/photo-verify.org/www;
    index index.php;

    ssl_certificate     /etc/letsencrypt/live/photo-verify.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/photo-verify.org/privkey.pem;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php8.3-fpm.sock;
        fastcgi_param PHP_VALUE "upload_max_filesize=200M
                                  post_max_size=200M
                                  max_execution_time=300";
    }
}
```

**API** (`/etc/nginx/sites-enabled/api.photo-verify.org`):

```nginx
server {
    listen 443 ssl;
    server_name api.photo-verify.org;

    root /var/www/photo-verify.org/api;
    index index.php;

    ssl_certificate     /etc/letsencrypt/live/api.photo-verify.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.photo-verify.org/privkey.pem;

    # Node metadata — static file or pass to PHP
    location = /.well-known/chain-of-custody {
        try_files $uri /index.php?$query_string;
    }

    location / {
        try_files $uri /index.php?$query_string;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php8.3-fpm.sock;
        fastcgi_param PHP_VALUE "upload_max_filesize=200M
                                  post_max_size=200M
                                  max_execution_time=300";
        # Pass Authorization header to PHP
        fastcgi_param HTTP_AUTHORIZATION $http_authorization;
    }
}
```

## Library API

```php
require_once 'src/ChainOfCustody.php';

$coc = new ChainOfCustody('config.php');

// Sign a file (modifies in-place)
$hash = $coc->createSignature('/path/to/image.tif', 1);       // userId

// Sign and return binary data (file on disk unchanged)
$signedData = $coc->createSignedFile('/path/to/image.jpg', 1); // userId

// Verify a signed file
$result = $coc->checkSignature('/path/to/image.tif');
if ($result['authenticated']) {
    echo "Signed by: " . $result['signature']['author_name'];
}
// $result['hash_valid'] indicates whether content matches independently of DB

// Full chain of custody
$chain = $coc->checkChainOfCustody('/path/to/image.tif');
foreach ($chain['chain'] as $link) {
    echo "{$link['author_name']} — {$link['created_at']}";
}

// Look up an unsigned file by content hash
$lookup = $coc->lookupSignature('/path/to/unsigned.jpg');
if ($lookup['found']) {
    echo "Matched: " . $lookup['record']['author_name'];
}

// Update chain: verify original, sign modified, link records
$result = $coc->updateChainOfCustody(
    '/path/to/original-signed.tif',
    '/path/to/modified.tif',
    1                                      // userId
);
file_put_contents('modified-signed.tif', $result['data']);
```

## Configuration

```php
<?php
return [
    'hash_salt' => '',            // Secret salt (generate: php -r "echo bin2hex(random_bytes(16));")
    'node_id'   => '',            // Unique 16-char hex node ID (generate: php bin/generate-node-id)
    'host'      => '127.0.0.1',   // MySQL host
    'port'      => 3306,          // MySQL port
    'dbname'    => 'chain_of_custody',
    'username'  => 'root',
    'password'  => '',
    'charset'   => 'utf8mb4',
    'smtp'      => [
        'host'               => '192.168.233.9',
        'port'               => 25,
        'auth'               => false,
        'from_email'         => 'noreply@example.org',
        'from_name'          => 'Chain of Custody',
        'feedback_recipient' => '',   // Admin email for feedback submissions
    ],

    // OAuth provider credentials (optional — omit for local-only auth)
    'oauth' => [
        'google' => [
            'client_id'     => '',
            'client_secret' => '',
            'redirect_uri'  => 'https://photo-verify.org/?action=oauth_callback&provider=google',
        ],
        'github' => [
            'client_id'     => '',
            'client_secret' => '',
            'redirect_uri'  => 'https://photo-verify.org/?action=oauth_callback&provider=github',
        ],
    ],
];
```

## Database

### Tables

**`users`** — registered user accounts

| Column | Type | Description |
|--------|------|-------------|
| id | BIGINT UNSIGNED | Primary key |
| email | VARCHAR(255) | Unique, used for login |
| password_hash | VARCHAR(255) | bcrypt hash |
| name | VARCHAR(255) | Display name |
| email_verified | TINYINT(1) | 1 after email verification |
| verification_token | VARCHAR(64) | Token for email verification link |
| verification_token_expires | DATETIME | Token expiry |
| auth_provider | VARCHAR(32) | Authentication method: local, google, github |
| provider_id | VARCHAR(255) | Unique ID from the OAuth provider |
| created_at | TIMESTAMP | Account creation time |

**`chain_of_custody_signatures`** — signature records

| Column | Type | Description |
|--------|------|-------------|
| id | BIGINT UNSIGNED | Primary key |
| user_id | BIGINT UNSIGNED | FK to users.id |
| signature_hash | CHAR(64) | SHA-256 hex (optionally salted) |
| author_name | VARCHAR(255) | Denormalized user name at signing time |
| file_name | VARCHAR(1024) | Original file name |
| previous_id | BIGINT UNSIGNED | FK to previous signature in chain (legacy) |
| previous_hash | VARCHAR(128) | Full signature payload of the previous link (cross-node compatible) |
| created_at | TIMESTAMP | Signature creation time |

### Migration

For fresh installations:

```bash
mysql -u root -p chain_of_custody < schema.sql
```

For upgrading an existing installation:

```bash
mysql -u root -p chain_of_custody < migrate.sql
```

## Project Structure

```
src/
├── ChainOfCustody.php          # Main API — format-agnostic dispatch
├── ImageSignatureHandler.php   # Abstract base class + exceptions
├── TiffSignatureHandler.php    # TIFF tag 65000, appended IFD — also handles CR2, NEF
├── JpegSignatureHandler.php    # JPEG APP8 marker
├── PngSignatureHandler.php     # PNG coCs chunk
├── Cr3SignatureHandler.php     # CR3 ISOBMFF box
├── OAuthProvider.php           # Google/GitHub OAuth 2.0 helper
├── ApiKeyStore.php             # API key generation + authentication
├── NodeResolver.php            # DNS-based node discovery
└── SignatureStore.php          # PDO/MySQL store for signature records + users

config.example.php              # Template DB + SMTP + OAuth configuration
schema.sql                      # Database DDL (fresh install)
migrate.sql                     # Migration script (existing installs)
api-migrate.sql                 # API keys table migration
CHAIN_OF_CUSTODY_STANDARD.md    # Tag and protocol specification
DISTRIBUTED.md                  # Distributed architecture overview
DISTRIBUTED-PLAN.md             # Distribution implementation plan
PROJECT.txt                     # Project description
README.md                       # This file
sign-all.sh                     # Batch signing script

www/
├── index.php                   # Single-page web app with auth
├── config.php                  # DB + SMTP + OAuth configuration
├── photo-verify-logo-transparent.png
├── CLAUDE.md                   # Website documentation
└── GOAL.md                     # Original requirements

api/
├── index.php                   # REST API entry point
├── config.php                  # API DB configuration
└── CLAUDE.md                   # API documentation

tests/
├── run.php                     # Full test suite (97+ tests)
├── config.php                  # Test DB configuration
├── config.example.php          # Template for test config
├── CLAUDE.md                   # Test documentation

demo/
├── sign.php, check.php, update.php   # CLI demo scripts
├── image.jpg, image.png, image.tif   # Sample images
└── CLAUDE.md                   # Demo documentation

bin/
├── generate-node-id            # Node ID generator
├── register-node.sh            # Node registration script
└── CLAUDE.md                   # Utility documentation
```

## Web Interface Tabs

| Tab | Auth Required | Description |
|-----|---------------|-------------|
| Home | No | Project blurb + quick file verification |
| Sign | Yes | Upload and sign a file |
| Check | No | Verify a signed file + view chain of custody |
| Lookup | No | Upload unsigned file, search database by hash |
| Update | Yes | Two-file update to extend the chain (supports remote originals) |
| API Keys | Yes | Generate and revoke API keys for remote access |
| Feedback | No | Message form with captcha, emailed to admin |
| GDPR | No | GDPR compliance information |

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
on `ImageSignatureHandler` and registering the handler in the constructor.

## Security

- **Salted hashes** — prevents pre-computed hash lookups against the database
- **Two-factor authentication** — file hash match AND database record required for `authenticated=true`
- **Timing-safe comparison** — uses `hash_equals()` for hash verification
- **Format integrity** — verification removes the signature metadata in memory and hashes the remainder; any content modification breaks the signature
- **Database trust** — the chain of custody is only as trustworthy as the database; protect with access controls and backups

## License

GNU General Public License v3.0 or later.

---

Project website: https://photo-verify.org
