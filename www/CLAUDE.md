# Photo Verify — Web Interface

Single-page PHP application with user authentication for signing, checking,
and updating Chain of Custody signatures on image files (JPEG, PNG, TIFF).

## Files

```
www/
├── GOAL.md                              # Requirements
├── photo-verify-logo-transparent.png    # Logo
├── config.php                           # DB credentials + SMTP config
├── index.php                            # Main single-page app (auth + core logic)
└── CLAUDE.md                            # This file
```

## How to Run

```bash
php -S localhost:8000 -t www/
```

Then open `http://localhost:8000` in a browser.

## Authentication

All signature operations require a logged-in user. Public pages:

| Route | Description |
|---|---|
| `?action=login` | Login form (email + password) |
| `?action=register` | Registration form with email verification |
| `?action=verify&token=xxx` | Email verification link |
| `?action=logout` | Destroy session, redirect to login |

- Passwords hashed with `bcrypt` via `password_hash()`
- Email verification uses SMTP relay configured in `config.php['smtp']`
- Verified users are stored in the `users` table with `email_verified=1`
- All protected routes check `$_SESSION['user_id']` before processing

## Architecture

`index.php` is a self-contained single-page application. It uses:

- **Routing**: `?action=sign|check|update|download|login|register|verify|logout`
- **Library**: `src/ChainOfCustody.php` for all signature operations (uses `user_id` from session)
- **Temp storage**: `sys_get_temp_dir()` for upload processing and download tokens
- **No JavaScript framework** — vanilla PHP and CSS
- **SMTP**: built-in `stream_socket_client` for email verification (no PHPMailer)

### Request flow (protected)

| Method + Action | Description |
|---|---|
| GET / | `renderPage('sign', null)` — requires login |
| POST ?action=sign | `handleSignAction()` — uses `$_SESSION['user_id']` |
| POST ?action=check | `handleCheckAction()` — read-only |
| POST ?action=update | `handleUpdateAction()` — two files, links chain |
| GET ?action=download | `handleDownload()` — serve signed file, cleanup |

### Key Functions

- **`handlePost()`** — validates upload, dispatches to sign or check
- **`handleSignAction()`** — calls `$coc->createSignedFile()`, stores result in temp file with random token, shows success with hash + download link
- **`handleCheckAction()`** — calls `$coc->checkSignature()` and `$coc->checkChainOfCustody()`, renders result with chain table
- **`handleDownload()`** — serves the temp signed file with `Content-Disposition` header, cleans up after
- **`cleanOldTempFiles()`** — removes expired temp files older than 1 hour
- **`renderPage()`** — outputs full HTML page with logo, tabs, form, and result content

## Temp File Management

Files signed via the web interface are stored in `sys_get_temp_dir()` as `coc_<token>` + `coc_<token>.meta` (metadata JSON). A random 16-byte hex token prevents guessing. Temp files are:

- Deleted immediately after download
- Auto-expired after 1 hour via `cleanOldTempFiles()`

## Dependencies

- PHP 8.0+
- PHP MySQL/PDO extension (`pdo_mysql`)
- `src/ChainOfCustody.php` library
- MySQL database with `schema.sql` applied

## Security

- File extension validated against whitelist before processing
- `move_uploaded_file()` used for secure upload handling
- Author name sanitized with `strip_tags()` and `htmlspecialchars()` for output
- Download tokens validated as hex only — no path traversal
- Upload temp files cleaned immediately after processing
- Signed temp files deleted after download or expired after 1 hour
