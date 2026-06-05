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

## Tabs

| Tab | Auth | Description |
|-----|------|-------------|
| Home | Public | Project blurb + quick file verification |
| Sign | Required | Upload and sign a file |
| Check | Public | Verify a signed file + view chain of custody |
| Lookup | Public | Upload unsigned file, search database by hash |
| Update | Required | Two-file update to extend the chain |
| Feedback | Public | Message form with simple captcha, emailed to admin |

## Authentication

All signature operations require a logged-in user. Public tabs:

| Route | Description |
|---|---|
| `?action=login` | Login tab (email + password) |
| `?action=register` | Registration form with email verification |
| `?action=verify&token=xxx` | Email verification link |
| `?action=logout` | Destroy session, redirect to home |

- Passwords hashed with `bcrypt` via `password_hash()`
- Email verification uses SMTP relay configured in `config.php['smtp']`
- Verified users are stored in the `users` table with `email_verified=1`
- Protected tabs redirect to the login tab with a `redirect` parameter

## Feedback Captcha

The feedback form uses a simple anti-spam captcha. A question is picked
at random from the `CAPTCHA_QUESTIONS` constant (defined at the top of
`index.php`). The expected answer is stored in the session. On submission
the answer is compared case-insensitively. A new question is generated
after each attempt regardless of success.

## Architecture

`index.php` is a self-contained single-page application. It uses:

- **Routing**: `?action=home|sign|check|lookup|update|feedback|login|register|verify|logout|download`
- **Library**: `src/ChainOfCustody.php` for all signature operations (uses `user_id` from session)
- **Temp storage**: `sys_get_temp_dir()` for upload processing and download tokens
- **No JavaScript framework** — vanilla PHP and CSS
- **SMTP**: built-in `stream_socket_client` for email verification and feedback delivery

### Request flow

| Method + Action | Auth | Description |
|---|---|---|
| GET / | public | `renderPage('home', ...)` |
| POST ?action=check | public | `handleCheckAction()` — verify file signature |
| POST ?action=lookup | public | `handleLookupAction()` — hash lookup |
| POST ?action=feedback | public | `handleFeedbackAction()` — captcha + email |
| GET ?action=login | public | Login tab form |
| POST ?action=login | public | `handleLoginPost()` — redirects to original tab |
| POST ?action=sign | required | `handleSignAction()` — uses `$_SESSION['user_id']` |
| POST ?action=update | required | `handleUpdateAction()` — two files, links chain |
| GET ?action=download | public | `handleDownload()` — serve signed file, cleanup |

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
