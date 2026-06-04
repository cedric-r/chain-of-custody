<?php

declare(strict_types=1);

/**
 * Chain of Custody — Web Interface
 *
 * Single-page application with user authentication. Supports signing,
 * checking, and updating image file signatures (TIFF, JPEG, PNG).
 *
 * Public routes:  login, register, verify, logout
 * Protected:      sign, check, update, download
 */

require_once __DIR__ . '/../src/ChainOfCustody.php';

define('ALLOWED_EXTENSIONS', ['jpg', 'jpeg', 'png', 'tif', 'tiff']);
define('MAX_FILE_SIZE', 100 * 1024 * 1024);
define('TEMP_FILE_TTL', 3600);
define('CONFIG_PATH', __DIR__ . '/config.php');

// ---------------------------------------------------------------------------
// Session & Routing
// ---------------------------------------------------------------------------

session_start();

$action = $_GET['action'] ?? 'sign';

if (!in_array($action, ['sign', 'check', 'update', 'download', 'login', 'register', 'logout', 'verify'], true)) {
    $action = 'sign';
}

// Public auth routes (no session required)
if (in_array($action, ['login', 'register', 'verify'], true)) {
    handleAuthRoute($action);
    exit;
}

// Logout
if ($action === 'logout') {
    session_destroy();
    header('Location: ?action=login');
    exit;
}

// Protected routes — check authentication
$userId   = (int) ($_SESSION['user_id'] ?? 0);
$userName = $_SESSION['user_name'] ?? '';

if ($userId === 0) {
    renderLoginPage(null);
    exit;
}

// ---------------------------------------------------------------------------
// Main routing
// ---------------------------------------------------------------------------

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    handlePost($action, $userId);
    exit;
}

if ($action === 'download') {
    handleDownload();
    exit;
}

if ($action === 'sign' || $action === 'check' || $action === 'update') {
    renderPage($action, null, $userName);
    exit;
}

// Fallback
renderPage('sign', null, $userName);

// ---------------------------------------------------------------------------
// Auth handlers
// ---------------------------------------------------------------------------

function handleAuthRoute(string $action): void
{
    if ($action === 'login') {
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            handleLoginPost();
        } else {
            renderLoginPage(null);
        }
        return;
    }

    if ($action === 'register') {
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            handleRegisterPost();
        } else {
            renderRegisterPage(null);
        }
        return;
    }

    // Verify email
    $token = $_GET['token'] ?? '';
    if ($token !== '') {
        handleVerifyEmail($token);
    } else {
        renderLoginPage('Invalid verification link.');
    }
}

function handleLoginPost(): void
{
    try {
        $config = loadConfig();
        $store  = new SignatureStore($config);

        $email    = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';

        if ($email === '' || $password === '') {
            renderLoginPage('Please enter your email and password.');
            return;
        }

        $user = $store->findUserByEmail($email);

        if ($user === null || !password_verify($password, $user['password_hash'])) {
            renderLoginPage('Invalid email or password.');
            return;
        }

        if (!$user['email_verified']) {
            renderLoginPage('Please verify your email address before logging in. Check your inbox.');
            return;
        }

        $_SESSION['user_id']   = (int) $user['id'];
        $_SESSION['user_name'] = $user['name'];

        header('Location: ?action=sign');
        exit;
    } catch (Throwable $e) {
        renderLoginPage('An error occurred. Please try again.');
    }
}

function handleRegisterPost(): void
{
    try {
        $config = loadConfig();
        $store  = new SignatureStore($config);

        $name     = trim($_POST['name'] ?? '');
        $email    = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        $confirm  = $_POST['password_confirm'] ?? '';

        // Validate
        if ($name === '' || $email === '' || $password === '' || $confirm === '') {
            renderRegisterPage('All fields are required.');
            return;
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            renderRegisterPage('Please enter a valid email address.');
            return;
        }

        if (strlen($password) < 8) {
            renderRegisterPage('Password must be at least 8 characters.');
            return;
        }

        if ($password !== $confirm) {
            renderRegisterPage('Passwords do not match.');
            return;
        }

        // Check duplicate
        $existing = $store->findUserByEmail($email);
        if ($existing !== null) {
            renderRegisterPage('An account with this email already exists.');
            return;
        }

        // Create user
        $passwordHash = password_hash($password, PASSWORD_DEFAULT);
        $token        = bin2hex(random_bytes(32));
        $expires      = date('Y-m-d H:i:s', time() + 3600); // 1 hour

        $store->createUser($email, $passwordHash, $name, $token, $expires);

        // Send verification email
        $smtpConfig = $config['smtp'] ?? [];
        $sent       = sendVerificationEmail($email, $name, $token, $smtpConfig);

        if ($sent) {
            $message = 'Registration successful! Please check your email to verify your account.';
        } else {
            $message = 'Registration successful, but we could not send the verification email. '
                     . 'Please contact the administrator.';
        }

        renderLoginPage(null, $message);
    } catch (PDOException $e) {
        renderRegisterPage('Database error. Please try again.');
    } catch (Throwable $e) {
        renderRegisterPage('An error occurred. Please try again.');
    }
}

function handleVerifyEmail(string $token): void
{
    try {
        $config = loadConfig();
        $store  = new SignatureStore($config);

        $user = $store->findUserByVerificationToken($token);

        if ($user === null) {
            renderLoginPage('Invalid or expired verification link.');
            return;
        }

        // Check expiry
        $expires = $user['verification_token_expires'] ?? null;
        if ($expires !== null && strtotime($expires) < time()) {
            renderLoginPage('Verification link has expired. Please register again.');
            return;
        }

        if ($user['email_verified']) {
            renderLoginPage('Email already verified. You can log in.');
            return;
        }

        $store->verifyUser((int) $user['id']);
        renderLoginPage(null, 'Email verified successfully! You can now log in.');
    } catch (Throwable $e) {
        renderLoginPage('An error occurred. Please try again.');
    }
}

// ---------------------------------------------------------------------------
// SMTP email
// ---------------------------------------------------------------------------

function sendVerificationEmail(string $to, string $name, string $token, array $smtpConfig): bool
{
    $host = $smtpConfig['host'] ?? '';
    $port = (int) ($smtpConfig['port'] ?? 25);

    if ($host === '') {
        return false;
    }

    $fromName  = $smtpConfig['from_name'] ?? 'Chain of Custody';
    $fromAddr  = $smtpConfig['from_email'] ?? 'noreply@chainofcustody.org';
    $ehloHost  = $smtpConfig['ehlo_host'] ?? parse_url($fromAddr, PHP_URL_HOST) ?: 'localhost';
    $subject   = 'Verify your Photo Verify account';

    $verifyUrl = 'http://' . ($_SERVER['HTTP_HOST'] ?? 'localhost') . '/?action=verify&token=' . urlencode($token);

    $body = "Hello {$name},\n\n"
          . "Thank you for registering with Photo Verify.\n\n"
          . "Please verify your email address by clicking the link below:\n\n"
          . "{$verifyUrl}\n\n"
          . "This link expires in 1 hour.\n\n"
          . "If you did not register, please ignore this email.\n";

    $socket = @stream_socket_client("tcp://{$host}:{$port}", $errno, $errstr, 15);

    if ($socket === false) {
        return false;
    }

    $read = function () use ($socket): void {
        fgets($socket, 512);
    };

    $read(); // banner

    fwrite($socket, "EHLO {$ehloHost}\r\n");
    while (($line = fgets($socket, 512)) !== false && substr($line, 3, 1) === '-') {
        // consume multi-line EHLO response
    }

    fwrite($socket, "MAIL FROM:<{$fromAddr}>\r\n");
    $read();

    fwrite($socket, "RCPT TO:<{$to}>\r\n");
    $read();

    fwrite($socket, "DATA\r\n");
    $read();

    $headers = "From: {$fromName} <{$fromAddr}>\r\n"
             . "Reply-To: {$fromAddr}\r\n"
             . "MIME-Version: 1.0\r\n"
             . "Content-Type: text/plain; charset=UTF-8\r\n"
             . "Subject: {$subject}\r\n";

    fwrite($socket, $headers . "\r\n" . $body . "\r\n.\r\n");
    $read();

    fwrite($socket, "QUIT\r\n");
    fclose($socket);

    return true;
}

// ---------------------------------------------------------------------------
// Auth page renderers
// ---------------------------------------------------------------------------

function renderLoginPage(?string $error, ?string $success = null): void
{
    renderAuthPage('login', $error, $success);
}

function renderRegisterPage(?string $error): void
{
    renderAuthPage('register', $error, null);
}

function renderAuthPage(string $mode, ?string $error, ?string $success): void
{
    $pageTitle = $mode === 'login' ? 'Log In' : 'Register';

    ?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Photo Verify — <?= $pageTitle ?></title>
<style>
*, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }
body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
                 Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
    background: #f0f2f5;
    color: #333;
    line-height: 1.6;
    display: flex; justify-content: center; align-items: center;
    min-height: 100vh;
}
.auth-container { width: 100%; max-width: 400px; padding: 0 20px; text-align: center; }
.auth-logo { max-width: 90px; height: auto; margin-bottom: 8px; }
.auth-container h1 { font-size: 22px; color: #1a1a2e; margin-bottom: 4px; }
.auth-container .subtitle { font-size: 13px; color: #888; margin-bottom: 24px; }
.auth-card {
    background: #fff; border-radius: 8px; border: 1px solid #e4e6eb;
    padding: 28px; text-align: left;
}
.form-group { margin-bottom: 18px; }
.form-group label { display: block; margin-bottom: 5px; font-weight: 500; font-size: 14px; color: #444; }
.form-group input[type="email"],
.form-group input[type="password"],
.form-group input[type="text"] {
    width: 100%; padding: 10px 12px; border: 1px solid #d1d5db;
    border-radius: 6px; font-size: 14px; transition: border-color .15s;
}
.form-group input:focus {
    outline: none; border-color: #2563eb; box-shadow: 0 0 0 3px rgba(37,99,235,.15);
}
.btn {
    display: block; width: 100%; padding: 11px 0; background: #2563eb;
    color: #fff; border: none; border-radius: 6px; cursor: pointer;
    font-size: 15px; font-weight: 600; text-align: center; text-decoration: none;
    transition: background .15s;
}
.btn:hover { background: #1d4ed8; }
.msg { padding: 12px 14px; border-radius: 6px; margin-bottom: 18px; font-size: 13px; }
.msg.error { background: #fef2f2; border: 1px solid #fecaca; color: #991b1b; }
.msg.success { background: #ecfdf5; border: 1px solid #a7f3d0; color: #065f46; }
.auth-footer { margin-top: 18px; font-size: 13px; color: #666; text-align: center; }
.auth-footer a { color: #2563eb; text-decoration: none; font-weight: 500; }
.auth-footer a:hover { text-decoration: underline; }
</style>
</head>
<body>
<div class="auth-container">
    <img src="photo-verify-logo-transparent.png" alt="Photo Verify logo" class="auth-logo">
    <h1>Photo Verify</h1>
    <p class="subtitle">Chain of Custody Signature Tool</p>

    <div class="auth-card">
        <?php if ($error !== null): ?>
            <div class="msg error"><?= htmlspecialchars($error) ?></div>
        <?php elseif ($success !== null): ?>
            <div class="msg success"><?= htmlspecialchars($success) ?></div>
        <?php endif; ?>

        <?php if ($mode === 'login'): ?>
            <form method="post" action="?action=login">
                <div class="form-group">
                    <label for="email">Email</label>
                    <input type="email" name="email" id="email" required>
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" name="password" id="password" required>
                </div>
                <button type="submit" class="btn">Log In</button>
            </form>
            <div class="auth-footer">
                Don't have an account? <a href="?action=register">Register</a>
            </div>
        <?php else: ?>
            <form method="post" action="?action=register">
                <div class="form-group">
                    <label for="name">Full name</label>
                    <input type="text" name="name" id="name" required>
                </div>
                <div class="form-group">
                    <label for="email">Email</label>
                    <input type="email" name="email" id="email" required>
                </div>
                <div class="form-group">
                    <label for="password">Password (min. 8 characters)</label>
                    <input type="password" name="password" id="password" minlength="8" required>
                </div>
                <div class="form-group">
                    <label for="password_confirm">Confirm password</label>
                    <input type="password" name="password_confirm" id="password_confirm" required>
                </div>
                <button type="submit" class="btn">Register</button>
            </form>
            <div class="auth-footer">
                Already have an account? <a href="?action=login">Log in</a>
            </div>
        <?php endif; ?>
    </div>
</div>
</body>
</html>
    <?php
}

// ---------------------------------------------------------------------------
// Config loader
// ---------------------------------------------------------------------------

function loadConfig(): array
{
    if (!is_file(CONFIG_PATH)) {
        throw new RuntimeException(
            'Configuration file not found. Create <code>www/config.php</code> ' .
            'from <code>config.example.php</code> with your database credentials.'
        );
    }

    /** @var array<string, mixed> $config */
    $config = require CONFIG_PATH;

    if (!is_array($config)) {
        throw new RuntimeException('Configuration file must return an array.');
    }

    return $config;
}

// ---------------------------------------------------------------------------
// POST handler (protected routes)
// ---------------------------------------------------------------------------

function handlePost(string $action, int $userId): void
{
    try {
        cleanOldTempFiles();

        $coc = new ChainOfCustody(CONFIG_PATH);

        if ($action === 'update') {
            handleUpdateAction($coc, $userId);
            return;
        }

        // --- Validate single-file upload (sign / check) ----------------------
        if (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
            renderPage($action, errorMsg('Please select an image file to upload.'), $_SESSION['user_name'] ?? '');
            return;
        }

        $file = $_FILES['file'];

        if ($file['size'] > MAX_FILE_SIZE) {
            renderPage($action, errorMsg('File too large. Maximum size is 100 MB.'), $_SESSION['user_name'] ?? '');
            return;
        }

        $originalName = basename($file['name']);
        $ext = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));

        if (!in_array($ext, ALLOWED_EXTENSIONS, true)) {
            renderPage($action, errorMsg('Unsupported file format. Allowed: JPG, PNG, TIFF.'), $_SESSION['user_name'] ?? '');
            return;
        }

        $tmpPath = tempnam(sys_get_temp_dir(), 'coc_upload_');
        if (!move_uploaded_file($file['tmp_name'], $tmpPath)) {
            renderPage($action, errorMsg('Failed to process uploaded file.'), $_SESSION['user_name'] ?? '');
            return;
        }

        if ($action === 'check') {
            handleCheckAction($coc, $tmpPath, $originalName, $action);
        } else {
            handleSignAction($coc, $tmpPath, $originalName, $ext, $userId, $action);
        }

        @unlink($tmpPath);
    } catch (ChainOfCustodyException $e) {
        renderPage($action, errorMsg(htmlspecialchars($e->getMessage())), $_SESSION['user_name'] ?? '');
    } catch (PDOException $e) {
        renderPage($action, errorMsg(
            'Database connection failed. Please check your <code>www/config.php</code> settings.'
        ), $_SESSION['user_name'] ?? '');
    } catch (Throwable $e) {
        renderPage($action, errorMsg(htmlspecialchars($e->getMessage())), $_SESSION['user_name'] ?? '');
    }
}

// ---------------------------------------------------------------------------
// Sign action
// ---------------------------------------------------------------------------

function handleSignAction(
    ChainOfCustody $coc,
    string $tmpPath,
    string $originalName,
    string $ext,
    int $userId,
    string $action,
): void {
    $signedData = $coc->createSignedFile($tmpPath, $userId);

    $token = bin2hex(random_bytes(16));
    $downloadPath = sys_get_temp_dir() . '/coc_' . $token;
    $metaPath     = sys_get_temp_dir() . '/coc_' . $token . '.meta';

    file_put_contents($downloadPath, $signedData);
    file_put_contents($metaPath, json_encode([
        'name' => $originalName,
        'ext'  => $ext,
    ]));

    $checkResult = $coc->checkSignature($downloadPath);
    $hash     = $checkResult['hash'] ?? 'unknown';
    $dbRecord = $checkResult['signature'];

    $size        = filesize($downloadPath);
    $actionLabel = $action === 'sign' ? 'Signed' : 'Re-signed';
    $verb        = $action === 'sign' ? 'Signed' : 'Updated';

    $userName = $_SESSION['user_name'] ?? '';

    $html = '<div class="msg success">';
    $html .= '<strong>✅ ' . htmlspecialchars($verb) . ' successfully!</strong><br>';
    $html .= 'File: ' . htmlspecialchars($originalName) . '<br>';
    $html .= 'Author: ' . htmlspecialchars($userName) . '<br>';

    if ($dbRecord !== null) {
        $html .= 'Timestamp: ' . htmlspecialchars($dbRecord['created_at']) . '<br>';
    }

    $html .= 'Hash: <code>' . htmlspecialchars($hash) . '</code><br>';
    $html .= 'Size: ' . number_format($size) . ' bytes<br><br>';
    $html .= '<a href="?action=download&file=' . urlencode($token) . '" class="btn">';
    $html .= 'Download ' . htmlspecialchars($actionLabel) . ' File</a>';
    $html .= '</div>';

    renderPage($action, $html, $userName);
}

// ---------------------------------------------------------------------------
// Update action (two-file flow)
// ---------------------------------------------------------------------------

function handleUpdateAction(ChainOfCustody $coc, int $userId): void
{
    $action = 'update';
    $userName = $_SESSION['user_name'] ?? '';

    // --- Validate original signed file --------------------------------------
    if (!isset($_FILES['original_file']) || $_FILES['original_file']['error'] !== UPLOAD_ERR_OK) {
        renderPage($action, errorMsg('Please upload the original signed file.'), $userName);
        return;
    }

    if ($_FILES['original_file']['size'] > MAX_FILE_SIZE) {
        renderPage($action, errorMsg('Original file is too large. Maximum size is 100 MB.'), $userName);
        return;
    }

    $originalName = basename($_FILES['original_file']['name']);
    $originalExt  = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));

    if (!in_array($originalExt, ALLOWED_EXTENSIONS, true)) {
        renderPage($action, errorMsg('Original file format not supported. Allowed: JPG, PNG, TIFF.'), $userName);
        return;
    }

    $originalTmp = tempnam(sys_get_temp_dir(), 'coc_orig_');
    if (!move_uploaded_file($_FILES['original_file']['tmp_name'], $originalTmp)) {
        renderPage($action, errorMsg('Failed to process the original file.'), $userName);
        return;
    }

    // --- Validate modified file ---------------------------------------------
    if (!isset($_FILES['modified_file']) || $_FILES['modified_file']['error'] !== UPLOAD_ERR_OK) {
        @unlink($originalTmp);
        renderPage($action, errorMsg('Please upload the modified file.'), $userName);
        return;
    }

    if ($_FILES['modified_file']['size'] > MAX_FILE_SIZE) {
        @unlink($originalTmp);
        renderPage($action, errorMsg('Modified file is too large. Maximum size is 100 MB.'), $userName);
        return;
    }

    $modifiedName = basename($_FILES['modified_file']['name']);
    $modifiedExt  = strtolower(pathinfo($modifiedName, PATHINFO_EXTENSION));

    if (!in_array($modifiedExt, ALLOWED_EXTENSIONS, true)) {
        @unlink($originalTmp);
        renderPage($action, errorMsg('Modified file format not supported. Allowed: JPG, PNG, TIFF.'), $userName);
        return;
    }

    $modifiedTmp = tempnam(sys_get_temp_dir(), 'coc_mod_');
    if (!move_uploaded_file($_FILES['modified_file']['tmp_name'], $modifiedTmp)) {
        @unlink($originalTmp);
        renderPage($action, errorMsg('Failed to process the modified file.'), $userName);
        return;
    }

    // --- Process ------------------------------------------------------------
    try {
        $result = $coc->updateChainOfCustody($originalTmp, $modifiedTmp, $userId);

        $token = bin2hex(random_bytes(16));
        $downloadPath = sys_get_temp_dir() . '/coc_' . $token;
        $metaPath     = sys_get_temp_dir() . '/coc_' . $token . '.meta';

        file_put_contents($downloadPath, $result['data']);
        file_put_contents($metaPath, json_encode([
            'name' => $modifiedName,
            'ext'  => $modifiedExt,
        ]));

        $size     = filesize($downloadPath);
        $original = $result['original'];

        $html = '';

        // Original verification
        $html .= '<div class="msg success">';
        $html .= '<strong>✅ Original file verified</strong><br>';
        $html .= 'File: ' . htmlspecialchars($originalName) . '<br>';
        $html .= 'Signed by: ' . htmlspecialchars($original['author_name'])
               . ' (' . htmlspecialchars($original['email'] ?? '') . ')<br>';
        $html .= 'Signed at: ' . htmlspecialchars($original['created_at']) . '<br>';
        $html .= 'Original hash: <code>' . htmlspecialchars($original['signature_hash']) . '</code>';
        $html .= '</div>';

        // New signature
        $html .= '<div class="msg success">';
        $html .= '<strong>✅ Modified file signed</strong><br>';
        $html .= 'File: ' . htmlspecialchars($modifiedName) . '<br>';
        $html .= 'Author: ' . htmlspecialchars($userName) . '<br>';
        $html .= 'New hash: <code>' . htmlspecialchars($result['hash']) . '</code><br>';
        $html .= 'Size: ' . number_format($size) . ' bytes<br><br>';
        $html .= '<a href="?action=download&file=' . urlencode($token) . '" class="btn">';
        $html .= 'Download Signed Modified File</a>';
        $html .= '</div>';

        // Chain update info
        $html .= '<div class="msg info">';
        $html .= '<strong>Chain of custody updated</strong><br>';
        $html .= 'New signature linked to original record. ';
        $html .= 'Use <strong>Check</strong> on the downloaded file to view the full chain.';
        $html .= '</div>';

        renderPage($action, $html, $userName);
    } finally {
        @unlink($originalTmp);
        @unlink($modifiedTmp);
    }
}

// ---------------------------------------------------------------------------
// Check action
// ---------------------------------------------------------------------------

function handleCheckAction(
    ChainOfCustody $coc,
    string $tmpPath,
    string $originalName,
    string $action,
): void {
    $userName = $_SESSION['user_name'] ?? '';
    $result   = $coc->checkSignature($tmpPath);
    $chainResult = $coc->checkChainOfCustody($tmpPath);

    $html = '';

    if ($result['authenticated']) {
        $html .= '<div class="msg success">';
        $html .= '<strong>✅ Signature Valid</strong><br>';
        $html .= 'The file ' . htmlspecialchars($originalName) . ' has not been tampered with.<br><br>';
        $html .= 'Hash: <code>' . htmlspecialchars($result['hash'] ?? '') . '</code><br>';

        if ($result['signature'] !== null) {
            $html .= 'Signed by: ' . htmlspecialchars($result['signature']['author_name'])
                   . ' (' . htmlspecialchars($result['signature']['email'] ?? '') . ')<br>';
            $html .= 'Signed at: ' . htmlspecialchars($result['signature']['created_at']);
        } else {
            $html .= '<em>No database record found for this hash.</em>';
        }

        $html .= '</div>';
    } elseif ($result['hash'] !== null) {
        $html .= '<div class="msg error">';
        $html .= '<strong>❌ Signature Invalid</strong><br>';
        $html .= 'The file has a signature tag but the content does not match.<br>';
        $html .= 'The file may have been tampered with.';
        $html .= '</div>';
    } else {
        $html .= '<div class="msg info">';
        $html .= '<strong>No Signature Found</strong><br>';
        $html .= 'This file does not contain a Chain of Custody signature.';
        $html .= '</div>';
    }

    // Chain of custody table
    $html .= '<h3>Chain of Custody</h3>';

    if ($chainResult['authenticated'] && !empty($chainResult['chain'])) {
        $html .= '<table class="chain-table">';
        $html .= '<thead><tr><th>#</th><th>Author</th><th>Date / Time</th><th>Signature Hash</th></tr></thead>';
        $html .= '<tbody>';

        foreach ($chainResult['chain'] as $i => $link) {
            $label = $i === 0 ? 'Current' : (string) ($i + 1);
            $html .= '<tr>';
            $html .= '<td>' . htmlspecialchars($label) . '</td>';
            $html .= '<td>' . htmlspecialchars($link['author_name'])
                   . ' (' . htmlspecialchars($link['email'] ?? '') . ')</td>';
            $html .= '<td>' . htmlspecialchars($link['created_at']) . '</td>';
            $html .= '<td><code>' . htmlspecialchars($link['signature_hash']) . '</code></td>';
            $html .= '</tr>';
        }

        $html .= '</tbody></table>';
    } else {
        $html .= '<p class="no-data">No chain of custody records in the database.</p>';
    }

    renderPage($action, $html, $userName);
}

// ---------------------------------------------------------------------------
// Download handler
// ---------------------------------------------------------------------------

function handleDownload(): void
{
    $token = $_GET['file'] ?? '';

    if ($token === '' || !ctype_xdigit($token)) {
        http_response_code(400);
        echo 'Invalid download token.';
        exit;
    }

    $tempDir      = sys_get_temp_dir();
    $downloadPath = $tempDir . '/coc_' . $token;
    $metaPath     = $tempDir . '/coc_' . $token . '.meta';

    if (!is_file($downloadPath) || !is_file($metaPath)) {
        http_response_code(404);
        echo 'File not found or expired. Please upload and sign again.';
        exit;
    }

    $meta         = json_decode((string) file_get_contents($metaPath), true);
    $originalName = $meta['name'] ?? 'signed-file';

    $pathInfo     = pathinfo($originalName);
    $downloadName = $pathInfo['filename'] . '-signed';
    if (!empty($pathInfo['extension'])) {
        $downloadName .= '.' . $pathInfo['extension'];
    }

    $mimeTypes = [
        'jpg'  => 'image/jpeg',
        'jpeg' => 'image/jpeg',
        'png'  => 'image/png',
        'tif'  => 'image/tiff',
        'tiff' => 'image/tiff',
    ];
    $ext  = $meta['ext'] ?? '';
    $mime = $mimeTypes[$ext] ?? 'application/octet-stream';

    $size = filesize($downloadPath);

    header('Content-Type: ' . $mime);
    header('Content-Disposition: attachment; filename="' . $downloadName . '"');
    header('Content-Length: ' . $size);
    header('Cache-Control: no-cache, must-revalidate');

    readfile($downloadPath);

    @unlink($downloadPath);
    @unlink($metaPath);
    exit;
}

// ---------------------------------------------------------------------------
// Temp file cleanup
// ---------------------------------------------------------------------------

function cleanOldTempFiles(): void
{
    $tempDir = sys_get_temp_dir();
    $now     = time();

    foreach (glob($tempDir . '/coc_*') as $file) {
        if (is_file($file) && ($now - filemtime($file)) > TEMP_FILE_TTL) {
            @unlink($file);
        }
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

function errorMsg(string $text): string
{
    return '<div class="msg error">' . $text . '</div>';
}

function renderPage(string $activeTab, ?string $resultHtml, string $userName): void
{
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Photo Verify — Chain of Custody</title>
<style>
*, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }
body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
                 Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
    background: #f0f2f5;
    color: #333;
    line-height: 1.6;
}
.container { max-width: 720px; margin: 40px auto; padding: 0 20px; }

/* Header */
.header { text-align: center; margin-bottom: 28px; position: relative; }
.header .logo { max-width: 110px; height: auto; margin-bottom: 10px; }
.header h1 { font-size: 24px; color: #1a1a2e; }
.header p { color: #666; font-size: 14px; margin-top: 2px; }
.header .user-info {
    position: absolute; top: 0; right: 0; font-size: 13px; color: #666;
    display: flex; align-items: center; gap: 12px;
}
.header .user-info .user-name { font-weight: 500; color: #333; }
.header .user-info a { color: #2563eb; text-decoration: none; }
.header .user-info a:hover { text-decoration: underline; }

/* Tabs */
.tabs { display: flex; gap: 4px; }
.tab {
    flex: 1; padding: 12px 16px; text-align: center; text-decoration: none;
    color: #666; background: #e4e6eb; border-radius: 8px 8px 0 0;
    font-weight: 500; font-size: 15px; transition: background .15s;
}
.tab:hover { background: #d8d9de; }
.tab.active { background: #fff; color: #2563eb; font-weight: 600; }

/* Card */
.card {
    background: #fff; border: 1px solid #e4e6eb; border-top: none;
    border-radius: 0 0 8px 8px; padding: 28px 30px;
}

/* Form */
.form-group { margin-bottom: 20px; }
.form-group:last-of-type { margin-bottom: 24px; }
.form-group label {
    display: block; margin-bottom: 6px; font-weight: 500;
    font-size: 14px; color: #444;
}
.form-group input[type="file"] { font-size: 14px; }
.form-group input[type="text"] {
    width: 100%; padding: 10px 12px; border: 1px solid #d1d5db;
    border-radius: 6px; font-size: 14px; transition: border-color .15s;
}
.form-group input[type="text"]:focus {
    outline: none; border-color: #2563eb; box-shadow: 0 0 0 3px rgba(37,99,235,.15);
}
.btn {
    display: inline-block; padding: 10px 28px; background: #2563eb;
    color: #fff; border: none; border-radius: 6px; cursor: pointer;
    font-size: 14px; font-weight: 600; text-decoration: none;
    transition: background .15s;
}
.btn:hover { background: #1d4ed8; }
.btn:focus { outline: 2px solid #2563eb; outline-offset: 2px; }

/* Messages */
.msg { padding: 16px 18px; border-radius: 6px; margin-bottom: 20px; font-size: 14px; }
.msg.success { background: #ecfdf5; border: 1px solid #a7f3d0; color: #065f46; }
.msg.error   { background: #fef2f2; border: 1px solid #fecaca; color: #991b1b; }
.msg.info    { background: #eff6ff; border: 1px solid #bfdbfe; color: #1e40af; }
.msg code, .msg strong code {
    background: rgba(0,0,0,.06); padding: 2px 6px; border-radius: 3px;
    font-size: 12px; word-break: break-all;
}
.msg .btn { margin-top: 4px; }

/* Chain table */
h3 { font-size: 16px; margin: 24px 0 12px; color: #333; }
.chain-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.chain-table th {
    text-align: left; padding: 10px 12px; background: #f8f9fa;
    border-bottom: 2px solid #e4e6eb; font-weight: 600; color: #444;
}
.chain-table td { padding: 10px 12px; border-bottom: 1px solid #eef0f2; }
.chain-table tr:last-child td { border-bottom: none; }
.chain-table code {
    font-size: 11px; word-break: break-all;
    background: #f4f5f7; padding: 2px 5px; border-radius: 3px;
}
.no-data { color: #888; font-style: italic; font-size: 14px; padding: 8px 0; }

/* Footer */
.footer { text-align: center; margin-top: 28px; font-size: 12px; color: #999; }

/* Responsive */
@media (max-width: 500px) {
    .container { margin: 20px auto; }
    .card { padding: 20px; }
    .tab { font-size: 13px; padding: 10px 8px; }
    .chain-table { font-size: 12px; }
    .chain-table th,
    .chain-table td { padding: 8px; }
    .header .user-info { position: static; justify-content: center; margin-top: 8px; }
}
</style>
</head>
<body>

<div class="container">

    <div class="header">
        <div class="user-info">
            <span class="user-name"><?= htmlspecialchars($userName) ?></span>
            <a href="?action=logout">Log out</a>
        </div>
        <img src="photo-verify-logo-transparent.png" alt="Photo Verify logo" class="logo">
        <h1>Photo Verify</h1>
        <p>Chain of Custody Signature Tool</p>
    </div>

    <div class="tabs">
        <a href="?action=sign"   class="tab <?= $activeTab === 'sign'   ? 'active' : '' ?>">Sign</a>
        <a href="?action=check"  class="tab <?= $activeTab === 'check'  ? 'active' : '' ?>">Check</a>
        <a href="?action=update" class="tab <?= $activeTab === 'update' ? 'active' : '' ?>">Update</a>
    </div>

    <div class="card">

        <?php if ($resultHtml !== null): ?>
            <?= $resultHtml ?>
            <p style="margin-top:16px"><a href="?action=<?= htmlspecialchars($activeTab) ?>" class="btn" style="background:#e4e6eb;color:#444;font-weight:500">&larr; Back</a></p>
        <?php else: ?>
            <form method="post" action="?action=<?= htmlspecialchars($activeTab) ?>" enctype="multipart/form-data">

                <?php if ($activeTab === 'update'): ?>
                <div class="form-group">
                    <label for="original_file">Original signed file (authentic, unmodified)</label>
                    <input type="file" name="original_file" id="original_file"
                           accept=".jpg,.jpeg,.png,.tif,.tiff" required>
                </div>
                <div class="form-group">
                    <label for="modified_file">Modified file to sign</label>
                    <input type="file" name="modified_file" id="modified_file"
                           accept=".jpg,.jpeg,.png,.tif,.tiff" required>
                </div>
                <?php else: ?>
                <div class="form-group">
                    <label for="file">Select image file (JPG, PNG, or TIFF)</label>
                    <input type="file" name="file" id="file"
                           accept=".jpg,.jpeg,.png,.tif,.tiff" required>
                </div>
                <?php endif; ?>

                <button type="submit" class="btn">
                    <?= $activeTab === 'check' ? 'Check Signature' : ($activeTab === 'update' ? 'Update Signature' : 'Sign File') ?>
                </button>
            </form>
        <?php endif; ?>

    </div>

    <div class="footer">
        Chain of Custody &mdash; SHA-256 image authentication
    </div>

</div>

</body>
</html>
    <?php
}
