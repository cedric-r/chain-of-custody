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
require_once __DIR__ . '/../src/OAuthProvider.php';
require_once __DIR__ . '/../src/ApiKeyStore.php';

define('ALLOWED_EXTENSIONS', ['jpg', 'jpeg', 'png', 'tif', 'tiff', 'cr2', 'cr3', 'nef']);
define('MAX_FILE_SIZE', 100 * 1024 * 1024);
define('TEMP_FILE_TTL', 3600);
define('CONFIG_PATH', __DIR__ . '/config.php');

define('CAPTCHA_QUESTIONS', [
    'What is 2 + 2?'                    => ['4'],
    'What is 3 + 5?'                    => ['8'],
    'What colour are tomatoes?'          => ['red'],
    'What colour is the sky on a clear day?' => ['blue'],
    'How many legs does a dog have?'     => ['4'],
    'What is 10 - 3?'                   => ['7'],
]);

// ---------------------------------------------------------------------------
// Session & Routing
// ---------------------------------------------------------------------------

session_start();

$action = $_GET['action'] ?? 'home';

$allowedActions = ['home', 'sign', 'check', 'lookup', 'update', 'download', 'login', 'register', 'logout', 'verify', 'feedback', 'gdpr', 'forgot', 'reset', 'oauth_login', 'oauth_callback', 'apikeys'];
if (!in_array($action, $allowedActions, true)) {
    $action = 'home';
}

// Public actions (no auth needed)
$publicActions = ['home', 'check', 'lookup', 'feedback', 'gdpr', 'download', 'login', 'register', 'verify', 'forgot', 'reset', 'oauth_login', 'oauth_callback'];

// Session
$userId   = (int) ($_SESSION['user_id'] ?? 0);
$userName = $_SESSION['user_name'] ?? '';

// Auth routes with their own UIs (not tabs)
if (in_array($action, ['register', 'verify', 'forgot', 'reset', 'oauth_login', 'oauth_callback'], true)) {
    handleAuthRoute($action);
    exit;
}

// Logout
if ($action === 'logout') {
    session_destroy();
    header('Location: ?action=home');
    exit;
}

// Auth check for protected routes
$authRequired = !in_array($action, $publicActions, true);
if ($authRequired && $userId === 0) {
    // Redirect to login tab with a return-to URL
    header('Location: ?action=login&redirect=' . urlencode($action));
    exit;
}

// ---------------------------------------------------------------------------
// Main routing
// ---------------------------------------------------------------------------

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if ($action === 'login') {
        handleLoginPost();
        exit;
    }
    if ($action === 'lookup') {
        handleLookupAction();
        exit;
    }
    if ($action === 'feedback') {
        handleFeedbackAction();
        exit;
    }
    if ($action === 'apikeys') {
        handleApiKeysAction($userId);
        exit;
    }
    handlePost($action, $userId);
    exit;
}

if ($action === 'download') {
    handleDownload();
    exit;
}

if (in_array($action, ['home', 'sign', 'check', 'lookup', 'feedback', 'gdpr', 'update', 'login', 'apikeys'], true)) {
    renderPage($action, null, $userName);
    exit;
}

// Fallback
renderPage('home', null, $userName);

// ---------------------------------------------------------------------------
// Auth handlers
// ---------------------------------------------------------------------------

function handleAuthRoute(string $action): void
{
    if ($action === 'oauth_login') {
        handleOAuthLogin();
        return;
    }

    if ($action === 'oauth_callback') {
        handleOAuthCallback();
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

    if ($action === 'forgot') {
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            handleForgotPost();
        } else {
            renderForgotPage(null);
        }
        return;
    }

    if ($action === 'reset') {
        handleResetAction();
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
            renderPage('login', errorMsg('Please enter your email and password.'), '');
            return;
        }

        $user = $store->findUserByEmail($email);

        if ($user === null) {
            renderPage('login', errorMsg('Invalid email or password.'), '');
            return;
        }

        // OAuth users must sign in through their provider
        if (($user['auth_provider'] ?? 'local') !== 'local') {
            renderPage('login', errorMsg(
                'This account uses ' . htmlspecialchars($user['auth_provider'])
                . ' login. Please sign in with ' . htmlspecialchars(ucfirst($user['auth_provider'])) . '.'
            ), '');
            return;
        }

        if (!password_verify($password, $user['password_hash'])) {
            renderPage('login', errorMsg('Invalid email or password.'), '');
            return;
        }

        if (!$user['email_verified']) {
            renderPage('login', errorMsg('Please verify your email address before logging in. Check your inbox.'), '');
            return;
        }

        $_SESSION['user_id']   = (int) $user['id'];
        $_SESSION['user_name'] = $user['name'];

        // Redirect to the original destination, or default to sign
        $redirect = trim($_POST['redirect'] ?? '');
        $allowed  = ['home', 'sign', 'check', 'lookup', 'update', 'apikeys', 'feedback', 'gdpr'];
        $target   = in_array($redirect, $allowed, true) ? $redirect : 'sign';
        header('Location: ?action=' . $target);
        exit;
    } catch (Throwable $e) {
        renderPage('login', errorMsg('An error occurred. Please try again.'), '');
    }
}

// ---------------------------------------------------------------------------
// OAuth handlers
// ---------------------------------------------------------------------------

function getOAuthConfig(): array
{
    $config = loadConfig();
    return $config['oauth'] ?? [];
}

function handleOAuthLogin(): void
{
    $provider = $_GET['provider'] ?? '';

    if (!in_array($provider, ['google', 'github'], true)) {
        renderPage('login', errorMsg('Unsupported OAuth provider.'), '');
        return;
    }

    try {
        $oauthCfg = getOAuthConfig();
        $state    = bin2hex(random_bytes(16));

        $_SESSION['oauth_state'] = $state;
        $_SESSION['oauth_provider'] = $provider;

        $url = OAuthProvider::getAuthorizationUrl($provider, $oauthCfg, $state);
        header('Location: ' . $url);
        exit;
    } catch (Throwable $e) {
        renderPage('login', errorMsg('OAuth configuration error: ' . htmlspecialchars($e->getMessage())), '');
    }
}

function handleOAuthCallback(): void
{
    $provider  = $_GET['provider'] ?? '';
    $code      = $_GET['code'] ?? '';
    $state     = $_GET['state'] ?? '';
    $error     = $_GET['error'] ?? '';

    // Handle provider-side errors (user denied consent, etc.)
    if ($error !== '') {
        renderPage('login', errorMsg('OAuth login was cancelled or denied.'), '');
        return;
    }

    // Validate state (CSRF)
    $expectedState = $_SESSION['oauth_state'] ?? '';
    $expectedProvider = $_SESSION['oauth_provider'] ?? '';

    if ($state === '' || !hash_equals($expectedState, $state) || $provider !== $expectedProvider) {
        renderPage('login', errorMsg('OAuth login failed: invalid state parameter.'), '');
        return;
    }

    // Clear session state
    unset($_SESSION['oauth_state']);
    unset($_SESSION['oauth_provider']);

    if ($code === '') {
        renderPage('login', errorMsg('OAuth login failed: no authorization code received.'), '');
        return;
    }

    try {
        $oauthCfg = getOAuthConfig();
        $accessToken = OAuthProvider::exchangeCode($provider, $code, $oauthCfg);
        $userInfo    = OAuthProvider::getUserInfo($provider, $accessToken, $oauthCfg);

        if (empty($userInfo['email'])) {
            renderPage('login', errorMsg('Could not retrieve your email from the OAuth provider.'), '');
            return;
        }

        $config = loadConfig();
        $store  = new SignatureStore($config);

        $userId = $store->findOrCreateOAuthUser(
            $provider,
            $userInfo['id'],
            $userInfo['email'],
            $userInfo['name'] ?: explode('@', $userInfo['email'])[0],
        );

        $user = $store->findUserById($userId);
        if ($user === null) {
            renderPage('login', errorMsg('Failed to create or retrieve user account.'), '');
            return;
        }

        $_SESSION['user_id']   = $userId;
        $_SESSION['user_name'] = $user['name'];

        $redirect = trim($_POST['redirect'] ?? '');
        $allowed  = ['home', 'sign', 'check', 'lookup', 'update', 'apikeys', 'feedback', 'gdpr'];
        $target   = in_array($redirect, $allowed, true) ? $redirect : 'sign';
        header('Location: ?action=' . $target);
        exit;
    } catch (Throwable $e) {
        renderPage('login', errorMsg('OAuth login error: ' . htmlspecialchars($e->getMessage())), '');
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

/**
 * Send a plain-text email via the configured SMTP relay.
 */
function sendRawEmail(string $to, string $subject, string $body, array $smtpConfig): bool
{
    $host = $smtpConfig['host'] ?? '';
    $port = (int) ($smtpConfig['port'] ?? 25);

    if ($host === '') {
        return false;
    }

    $fromName = $smtpConfig['from_name'] ?? 'Chain of Custody';
    $fromAddr = $smtpConfig['from_email'] ?? 'noreply@chainofcustody.org';
    $ehloHost = $smtpConfig['ehlo_host'] ?? (parse_url($fromAddr, PHP_URL_HOST) ?: 'localhost');

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

function sendVerificationEmail(string $to, string $name, string $token, array $smtpConfig): bool
{
    if (($smtpConfig['host'] ?? '') === '') {
        return false;
    }

    $subject = 'Verify your Photo Verify account';

    $verifyUrl = 'http://' . ($_SERVER['HTTP_HOST'] ?? 'localhost') . '/?action=verify&token=' . urlencode($token);

    $body = "Hello {$name},\n\n"
          . "Thank you for registering with Photo Verify.\n\n"
          . "Please verify your email address by clicking the link below:\n\n"
          . "{$verifyUrl}\n\n"
          . "This link expires in 1 hour.\n\n"
          . "If you did not register, please ignore this email.\n";

    return sendRawEmail($to, $subject, $body, $smtpConfig);
}

// ---------------------------------------------------------------------------
// Auth page renderers
// ---------------------------------------------------------------------------

function renderLoginPage(?string $error, ?string $success = null): void
{
    renderAuthPage('login', $error, $success);
}

// ---------------------------------------------------------------------------
// Password reset
// ---------------------------------------------------------------------------

function renderForgotPage(?string $error): void
{
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Photo Verify — Reset Password</title>
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
.form-group input[type="password"] {
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
        <?php endif; ?>

        <form method="post" action="?action=forgot">
            <div class="form-group">
                <label for="email">Enter your email address</label>
                <input type="email" name="email" id="email" required>
            </div>
            <button type="submit" class="btn">Send Reset Link</button>
        </form>
        <div class="auth-footer">
            <a href="?action=login">Back to log in</a>
        </div>
    </div>
</div>
</body>
</html>
    <?php
}

function handleForgotPost(): void
{
    try {
        $config = loadConfig();
        $store  = new SignatureStore($config);

        $email = trim($_POST['email'] ?? '');
        if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            renderForgotPage('Please enter a valid email address.');
            return;
        }

        $user = $store->findUserByEmail($email);
        if ($user === null) {
            // Don't reveal whether the email exists
            renderForgotPage('If that email is registered, a reset link has been sent.');
            return;
        }

        $token   = bin2hex(random_bytes(32));
        $expires = date('Y-m-d H:i:s', time() + 3600);

        $store->setResetToken((int) $user['id'], $token, $expires);

        // Send reset email
        $smtpConfig = $config['smtp'] ?? [];
        $resetUrl   = 'http://' . ($_SERVER['HTTP_HOST'] ?? 'localhost') . '/?action=reset&token=' . urlencode($token);

        $subject = 'Reset your Photo Verify password';
        $body    = "Hello {$user['name']},\n\n"
                 . "A password reset was requested for your Photo Verify account.\n\n"
                 . "Click the link below to set a new password:\n\n"
                 . "{$resetUrl}\n\n"
                 . "This link expires in 1 hour.\n\n"
                 . "If you did not request this, please ignore this email.\n";

        sendRawEmail($email, $subject, $body, $smtpConfig);

        renderForgotPage('If that email is registered, a reset link has been sent.');
    } catch (Throwable $e) {
        renderForgotPage('An error occurred. Please try again.');
    }
}

function handleResetAction(): void
{
    $token = $_GET['token'] ?? '';

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        handleResetPost($token);
        return;
    }

    if ($token === '') {
        renderLoginPage('Invalid reset link.');
        return;
    }

    // Show the reset password form
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Photo Verify — Set New Password</title>
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
.form-group input[type="password"] {
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
</style>
</head>
<body>
<div class="auth-container">
    <img src="photo-verify-logo-transparent.png" alt="Photo Verify logo" class="auth-logo">
    <h1>Photo Verify</h1>
    <p class="subtitle">Set a new password</p>

    <div class="auth-card">
        <form method="post" action="?action=reset&token=<?= htmlspecialchars(urlencode($token)) ?>">
            <div class="form-group">
                <label for="password">New password (min. 8 characters)</label>
                <input type="password" name="password" id="password" minlength="8" required>
            </div>
            <div class="form-group">
                <label for="password_confirm">Confirm new password</label>
                <input type="password" name="password_confirm" id="password_confirm" required>
            </div>
            <button type="submit" class="btn">Set New Password</button>
        </form>
    </div>
</div>
</body>
</html>
    <?php
}

function handleResetPost(string $token): void
{
    try {
        $config = loadConfig();
        $store  = new SignatureStore($config);

        $password       = $_POST['password'] ?? '';
        $passwordConfirm = $_POST['password_confirm'] ?? '';

        if ($token === '') {
            renderLoginPage('Invalid reset link.');
            return;
        }

        if (strlen($password) < 8) {
            renderLoginPage('Password must be at least 8 characters.');
            return;
        }

        if ($password !== $passwordConfirm) {
            renderLoginPage('Passwords do not match.');
            return;
        }

        $user = $store->findUserByVerificationToken($token);

        if ($user === null) {
            renderLoginPage('Invalid or expired reset link.');
            return;
        }

        $expires = $user['verification_token_expires'] ?? null;
        if ($expires !== null && strtotime($expires) < time()) {
            renderLoginPage('Reset link has expired. Please request a new one.');
            return;
        }

        $store->updatePassword((int) $user['id'], password_hash($password, PASSWORD_DEFAULT));

        renderLoginPage(null, 'Password reset successfully. You can now log in.');
    } catch (Throwable $e) {
        renderLoginPage('An error occurred. Please try again.');
    }
}

/**
 * Render the login form inside the tabbed interface card.
 * Used by the "Log in" tab when the user is not authenticated.
 */
/**
 * Pick a random captcha question and store the expected answer in the session.
 */
function pickCaptcha(): string
{
    $questions = array_keys(CAPTCHA_QUESTIONS);
    $question  = $questions[array_rand($questions)];
    $_SESSION['captcha_answer'] = strtolower(trim(CAPTCHA_QUESTIONS[$question][0]));
    return $question;
}

/**
 * Render the feedback form inside the tabbed interface card.
 */
function renderFeedbackFormContent(?string $error): void
{
    $senderName  = htmlspecialchars($_POST['feedback_name'] ?? '');
    $senderEmail = htmlspecialchars($_POST['feedback_email'] ?? '');
    $message     = htmlspecialchars($_POST['feedback_message'] ?? '');
    $captchaQ    = $_SESSION['captcha_question'] ?? pickCaptcha();
    $_SESSION['captcha_question'] = $captchaQ;

    if ($error !== null):
        ?><div class="msg error"><?= htmlspecialchars($error) ?></div><?php
    endif; ?>
    <div class="blurb">
        <h2>Feedback</h2>
        <p>Send a message to the site administrator.</p>
    </div>
    <form method="post" action="?action=feedback">
        <div class="form-group">
            <label for="feedback_name">Your name</label>
            <input type="text" name="feedback_name" id="feedback_name"
                   value="<?= $senderName ?>" required>
        </div>
        <div class="form-group">
            <label for="feedback_email">Your email</label>
            <input type="email" name="feedback_email" id="feedback_email"
                   value="<?= $senderEmail ?>" required>
        </div>
        <div class="form-group">
            <label for="feedback_message">Message</label>
            <textarea name="feedback_message" id="feedback_message" rows="5"
                      style="width:100%;padding:10px 12px;border:1px solid #d1d5db;border-radius:6px;font-size:14px;font-family:inherit;resize:vertical;" required><?= $message ?></textarea>
        </div>
        <div class="form-group">
            <label for="captcha"><?= htmlspecialchars($captchaQ) ?></label>
            <input type="text" name="captcha" id="captcha" placeholder="Type your answer" required>
        </div>
        <button type="submit" class="btn">Send Feedback</button>
    </form>
    <?php
}

function renderLoginFormContent(?string $error): void
{
    $redirect = $_GET['redirect'] ?? ($_POST['redirect'] ?? '');
    $oauthCfg = [];
    try {
        $config   = loadConfig();
        $oauthCfg = $config['oauth'] ?? [];
    } catch (Throwable) {
        // Config unavailable — show only the local form
    }

    if ($error !== null):
        ?><div class="msg error"><?= htmlspecialchars($error) ?></div><?php
    endif;

    // OAuth buttons
    $hasOAuth = false;
    foreach (['google', 'github'] as $prov) {
        if (!empty($oauthCfg[$prov]['client_id'])) {
            $hasOAuth = true;
            $label = $prov === 'google' ? 'Google' : 'GitHub';
            ?><a href="?action=oauth_login&provider=<?= $prov ?>" class="btn oauth-btn oauth-<?= $prov ?>">Sign in with <?= $label ?></a><?php
        }
    }
    if ($hasOAuth): ?><p style="margin:14px 0 10px;text-align:center;font-size:13px;color:#999;">or sign in with email</p><?php endif; ?>

    <form method="post" action="?action=login">
        <input type="hidden" name="redirect" value="<?= htmlspecialchars($redirect) ?>">
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
    <p style="margin-top:12px;font-size:13px;color:#666;">
        <a href="?action=forgot" style="color:#2563eb;font-weight:500;">Forgot your password?</a>
    </p>
    <p style="margin-top:8px;font-size:13px;color:#666;">
        Don't have an account? <a href="?action=register" style="color:#2563eb;font-weight:500;">Register</a>
    </p>
    <?php
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
            renderPage($action, errorMsg('Unsupported file format. Allowed: JPG, PNG, TIFF, CR2, CR3, NEF.'), $_SESSION['user_name'] ?? '');
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
        renderPage($action, errorMsg('Original file format not supported. Allowed: JPG, PNG, TIFF, CR2, CR3, NEF.'), $userName);
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
        renderPage($action, errorMsg('Modified file format not supported. Allowed: JPG, PNG, TIFF, CR2, CR3, NEF.'), $userName);
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
               . ' (' . htmlspecialchars($original['email'] ?? '') . ', '
               . htmlspecialchars($original['auth_provider'] ?? 'local') . ')<br>';
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

        if (!empty($result['node_id'])) {
            $html .= 'Node: <code>' . htmlspecialchars($result['node_id']) . '</code><br>';
        }

        $html .= 'Signed by: ' . htmlspecialchars($result['signature']['author_name'])
               . ' (' . htmlspecialchars($result['signature']['email'] ?? '') . ', '
               . htmlspecialchars($result['signature']['auth_provider'] ?? 'local') . ')<br>';
        $html .= 'Signed at: ' . htmlspecialchars($result['signature']['created_at']);
        $html .= '</div>';
    } elseif ($result['hash_valid']) {
        $html .= '<div class="msg error">';
        $html .= '<strong>❌ Signature Not in Database</strong><br>';
        $html .= 'The file content is authentic but no matching signature record ';
        $html .= 'was found in the database.<br>';
        $html .= 'The file may have been signed outside this system or the database ';
        $html .= 'records have been cleared.';
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

    // Remote node notice
    if (!empty($result['node_id']) && !empty($result['requires_remote'])) {
        $html .= '<div class="msg info">';
        $html .= '<strong>🔗 Signed by a different node</strong><br>';
        $html .= 'This file was signed by node <code>' . htmlspecialchars($result['node_id']) . '</code>. ';
        $html .= 'To verify it, use the API:<br>';
        $html .= '<code style="font-size:12px;">curl -X POST https://' . htmlspecialchars($result['node_id']) . '.photo-verify.org/verify -F "file=@..."</code>';
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
            $authProvider = $link['auth_provider'] ?? 'local';
            $html .= '<td>' . htmlspecialchars($link['author_name'])
                   . ' (' . htmlspecialchars($link['email'] ?? '') . ', ' . htmlspecialchars($authProvider) . ')</td>';
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
// Lookup handler
// ---------------------------------------------------------------------------

function handleLookupAction(): void
{
    try {
        $config = loadConfig();
        $coc    = new ChainOfCustody(CONFIG_PATH);

        // Validate upload
        if (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
            renderPage('lookup', errorMsg('Please select a file to look up.'), '');
            return;
        }

        $file = $_FILES['file'];
        $originalName = basename($file['name']);
        $ext = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));

        if (!in_array($ext, ALLOWED_EXTENSIONS, true)) {
            renderPage('lookup', errorMsg('Unsupported file format. Allowed: JPG, PNG, TIFF, CR2, CR3, NEF.'), '');
            return;
        }

        if ($file['size'] > MAX_FILE_SIZE) {
            renderPage('lookup', errorMsg('File too large. Maximum size is 100 MB.'), '');
            return;
        }

        $tmpPath = tempnam(sys_get_temp_dir(), 'coc_lookup_');
        if (!move_uploaded_file($file['tmp_name'], $tmpPath)) {
            renderPage('lookup', errorMsg('Failed to process uploaded file.'), '');
            return;
        }

        // If the file has an embedded signature, pass it to the check flow instead
        $checkResult = $coc->checkSignature($tmpPath);
        if ($checkResult['hash'] !== null) {
            $userName = $_SESSION['user_name'] ?? '';
            handleCheckAction($coc, $tmpPath, $originalName, 'lookup');
            @unlink($tmpPath);
            return;
        }

        $result = $coc->lookupSignature($tmpPath);
        @unlink($tmpPath);
        @unlink($tmpPath);

        $html = '';

        if ($result['found']) {
            $record = $result['record'];
            $html .= '<div class="msg success">';
            $html .= '<strong>✅ Signature Found</strong><br>';
            $html .= 'File: ' . htmlspecialchars($originalName) . '<br>';
            $html .= 'Signed by: ' . htmlspecialchars($record['author_name'])
                   . ' (' . htmlspecialchars($record['email'] ?? '') . ', '
                   . htmlspecialchars($record['auth_provider'] ?? 'local') . ')<br>';
            $html .= 'File name at signing: ' . htmlspecialchars($record['file_name']) . '<br>';
            $html .= 'Signed at: ' . htmlspecialchars($record['created_at']) . '<br>';
            $html .= 'Hash: <code>' . htmlspecialchars($result['hash']) . '</code>';
            $html .= '</div>';

            // Chain of custody
            if (!empty($result['chain'])) {
                $html .= '<h3>Chain of Custody</h3>';
                $html .= '<table class="chain-table">';
                $html .= '<thead><tr><th>#</th><th>Author</th><th>Date / Time</th><th>Signature Hash</th></tr></thead>';
                $html .= '<tbody>';
                foreach ($result['chain'] as $i => $link) {
                    $label = $i === 0 ? 'Current' : (string) ($i + 1);
                    $html .= '<tr>';
                    $html .= '<td>' . htmlspecialchars($label) . '</td>';
                    $authProvider = $link['auth_provider'] ?? 'local';
                    $html .= '<td>' . htmlspecialchars($link['author_name'])
                           . ' (' . htmlspecialchars($link['email'] ?? '') . ', ' . htmlspecialchars($authProvider) . ')</td>';
                    $html .= '<td>' . htmlspecialchars($link['created_at']) . '</td>';
                    $html .= '<td><code>' . htmlspecialchars($link['signature_hash']) . '</code></td>';
                    $html .= '</tr>';
                }
                $html .= '</tbody></table>';
            }
        } else {
            $html .= '<div class="msg info">';
            $html .= '<strong>No Matching Signature</strong><br>';
            $html .= 'The file ' . htmlspecialchars($originalName) . ' is not known in the system.<br>';
            $html .= 'Hash computed: <code>' . htmlspecialchars($result['hash']) . '</code>';
            $html .= '</div>';
        }

        $userName = $_SESSION['user_name'] ?? '';
        renderPage('lookup', $html, $userName);
    } catch (Throwable $e) {
        renderPage('lookup', errorMsg(htmlspecialchars($e->getMessage())), '');
    }
}

// ---------------------------------------------------------------------------
// Feedback handler
// ---------------------------------------------------------------------------

function handleFeedbackAction(): void
{
    $name    = trim($_POST['feedback_name'] ?? '');
    $email   = trim($_POST['feedback_email'] ?? '');
    $message = trim($_POST['feedback_message'] ?? '');
    $answer  = strtolower(trim($_POST['captcha'] ?? ''));
    $expected = strtolower(trim($_SESSION['captcha_answer'] ?? ''));

    // Validate fields
    if ($name === '' || $email === '' || $message === '') {
        renderPage('feedback', errorMsg('All fields are required.'), '');
        return;
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        renderPage('feedback', errorMsg('Please enter a valid email address.'), '');
        return;
    }

    if ($answer === '' || $answer !== $expected) {
        // Pick a new captcha question on failure
        unset($_SESSION['captcha_answer']);
        unset($_SESSION['captcha_question']);
        renderPage('feedback', errorMsg('Incorrect captcha answer. Please try again.'), '');
        return;
    }

    // Send feedback email
    try {
        $config    = loadConfig();
        $smtpConfig = $config['smtp'] ?? [];
        $to        = $smtpConfig['feedback_recipient'] ?? '';

        if ($to === '') {
            renderPage('feedback', errorMsg(
                'Feedback is not configured. Please contact the administrator directly.'
            ), '');
            return;
        }

        $subject = 'Feedback from ' . $name;
        $body = "Name: {$name}\n"
              . "Email: {$email}\n\n"
              . "Message:\n{$message}\n";

        $sent = sendRawEmail($to, $subject, $body, $smtpConfig);

        if ($sent) {
            // Clear captcha state
            unset($_SESSION['captcha_answer']);
            unset($_SESSION['captcha_question']);
            renderPage('feedback', '<div class="msg success"><strong>Thank you!</strong><br>Your feedback has been sent.</div>', '');
        } else {
            renderPage('feedback', errorMsg('Failed to send your message. Please try again later.'), '');
        }
    } catch (Throwable $e) {
        renderPage('feedback', errorMsg('An error occurred. Please try again later.'), '');
    }
}

// ---------------------------------------------------------------------------
// API Keys handler
// ---------------------------------------------------------------------------

function renderApiKeysContent(int $userId): void
{
    try {
        $config   = loadConfig();
        $keyStore = new ApiKeyStore($config);
        $keys     = $keyStore->listByUser($userId);
    } catch (Throwable) {
        $keys = [];
    }
    ?>
    <div class="blurb">
        <h2>API Keys</h2>
        <p>Generate API keys for remote access to the signing API at
        <code>api.photo-verify.org</code>.</p>
    </div>

    <form method="post" action="?action=apikeys" style="margin-bottom:24px;">
        <input type="hidden" name="action" value="generate">
        <div class="form-group">
            <label for="key_label">New key label</label>
            <input type="text" name="label" id="key_label"
                   placeholder="e.g. CI pipeline, phone upload"
                   required style="max-width:300px;">
        </div>
        <button type="submit" class="btn">Generate Key</button>
    </form>

    <?php if (empty($keys)): ?>
        <p style="color:#888;font-style:italic;">No API keys yet.</p>
    <?php else: ?>
        <h3 style="font-size:15px;margin-bottom:8px;">Your API Keys</h3>
        <table class="chain-table">
            <thead>
                <tr>
                    <th>Label</th>
                    <th>Key ID</th>
                    <th>Last Used</th>
                    <th>Created</th>
                    <th>Status</th>
                    <th></th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($keys as $k): ?>
                <tr>
                    <td><?= htmlspecialchars($k['label']) ?></td>
                    <td><code>coc_<?= htmlspecialchars($k['prefix']) ?>...</code></td>
                    <td><?= htmlspecialchars($k['last_used_at'] ?? 'never') ?></td>
                    <td><?= htmlspecialchars($k['created_at']) ?></td>
                    <td><?= $k['revoked_at'] !== null ? 'Revoked' : 'Active' ?></td>
                    <td>
                        <?php if ($k['revoked_at'] === null): ?>
                        <form method="post" action="?action=apikeys" style="display:inline;">
                            <input type="hidden" name="action" value="revoke">
                            <input type="hidden" name="key_id" value="<?= (int) $k['id'] ?>">
                            <button type="submit" class="btn"
                                    style="background:#dc2626;padding:4px 12px;font-size:12px;"
                                    onclick="return confirm('Revoke this key? This cannot be undone.')">Revoke</button>
                        </form>
                        <?php endif; ?>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
    <?php
}

function handleApiKeysAction(int $userId): void
{
    try {
        $config    = loadConfig();
        $keyStore  = new ApiKeyStore($config);
        $subAction = $_POST['action'] ?? '';

        if ($subAction === 'generate') {
            $label  = trim($_POST['label'] ?? '');
            if ($label === '') {
                renderPage('apikeys', errorMsg('Please enter a label for the key.'), $_SESSION['user_name'] ?? '');
                return;
            }

            $result = $keyStore->generate($userId, $label);
            $html  = '<div class="msg success">';
            $html .= '<strong>Key generated!</strong><br>';
            $html .= 'Make sure to copy this key now — it will not be shown again.<br><br>';
            $html .= '<code style="font-size:16px;word-break:break-all;">' . htmlspecialchars($result['key']) . '</code>';
            $html .= '</div>';

            renderPage('apikeys', $html, $_SESSION['user_name'] ?? '');
            return;
        }

        if ($subAction === 'revoke') {
            $keyId = (int) ($_POST['key_id'] ?? 0);
            if ($keyId <= 0) {
                renderPage('apikeys', errorMsg('Invalid key ID.'), $_SESSION['user_name'] ?? '');
                return;
            }

            $keyStore->revoke($keyId, $userId);
            renderPage('apikeys', '<div class="msg success">Key revoked successfully.</div>', $_SESSION['user_name'] ?? '');
            return;
        }

        renderPage('apikeys', errorMsg('Unknown action.'), $_SESSION['user_name'] ?? '');
    } catch (RuntimeException $e) {
        renderPage('apikeys', errorMsg(htmlspecialchars($e->getMessage())), $_SESSION['user_name'] ?? '');
    } catch (Throwable $e) {
        renderPage('apikeys', errorMsg('An error occurred.'), $_SESSION['user_name'] ?? '');
    }
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
        'cr2'  => 'image/x-canon-cr2',
        'cr3'  => 'image/x-canon-cr3',
        'nef'  => 'image/x-nikon-nef',
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
    $userId = (int) ($_SESSION['user_id'] ?? 0);
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

/* Blurb */
.blurb h2 { font-size: 18px; margin-bottom: 12px; color: #1a1a2e; }
.blurb h3 { font-size: 15px; margin: 20px 0 8px; color: #1a1a2e; }
.blurb p { font-size: 14px; color: #555; margin-bottom: 10px; line-height: 1.7; }
.blurb ul { margin: 10px 0 0 20px; font-size: 14px; color: #555; line-height: 1.8; }
.blurb ul li strong { color: #333; }

/* OAuth buttons */
.oauth-btn { margin-bottom: 8px; text-align: center; }
.oauth-google { background: #fff; color: #333 !important; border: 1px solid #d1d5db; font-weight: 500; }
.oauth-google:hover { background: #f3f4f6; }
.oauth-github { background: #24292f; color: #fff !important; font-weight: 500; }
.oauth-github:hover { background: #1b1f23; }

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
        <a href="?action=home"   class="tab <?= $activeTab === 'home'   ? 'active' : '' ?>">Home</a>
        <a href="?action=sign"   class="tab <?= $activeTab === 'sign'   ? 'active' : '' ?>">Sign</a>
        <a href="?action=check"  class="tab <?= $activeTab === 'check'  ? 'active' : '' ?>">Check</a>
        <a href="?action=lookup"  class="tab <?= $activeTab === 'lookup'   ? 'active' : '' ?>">Lookup</a>
        <a href="?action=update"  class="tab <?= $activeTab === 'update'   ? 'active' : '' ?>">Update</a>
        <a href="?action=apikeys" class="tab <?= $activeTab === 'apikeys'  ? 'active' : '' ?>">API Keys</a>
        <a href="?action=feedback" class="tab <?= $activeTab === 'feedback' ? 'active' : '' ?>">Feedback</a>
        <?php if ($userId === 0): ?>
        <a href="?action=login"  class="tab <?= $activeTab === 'login'  ? 'active' : '' ?>">Log in</a>
        <?php endif; ?>
        <a href="?action=gdpr"   class="tab <?= $activeTab === 'gdpr'   ? 'active' : '' ?>">GDPR</a>
    </div>

    <div class="card">

        <?php if ($resultHtml !== null): ?>
            <?= $resultHtml ?>
            <p style="margin-top:16px"><a href="?action=<?= htmlspecialchars($activeTab) ?>" class="btn" style="background:#e4e6eb;color:#444;font-weight:500">&larr; Back</a></p>
        <?php elseif ($activeTab === 'login'): ?>
            <?php renderLoginFormContent(null); ?>
        <?php elseif ($activeTab === 'home'): ?>
            <div class="blurb">
                <h2>Welcome to Photo Verify</h2>
                <p>
                    This tool lets you create and verify <strong>Chain of Custody</strong>
                    signatures on image and raw camera files (JPEG, PNG, TIFF, CR2, CR3, NEF).
                </p>
                <p>
                    A Chain of Custody signature embeds a SHA-256 hash of the file directly
                    into the file itself using format-specific metadata mechanisms. Each signature
                    is recorded in a database with the author's name, creating an auditable trail.
                </p>
                <ul>
                    <li><strong>Sign</strong> — embed a signature into a file (requires login)</li>
                    <li><strong>Check</strong> — verify an existing signature and view its chain of custody</li>
                    <li><strong>Lookup</strong> — upload any unsigned file; the system computes its hash and searches the database for a matching signature record</li>
                    <li><strong>Update</strong> — sign a modified file while keeping the link to the original signature</li>
                </ul>
            </div>
            <h3 style="margin-top:24px;font-size:15px;">Quick Check — verify a signed file</h3>
            <form method="post" action="?action=check" enctype="multipart/form-data">
                <div class="form-group">
                    <label for="file_home">Select a signed image or raw file</label>
                    <input type="file" name="file" id="file_home"
                           accept=".jpg,.jpeg,.png,.tif,.tiff,.cr2,.cr3,.nef" required>
                </div>
                <button type="submit" class="btn">Check Signature</button>
            </form>
        <?php elseif ($activeTab === 'lookup'): ?>
            <div class="blurb">
                <h2>Look Up a File</h2>
                <p>
                    Upload any image or raw file to search the database for a matching
                    signature record. The system computes the file's hash and checks
                    whether that hash exists in the chain of custody database.
                </p>
            </div>
            <form method="post" action="?action=lookup" enctype="multipart/form-data">
                <div class="form-group">
                    <label for="file_lookup">Select an unsigned image or raw file</label>
                    <input type="file" name="file" id="file_lookup"
                           accept=".jpg,.jpeg,.png,.tif,.tiff,.cr2,.cr3,.nef" required>
                </div>
                <button type="submit" class="btn">Look Up Hash</button>
            </form>
        <?php elseif ($activeTab === 'apikeys'): ?>
            <?php renderApiKeysContent($userId); ?>
        <?php elseif ($activeTab === 'feedback'): ?>
            <?php renderFeedbackFormContent(null); ?>
        <?php elseif ($activeTab === 'gdpr'): ?>
            <div class="blurb">
                <h2>GDPR Compliance</h2>

                <h3>Data Controller</h3>
                <p>
                    The operator of this website is the data controller for any
                    personal data collected through the service. If you have
                    questions about your data, please use the Feedback tab to
                    contact the site administrator.
                </p>

                <h3>What Data We Collect</h3>
                <p>
                    When you register for an account, we collect your
                    <strong>email address</strong> and the
                    <strong>name</strong> you provide. The email address is
                    used as your login identifier and as a contact address for
                    account-related communication (verification email,
                    password reset). The name is displayed alongside signatures
                    you create in the chain of custody records.
                </p>
                <p>
                    When you submit the feedback form, we collect the
                    <strong>name</strong>, <strong>email address</strong>, and
                    <strong>message</strong> you enter. These are forwarded to
                    the site administrator via email and are not stored in the
                    website database.
                </p>
                <p>
                    No other personal data is processed. We do not use
                    analytics services, tracking cookies, advertising, or
                    third-party data processors. The website does not log IP
                    addresses or browser fingerprints beyond what your HTTP
                    client automatically sends in request headers.
                </p>

                <h3>Legal Basis</h3>
                <p>
                    The processing of your email address and name for account
                    management is necessary for the performance of the contract
                    (providing the chain of custody signing service). The
                    processing of feedback form data is based on your consent,
                    given when you submit the form.
                </p>

                <h3>Data Retention</h3>
                <p>
                    Your account data (email, name) is retained for as long as
                    your account exists. Signature records are kept
                    indefinitely as they form part of an auditable chain of
                    custody. You can request deletion of your account and
                    personal data via the Feedback tab.
                </p>

                <h3>Your Rights</h3>
                <p>Under the General Data Protection Regulation you have the following rights:</p>
                <ul>
                    <li><strong>Right of access</strong> — request a copy of the personal data we hold about you.</li>
                    <li><strong>Right to rectification</strong> — request correction of inaccurate data.</li>
                    <li><strong>Right to erasure</strong> — request deletion of your account and personal data.</li>
                    <li><strong>Right to restrict processing</strong> — request limitation of data processing.</li>
                    <li><strong>Right to data portability</strong> — request a machine-readable export of your data.</li>
                    <li><strong>Right to object</strong> — object to the processing of your personal data.</li>
                </ul>
                <p>
                    To exercise any of these rights, use the Feedback tab or
                    contact the site administrator directly.
                </p>

                <h3>Data Security</h3>
                <p>
                    Passwords are stored as bcrypt hashes. Communications
                    between your browser and this website are encrypted via
                    HTTPS. The database is accessible only to the web
                    application and authorised administrators.
                </p>

                <h3>Third-Party Data Sharing</h3>
                <p>
                    We do not sell, rent, or share your personal data with
                    third parties. Emails sent through the feedback form are
                    delivered via the configured SMTP relay and are not stored
                    on the website.
                </p>

                <h3>Cookies</h3>
                <p>
                    This website uses a session cookie (PHPSESSID) that is
                    strictly necessary for authentication. No tracking,
                    analytics, or advertising cookies are used.
                </p>

                <h3>Changes to This Policy</h3>
                <p>
                    Any changes to this GDPR compliance statement will be
                    posted on this page. Continued use of the service after
                    changes constitutes acceptance of the updated policy.
                </p>

                <p style="margin-top:20px;font-size:13px;color:#888;">
                    Last updated: June 2026
                </p>
            </div>
        <?php else: ?>
            <form method="post" action="?action=<?= htmlspecialchars($activeTab) ?>" enctype="multipart/form-data">

                <?php if ($activeTab === 'update'): ?>
                <div class="form-group">
                    <label for="original_file">Original signed file (authentic, unmodified)</label>
                    <input type="file" name="original_file" id="original_file"
                           accept=".jpg,.jpeg,.png,.tif,.tiff,.cr2,.cr3,.nef" required>
                </div>
                <div class="form-group">
                    <label for="modified_file">Modified file to sign</label>
                    <input type="file" name="modified_file" id="modified_file"
                           accept=".jpg,.jpeg,.png,.tif,.tiff,.cr2,.cr3,.nef" required>
                </div>
                <?php else: ?>
                <div class="form-group">
                    <label for="file">Select image file (JPG, PNG, TIFF, CR2, CR3, NEF)</label>
                    <input type="file" name="file" id="file"
                           accept=".jpg,.jpeg,.png,.tif,.tiff,.cr2,.cr3,.nef" required>
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
