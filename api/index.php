<?php

declare(strict_types=1);

/**
 * Chain of Custody — REST API
 *
 * Provides programmatic access to signing, checking, looking up, and
 * updating image signatures. All endpoints use POST with
 * multipart/form-data and require authentication via an API key
 * in the Authorization header.
 *
 * Usage:
 *   curl -X POST https://api.photo-verify.org/sign \
 *     -H "Authorization: Bearer coc_<key>" \
 *     -F "file=@image.jpg"
 */

require_once __DIR__ . '/../src/ChainOfCustody.php';
require_once __DIR__ . '/../src/ApiKeyStore.php';

define('CONFIG_PATH', __DIR__ . '/config.php');
define('MAX_FILE_SIZE', 100 * 1024 * 1024);
define('ALLOWED_EXTENSIONS', ['jpg', 'jpeg', 'png', 'tif', 'tiff', 'cr2', 'cr3', 'nef']);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function jsonResponse(array $data, int $code = 200): void
{
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

function jsonError(int $code, string $message): void
{
    jsonResponse(['status' => 'error', 'message' => $message], $code);
}

function getUploadedFile(string $field): array
{
    if (!isset($_FILES[$field]) || $_FILES[$field]['error'] !== UPLOAD_ERR_OK) {
        jsonError(400, "Missing or invalid file field: {$field}");
    }

    $file = $_FILES[$field];

    if ($file['size'] > MAX_FILE_SIZE) {
        jsonError(413, 'File too large. Maximum size is 100 MB.');
    }

    $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    if (!in_array($ext, ALLOWED_EXTENSIONS, true)) {
        jsonError(400, 'Unsupported file format. Allowed: JPG, PNG, TIFF, CR2, CR3, NEF.');
    }

    $tmpPath = tempnam(sys_get_temp_dir(), 'coc_api_');
    if (!move_uploaded_file($file['tmp_name'], $tmpPath)) {
        jsonError(500, 'Failed to process uploaded file.');
    }

    return ['path' => $tmpPath, 'name' => $file['name'], 'ext' => $ext];
}

function cleanTemp(string $path): void
{
    if (file_exists($path)) {
        @unlink($path);
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

function handleSign(ChainOfCustody $coc, int $userId): void
{
    $upload = getUploadedFile('file');
    try {
        $signedData = $coc->createSignedFile($upload['path'], $userId);

        $checkResult = $coc->checkSignature($upload['path']);

        jsonResponse([
            'status' => 'ok',
            'hash'   => $checkResult['hash'] ?? hash('sha256', $signedData),
            'size'   => strlen($signedData),
            'signed' => base64_encode($signedData),
        ]);
    } finally {
        cleanTemp($upload['path']);
    }
}

function handleCheck(ChainOfCustody $coc): void
{
    $upload = getUploadedFile('file');
    try {
        $result = $coc->checkSignature($upload['path']);
        $chain  = $coc->checkChainOfCustody($upload['path']);

        jsonResponse([
            'status'        => 'ok',
            'authenticated' => $result['authenticated'],
            'hash_valid'    => $result['hash_valid'],
            'hash'          => $result['hash'],
            'signature'     => $result['signature'],
            'chain'         => $chain['chain'],
        ]);
    } finally {
        cleanTemp($upload['path']);
    }
}

function handleLookup(ChainOfCustody $coc): void
{
    $upload = getUploadedFile('file');
    try {
        $result = $coc->lookupSignature($upload['path']);

        jsonResponse([
            'status'     => 'ok',
            'found'      => $result['found'],
            'hash'       => $result['hash'],
            'record'     => $result['record'],
            'chain'      => $result['chain'],
        ]);
    } finally {
        cleanTemp($upload['path']);
    }
}

function handleUpdate(ChainOfCustody $coc, int $userId): void
{
    $original = getUploadedFile('original');
    $modified = getUploadedFile('modified');
    try {
        $result = $coc->updateChainOfCustody($original['path'], $modified['path'], $userId);

        jsonResponse([
            'status'   => 'ok',
            'hash'     => $result['hash'],
            'size'     => strlen($result['data']),
            'signed'   => base64_encode($result['data']),
            'original' => $result['original'],
        ]);
    } finally {
        cleanTemp($original['path']);
        cleanTemp($modified['path']);
    }
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

// Only POST is accepted
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    jsonError(405, 'Method not allowed. Use POST.');
}

// Parse the route
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
$allowedRoutes = ['/sign', '/check', '/lookup', '/update'];

if (!in_array($path, $allowedRoutes, true)) {
    jsonError(404, 'Not found. Available endpoints: /sign, /check, /lookup, /update');
}

// Authenticate via API key
$authHeader = $_SERVER['HTTP_AUTHORIZATION']
    ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION']
    ?? '';

if (!preg_match('/^Bearer\s+(coc_.+)$/i', $authHeader, $matches)) {
    jsonError(401, 'Missing or invalid Authorization header. Expected: Bearer coc_<key>');
}

$apiKey = $matches[1];

try {
    $config   = require CONFIG_PATH;
    $keyStore = new ApiKeyStore($config);
    $keyData  = $keyStore->authenticate($apiKey);
    $userId   = (int) $keyData['user_id'];

    // Update last used timestamp (fire and forget)
    $keyStore->touch((int) $keyData['id']);

    // Build ChainOfCustody and route
    $coc = new ChainOfCustody(CONFIG_PATH);

    match ($path) {
        '/sign'   => handleSign($coc, $userId),
        '/check'  => handleCheck($coc),
        '/lookup' => handleLookup($coc),
        '/update' => handleUpdate($coc, $userId),
    };
} catch (RuntimeException $e) {
    jsonError(401, $e->getMessage());
} catch (ChainOfCustodyException $e) {
    jsonError(400, $e->getMessage());
} catch (Throwable $e) {
    jsonError(500, 'Internal server error: ' . $e->getMessage());
}
