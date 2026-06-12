<?php

declare(strict_types=1);

/**
 * Copyright © 2026 Cedric Raguenaud <cedric@raguenaud.earth>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

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
require_once __DIR__ . '/../src/NodeResolver.php';

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
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function jsonError(int $code, string $message): void
{
    jsonResponse(['status' => 'error', 'message' => $message], $code);
}

function getUploadedFile(string $field): array
{
    if (!isset($_FILES[$field])) {
        jsonError(400, "Missing file field: {$field}");
    }

    $file = $_FILES[$field];
    $err  = $file['error'];

    if ($err !== UPLOAD_ERR_OK) {
        $messages = [
            UPLOAD_ERR_INI_SIZE   => 'File exceeds server upload limit (upload_max_filesize).',
            UPLOAD_ERR_FORM_SIZE  => 'File exceeds form size limit.',
            UPLOAD_ERR_PARTIAL    => 'File was only partially uploaded.',
            UPLOAD_ERR_NO_FILE    => 'No file was uploaded.',
            UPLOAD_ERR_NO_TMP_DIR => 'Server is missing a temporary upload directory.',
            UPLOAD_ERR_CANT_WRITE => 'Server failed to write the uploaded file.',
            UPLOAD_ERR_EXTENSION  => 'A PHP extension stopped the upload.',
        ];
        $msg = $messages[$err] ?? "Upload error code {$err}.";
        jsonError(400, $msg);
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

function handleForward(): void
{
    $upload = getUploadedFile('file');
    try {
        $coc = new ChainOfCustody(CONFIG_PATH);
        $checkResult = $coc->checkSignature($upload['path']);

        $nodeId = $checkResult['node_id'] ?? '';

        if ($nodeId === '') {
            jsonError(400, 'No node identifier found in the file. This file may have been signed by a legacy node.');
        }

        if (!$checkResult['requires_remote']) {
            // The file belongs to this node — return the local verification result
            $chain = $coc->checkChainOfCustody($upload['path']);
            jsonResponse([
                'status'        => 'ok',
                'forwarded'     => false,
                'authenticated' => $checkResult['authenticated'],
                'hash_valid'    => $checkResult['hash_valid'],
                'hash'          => $checkResult['hash'],
                'signature'     => $checkResult['signature'],
                'chain'         => $chain['chain'],
            ]);
            return;
        }

        // Forward to the owning node
        $remoteResult = NodeResolver::forward($nodeId, $upload['path'], $upload['name']);

        jsonResponse([
            'status'    => 'ok',
            'forwarded' => true,
            'node_id'   => $nodeId,
            'result'    => $remoteResult,
        ]);
    } catch (RuntimeException $e) {
        jsonError(502, 'Forwarding failed: ' . $e->getMessage());
    } finally {
        cleanTemp($upload['path']);
    }
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

// Public metadata endpoint (GET only, no auth)
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
    if ($path === '/.well-known/chain-of-custody') {
        $config = require CONFIG_PATH;
        $nodeId = $config['node_id'] ?? '';
        header('Content-Type: application/json');
        echo json_encode([
            'node_id'          => $nodeId,
            'algorithm'        => 'SHA-256',
            'verification_url' => $nodeId !== ''
                ? "https://{$nodeId}.photo-verify.org/verify"
                : null,
        ], JSON_UNESCAPED_SLASHES);
        exit;
    }
    jsonError(404, 'Not found.');
}

// Only POST is accepted for API endpoints
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    jsonError(405, 'Method not allowed. Use POST.');
}

// Parse the route
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
$allowedRoutes = ['/sign', '/check', '/lookup', '/update', '/forward', '/verify', '/chain'];

if (!in_array($path, $allowedRoutes, true)) {
    jsonError(404, 'Not found. Available endpoints: /sign, /check, /lookup, /update, /verify');
}

// Public endpoints (no API key required)
$publicRoutes = ['/verify', '/chain'];

// Authenticate via API key (skip for public routes)
if (!in_array($path, $publicRoutes, true)) {
    $authHeader = $_SERVER['HTTP_AUTHORIZATION']
        ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION']
        ?? '';

    if (!preg_match('/^Bearer\s+(coc_.+)$/i', $authHeader, $matches)) {
        jsonError(401, 'Missing or invalid Authorization header. Expected: Bearer coc_<key>');
    }
}

// Public routes — no auth needed
if ($path === '/verify') {
    $coc = new ChainOfCustody(CONFIG_PATH);
    handleCheck($coc);
    exit;
}

if ($path === '/chain') {
    $input = json_decode(file_get_contents('php://input'), true);
    $hash  = trim($input['hash'] ?? $_POST['hash'] ?? '');
    if ($hash === '') {
        jsonError(400, 'Missing hash parameter.');
    }
    $coc   = new ChainOfCustody(CONFIG_PATH);
    $store = new SignatureStore(require CONFIG_PATH);
    $record = $store->findByHash($hash);

    if ($record === null) {
        jsonError(404, 'Hash not found on this node.');
    }

    $chain = $coc->resolveFullChain($hash);
    jsonResponse([
        'status'  => 'ok',
        'hash'    => $hash,
        'record'  => $record,
        'chain'   => $chain,
    ]);
    exit;
}

// Protected routes — require API key
$apiKey = $matches[1] ?? '';

try {
    $config   = require CONFIG_PATH;
    $keyStore = new ApiKeyStore($config);
    $keyData  = $keyStore->authenticate($apiKey);
    $userId   = (int) $keyData['user_id'];

    $keyStore->touch((int) $keyData['id']);

    $coc = new ChainOfCustody(CONFIG_PATH);

    match ($path) {
        '/sign'    => handleSign($coc, $userId),
        '/check'   => handleCheck($coc),
        '/lookup'  => handleLookup($coc),
        '/update'  => handleUpdate($coc, $userId),
        '/forward' => handleForward(),
    };
} catch (RuntimeException $e) {
    jsonError(401, $e->getMessage());
} catch (ChainOfCustodyException $e) {
    jsonError(400, $e->getMessage());
} catch (Throwable $e) {
    jsonError(500, 'Internal server error: ' . $e->getMessage());
}
