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
 * Chain of Custody — Sign an image file.
 *
 * Usage:
 *   php demo/sign.php <file>
 *
 * Examples:
 *   php demo/sign.php image.jpg     → image-signed.jpg
 *   php demo/sign.php image.png     → image-signed.png
 *   php demo/sign.php image.tif     → image-signed.tif
 *
 * The format (TIFF/JPEG/PNG) is auto-detected from the file content.
 * The original file is never modified — the signed copy is written to
 * a new file with "-signed" inserted before the extension.
 */

require_once __DIR__ . '/../src/ChainOfCustody.php';

// ---------------------------------------------------------------------------
// Helper — find or create a demo user in the database
// ---------------------------------------------------------------------------

function getDemoUserId(string $configPath): ?int
{
    /** @var array<string, mixed> $config */
    $config = require $configPath;

    if (! is_array($config)) {
        return null;
    }

    $host    = $config['host'] ?? '127.0.0.1';
    $port    = $config['port'] ?? 3306;
    $dbname  = $config['dbname'] ?? '';
    $charset = $config['charset'] ?? 'utf8mb4';

    $dsn  = sprintf('mysql:host=%s;port=%d;dbname=%s;charset=%s', $host, $port, $dbname, $charset);
    $pdo  = new PDO($dsn, $config['username'] ?? '', $config['password'] ?? '', [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);

    // Look for an existing demo user
    $stmt = $pdo->prepare('SELECT id FROM users WHERE email = :email LIMIT 1');
    $stmt->execute([':email' => 'demo@example.com']);
    $row = $stmt->fetch();

    if ($row !== false) {
        return (int) $row['id'];
    }

    // Create a demo user
    $hash = password_hash('demo', PASSWORD_DEFAULT);
    $stmt = $pdo->prepare(
        'INSERT INTO users (email, password_hash, name, email_verified)
         VALUES (:email, :password_hash, :name, 1)'
    );
    $stmt->execute([
        ':email'         => 'demo@example.com',
        ':password_hash' => $hash,
        ':name'          => 'Demo User',
    ]);

    return (int) $pdo->lastInsertId();
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

$configPath = __DIR__ . '/../tests/config.php';
if (! is_file($configPath)) {
    fwrite(STDERR, "Database config not found at {$configPath}\n");
    fwrite(STDERR, "Copy tests/config.example.php to tests/config.php and fill in credentials.\n");
    exit(1);
}

// ---------------------------------------------------------------------------
// Parse argument
// ---------------------------------------------------------------------------

if ($argc < 2) {
    fwrite(STDERR, "Usage: php demo/sign.php <file>\n");
    fwrite(STDERR, "  Signs the given image and saves <base>-signed.<ext>\n");
    exit(1);
}

$inputPath = $argv[1];

if (! is_file($inputPath)) {
    fwrite(STDERR, "File not found: {$inputPath}\n");
    exit(1);
}

// Derive output path: insert "-signed" before the extension
$pathInfo  = pathinfo($inputPath);
$outputPath = $pathInfo['dirname'] . '/' . $pathInfo['filename'] . '-signed';
if (! empty($pathInfo['extension'])) {
    $outputPath .= '.' . $pathInfo['extension'];
}

// ---------------------------------------------------------------------------
// Bootstrap demo user
// ---------------------------------------------------------------------------

$demoUserId = getDemoUserId($configPath);
if ($demoUserId === null) {
    fwrite(STDERR, "Failed to find or create demo user.\n");
    exit(1);
}

echo "Demo user ID: {$demoUserId}\n\n";

// ---------------------------------------------------------------------------
// Sign
// ---------------------------------------------------------------------------

echo "Chain of Custody — Sign\n";
echo str_repeat('─', 50) . "\n\n";

$coc = new ChainOfCustody($configPath);

echo "Input:  {$inputPath}\n";
echo "Output: {$outputPath}\n\n";

echo "Signing… ";
$signedData = $coc->createSignedFile($inputPath, $demoUserId);
file_put_contents($outputPath, $signedData);
echo "done.\n";
printf("Signed file: %d bytes\n\n", strlen($signedData));

echo "Verifying… ";
$result = $coc->checkSignature($outputPath);
if ($result['authenticated']) {
    echo "✅ PASS — file is authentic.\n";
    if ($result['signature'] !== null) {
        echo "  Signed by: {$result['signature']['author_name']}\n";
        echo "  Signed at: {$result['signature']['created_at']}\n";
        echo "  Hash:      {$result['hash']}\n";
    }
} else {
    echo "❌ FAIL — file is NOT authentic.\n";
}

echo "\nDone. Signed file saved to {$outputPath}\n";
echo "The original " . basename($inputPath) . " was not modified.\n";
