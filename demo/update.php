<?php

declare(strict_types=1);

/**
 * Chain of Custody — Update chain by signing a modified file.
 *
 * Usage:
 *   php demo/update.php <original-signed-file> <modified-file>
 *
 * Examples:
 *   php demo/update.php image-signed.jpg image-edited.jpg
 *   php demo/update.php image-signed.png image-edited.png
 *
 * Verifies the original signed file and that the demo user owns it,
 * then signs the modified file and links the new signature to the
 * original in the database. The signed modified file is saved with
 * "-updated" inserted before the extension.
 *
 * Run demo/sign.php first to create a signed file, then edit it
 * with any image editor, then run this script.
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

    $stmt = $pdo->prepare('SELECT id FROM users WHERE email = :email LIMIT 1');
    $stmt->execute([':email' => 'demo@example.com']);
    $row = $stmt->fetch();

    if ($row !== false) {
        return (int) $row['id'];
    }

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
    exit(1);
}

// ---------------------------------------------------------------------------
// Parse arguments
// ---------------------------------------------------------------------------

if ($argc < 3) {
    fwrite(STDERR, "Usage: php demo/update.php <original-signed-file> <modified-file>\n");
    fwrite(STDERR, "  Verifies the original, signs the modified, links the chain.\n");
    fwrite(STDERR, "\n");
    fwrite(STDERR, "Example workflow:\n");
    fwrite(STDERR, "  php demo/sign.php demo/image.jpg\n");
    fwrite(STDERR, "  # edit demo/image-signed.jpg in an image editor\n");
    fwrite(STDERR, "  php demo/update.php demo/image-signed.jpg demo/image-signed.jpg\n");
    exit(1);
}

$originalPath = $argv[1];
$modifiedPath = $argv[2];

if (! is_file($originalPath)) {
    fwrite(STDERR, "Original signed file not found: {$originalPath}\n");
    exit(1);
}
if (! is_file($modifiedPath)) {
    fwrite(STDERR, "Modified file not found: {$modifiedPath}\n");
    exit(1);
}

// Derive output path: insert "-updated" before the extension
$pathInfo   = pathinfo($modifiedPath);
$outputPath = $pathInfo['dirname'] . '/' . $pathInfo['filename'] . '-updated';
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
// Update chain of custody
// ---------------------------------------------------------------------------

echo "Chain of Custody — Update (two-file flow)\n";
echo str_repeat('─', 50) . "\n\n";

$coc = new ChainOfCustody($configPath);

echo "Original signed: {$originalPath}\n";
echo "Modified:        {$modifiedPath}\n";
echo "Output:          {$outputPath}\n\n";

// Verify the original signed file
echo "Verifying original signed file… ";
$existing = $coc->checkSignature($originalPath);
if ($existing['authenticated']) {
    echo "✅ valid.\n";
    printf("  Signed by: %s at %s\n",
        $existing['signature']['author_name'] ?? 'unknown',
        $existing['signature']['created_at']  ?? 'unknown');
    printf("  User ID:   %d\n", $existing['signature']['user_id'] ?? '?');
} else {
    echo "❌ not authentic or not signed.\n";
    echo "  Run demo/sign.php first to create a signed file.\n";
    exit(1);
}
echo "\n";

// Update: sign modified and link to original
echo "Updating chain of custody… ";
try {
    $result = $coc->updateChainOfCustody($originalPath, $modifiedPath, $demoUserId);
    file_put_contents($outputPath, $result['data']);
    echo "done.\n";
    printf("Output file: %d bytes\n\n", strlen($result['data']));

    // Verify the new signed copy
    echo "Verifying new signature… ";
    $verified = $coc->checkSignature($outputPath);
    if ($verified['authenticated']) {
        echo "✅ PASS\n";
        printf("  Hash:      %s\n", $verified['hash']);
        printf("  Signed by: %s\n", $verified['signature']['author_name'] ?? '?');
        printf("  Signed at: %s\n", $verified['signature']['created_at']   ?? '?');
    } else {
        echo "❌ FAIL\n";
    }
} catch (ChainOfCustodyException $e) {
    echo "❌ failed.\n  " . $e->getMessage() . "\n";
    exit(1);
}

// Display the chain of custody
echo "\n" . str_repeat('─', 50) . "\n\n";
echo "Chain of Custody:\n\n";

$chain = $coc->checkChainOfCustody($outputPath);
if ($chain['authenticated'] && ! empty($chain['chain'])) {
    foreach ($chain['chain'] as $i => $link) {
        $prefix = $i === 0 ? 'Current' : str_repeat(' ', 4) . '←';
        printf("  %s  %-16s  %s\n", $prefix, $link['author_name'], $link['created_at']);
        printf("  %s  %s\n", str_repeat(' ', 9), $link['signature_hash']);
        echo "\n";
    }
} else {
    echo "  (No records found in database)\n";
}

echo "Done. Signed modified file saved to {$outputPath}\n";
