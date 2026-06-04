<?php

declare(strict_types=1);

/**
 * Chain of Custody — Re-sign an already-signed image file.
 *
 * Usage:
 *   php demo/update.php <file>
 *
 * Examples:
 *   php demo/update.php image-signed.jpg   → image-signed-signed.jpg
 *   php demo/update.php image-signed.png   → image-signed-signed.png
 *
 * Verifies the existing signature, creates a new one linked to the
 * previous record, and saves the result with "-signed" inserted once
 * more before the extension.
 */

require_once __DIR__ . '/../src/ChainOfCustody.php';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

$configPath = __DIR__ . '/../tests/config.php';
if (! is_file($configPath)) {
    fwrite(STDERR, "Database config not found at {$configPath}\n");
    exit(1);
}

// ---------------------------------------------------------------------------
// Parse argument
// ---------------------------------------------------------------------------

if ($argc < 2) {
    fwrite(STDERR, "Usage: php demo/update.php <file>\n");
    fwrite(STDERR, "  Re-signs an already-signed image.\n");
    exit(1);
}

$inputPath = $argv[1];

if (! is_file($inputPath)) {
    fwrite(STDERR, "File not found: {$inputPath}\n");
    exit(1);
}

// Derive output path: insert another "-signed" before the extension
$pathInfo  = pathinfo($inputPath);
$outputPath = $pathInfo['dirname'] . '/' . $pathInfo['filename'] . '-signed';
if (! empty($pathInfo['extension'])) {
    $outputPath .= '.' . $pathInfo['extension'];
}

// ---------------------------------------------------------------------------
// Re-sign
// ---------------------------------------------------------------------------

echo "Chain of Custody — Re-sign\n";
echo str_repeat('─', 50) . "\n\n";

$coc = new ChainOfCustody($configPath);

echo "Input:  {$inputPath}\n";
echo "Output: {$outputPath}\n\n";

// Verify existing signature first
echo "Verifying existing signature… ";
$existing = $coc->checkSignature($inputPath);
if ($existing['authenticated']) {
    echo "✅ valid.\n";
    printf("  Previous signer: %s at %s\n",
        $existing['signature']['author_name'] ?? 'unknown',
        $existing['signature']['created_at']  ?? 'unknown');
} else {
    echo "⚠ not found or invalid — will sign fresh.\n";
}
echo "\n";

// Re-sign to a new file
echo "Re-signing with updated author… ";
$signedData = $coc->createSignedFile($inputPath, 'Notary Public');
file_put_contents($outputPath, $signedData);
echo "done.\n";
printf("Output file: %d bytes\n\n", strlen($signedData));

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
