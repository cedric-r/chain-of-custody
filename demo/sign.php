<?php

declare(strict_types=1);

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
// Sign
// ---------------------------------------------------------------------------

echo "Chain of Custody — Sign\n";
echo str_repeat('─', 50) . "\n\n";

$coc = new ChainOfCustody($configPath);

echo "Input:  {$inputPath}\n";
echo "Output: {$outputPath}\n\n";

echo "Signing… ";
$signedData = $coc->createSignedFile($inputPath, 'Demo User');
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
