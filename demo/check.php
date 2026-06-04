<?php

declare(strict_types=1);

/**
 * Chain of Custody — Verify a signed image file and show its chain of custody.
 *
 * Usage:
 *   php demo/check.php <file>
 *
 * Examples:
 *   php demo/check.php image-signed.jpg
 *   php demo/check.php image-signed.png
 *   php demo/check.php image-signed.tif
 *
 * The file is checked for a valid Chain of Custody signature, then the
 * full chain of custody is retrieved from the database.
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
    fwrite(STDERR, "Usage: php demo/check.php <file>\n");
    fwrite(STDERR, "  Verifies the signature on a signed image file.\n");
    exit(1);
}

$signedPath = $argv[1];

if (! is_file($signedPath)) {
    fwrite(STDERR, "File not found: {$signedPath}\n");
    exit(1);
}

// ---------------------------------------------------------------------------
// Check signature
// ---------------------------------------------------------------------------

echo "Chain of Custody — Signature Check\n";
echo str_repeat('─', 50) . "\n\n";

$coc = new ChainOfCustody($configPath);

echo "File: {$signedPath}\n\n";

echo "Checking signature… ";
$result = $coc->checkSignature($signedPath);
echo "done.\n\n";

if ($result['authenticated']) {
    echo "  ✅ SIGNATURE VALID\n\n";
    echo "  Hash:      {$result['hash']}\n";
    echo "  Signed by: {$result['signature']['author_name']}\n";
    echo "  Signed at: {$result['signature']['created_at']}\n";
} elseif ($result['hash_valid']) {
    echo "  ❌ SIGNATURE NOT IN DATABASE\n\n";
    echo "  Hash:      {$result['hash']}\n";
    echo "  The file content is authentic but no matching signature record\n";
    echo "  was found in the database.\n";
} elseif ($result['hash'] !== null) {
    echo "  ❌ SIGNATURE INVALID\n\n";
    echo "  Hash:      {$result['hash']}\n";
    echo "  The file has a signature tag but the content does not match.\n";
    echo "  It may have been tampered with.\n";
} else {
    echo "  ❌ NO SIGNATURE\n\n";
    echo "  No Chain of Custody signature found in this file.\n";
}

// Chain of custody
echo "\n";
echo str_repeat('─', 50) . "\n\n";
echo "Chain of Custody:\n\n";

$chainResult = $coc->checkChainOfCustody($signedPath);

if ($chainResult['authenticated'] && ! empty($chainResult['chain'])) {
    foreach ($chainResult['chain'] as $i => $link) {
        $label = $i === 0 ? 'Current' : str_repeat(' ', 7) . '←';
        echo "  {$label}  {$link['author_name']}  ({$link['created_at']})\n";
        echo "         {$link['signature_hash']}\n\n";
    }
} else {
    echo "  (No chain of custody records in the database)\n";
}
