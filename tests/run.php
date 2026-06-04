<?php

declare(strict_types=1);

/**
 * Chain of Custody — Full test suite.
 *
 * Usage:  php tests/run.php
 *
 * Sections:
 *   1. ImageSignatureHandler  — abstract class & isValidHash
 *   2. TiffSignatureHandler   — TIFF unit tests (no DB)
 *   3. JpegSignatureHandler   — JPEG unit tests (no DB)
 *   3b. PngSignatureHandler    — PNG unit tests (no DB)
 *   4. ChainOfCustody         — integration tests (require MySQL)
 */

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

require_once __DIR__ . '/../src/ImageSignatureHandler.php';
require_once __DIR__ . '/../src/SignatureStore.php';
require_once __DIR__ . '/../src/ChainOfCustody.php';

// Paths
const ORIGINAL_TIF = __DIR__ . '/../demo/image.tif';
const TEST_TIF     = __DIR__ . '/test.tif';

// ---------------------------------------------------------------------------
// Mini test framework
// ---------------------------------------------------------------------------

$GLOBALS['passed']  = 0;
$GLOBALS['failed']  = 0;
$GLOBALS['skipped'] = 0;

function test(string $label, callable $fn): void
{
    try {
        $fn();
        $GLOBALS['passed']++;
        echo "  PASS  {$label}\n";
    } catch (Throwable $e) {
        $GLOBALS['failed']++;
        echo "  FAIL  {$label}\n";
        echo "        " . $e->getMessage() . "\n";
        if ($e->getPrevious()) {
            echo "        Caused by: " . $e->getPrevious()->getMessage() . "\n";
        }
    }
}

function skip(string $label, string $reason): void
{
    $GLOBALS['skipped']++;
    echo "  SKIP  {$label}  — {$reason}\n";
}

function assertTrue(bool $condition, string $message = 'Expected true'): void
{
    if (! $condition) {
        throw new RuntimeException($message);
    }
}

function assertFalse(bool $condition, string $message = 'Expected false'): void
{
    if ($condition) {
        throw new RuntimeException($message);
    }
}

function assertEquals(mixed $expected, mixed $actual, string $message = ''): void
{
    if ($expected !== $actual) {
        $msg = $message ?: 'Values differ';
        throw new RuntimeException(
            "{$msg}\n            Expected: " . var_export($expected, true)
            . "\n            Actual:   " . var_export($actual, true)
        );
    }
}

function assertNotEquals(mixed $expected, mixed $actual, string $message = ''): void
{
    if ($expected === $actual) {
        $msg = $message ?: 'Values should differ but are identical';
        throw new RuntimeException("{$msg}: " . var_export($expected, true));
    }
}

function assertNull(mixed $value, string $message = 'Expected null'): void
{
    if ($value !== null) {
        throw new RuntimeException("{$message}, got: " . var_export($value, true));
    }
}

function assertNotNull(mixed $value, string $message = 'Expected non-null'): void
{
    if ($value === null) {
        throw new RuntimeException($message);
    }
}

function assertThrows(string $exceptionClass, callable $fn): void
{
    try {
        $fn();
        throw new RuntimeException("Expected {$exceptionClass} but no exception was thrown");
    } catch (\Throwable $e) {
        if (! $e instanceof $exceptionClass) {
            throw new RuntimeException(
                "Expected {$exceptionClass} but got " . get_class($e) . ': ' . $e->getMessage(),
                0,
                $e
            );
        }
    }
}

function assertIsString(mixed $value, string $message = 'Expected string'): void
{
    if (! is_string($value)) {
        throw new RuntimeException($message . ', got: ' . gettype($value));
    }
}

// ---------------------------------------------------------------------------
// Test data helpers
// ---------------------------------------------------------------------------

function readTiff(): string
{
    static $data = null;
    if ($data === null) {
        $data = file_get_contents(ORIGINAL_TIF);
        if ($data === false) {
            throw new RuntimeException('Cannot read ' . ORIGINAL_TIF);
        }
    }
    return $data;
}

function copyTif(): string
{
    $src = ORIGINAL_TIF;
    $dst = TEST_TIF;
    if (! copy($src, $dst)) {
        throw new RuntimeException("Cannot copy {$src} to {$dst}");
    }
    return $dst;
}

/**
 * Copy the test TIFF and flip one byte so the content differs.
 * The result is a different file than the original — useful as a
 * "modified" file in updateChainOfCustody tests.
 */
function copyModifiedTif(): string
{
    $src = ORIGINAL_TIF;
    $dst = __DIR__ . '/test_modified.tif';
    if (! copy($src, $dst)) {
        throw new RuntimeException("Cannot copy {$src} to {$dst}");
    }
    $data = file_get_contents($dst);
    $data[777] = chr(ord($data[777]) ^ 0xFF);
    file_put_contents($dst, $data);

    return $dst;
}

/**
 * Build a minimal valid JPEG file for marker-scanning tests.
 *
 * Structure: SOI + APP1 + SOF0 + DHT + SOS + minimal scan data + EOI
 */
function createTestJpeg(): string
{
    $jpeg = "\xFF\xD8"; // SOI

    // APP1 — general metadata
    $app1data = "TestJpeg\0";
    $jpeg .= "\xFF\xE1" . pack('n', strlen($app1data) + 2) . $app1data;

    // SOF0 — 1×1 pixel, 8-bit, 1 component
    $sof0 = "\x08\x00\x01\x00\x01\x01\x11\x00";
    $jpeg .= "\xFF\xC0" . pack('n', strlen($sof0) + 2) . $sof0;

    // DHT — minimal Huffman table (required for valid SOS)
    $dht = "\x00\xFF\x00";
    $jpeg .= "\xFF\xC4" . pack('n', strlen($dht) + 2) . $dht;

    // SOS — start of scan
    $sos = "\x01\x01\x00\x00\x3F\x00";
    $jpeg .= "\xFF\xDA" . pack('n', strlen($sos) + 2) . $sos;

    // Scan data
    $jpeg .= "\x7B\x40\x00";

    // EOI
    $jpeg .= "\xFF\xD9";

    return $jpeg;
}

/**
 * Build a minimal PNG file for chunk-scanning tests.
 *
 * Structure: PNG sig + IHDR (1×1) + IEND.
 * CRCs are computed properly for valid chunk structure.
 */
function createTestPng(): string
{
    $png = "\x89PNG\r\n\x1a\n";

    // IHDR — 1×1 pixel, 8-bit truecolour
    $ihdrData = pack('NNCCCCC', 1, 1, 8, 2, 0, 0, 0);
    $ihdrCrc  = pack('N', crc32('IHDR' . $ihdrData) & 0xFFFFFFFF);
    $png .= pack('N', 13) . 'IHDR' . $ihdrData . $ihdrCrc;

    // IEND — empty
    $iendCrc = pack('N', crc32('IEND') & 0xFFFFFFFF);
    $png .= pack('N', 0) . 'IEND' . $iendCrc;

    return $png;
}

function cleanup(): void
{
    if (is_file(TEST_TIF)) {
        unlink(TEST_TIF);
    }
    $modified = __DIR__ . '/test_modified.tif';
    if (is_file($modified)) {
        unlink($modified);
    }
    $signed = __DIR__ . '/test_signed.tif';
    if (is_file($signed)) {
        unlink($signed);
    }
}

// ===========================================================================
// 1. ImageSignatureHandler — abstract class tests
// ===========================================================================

echo "\n══════════════════════════════════════════════════════════════════\n";
echo "  ImageSignatureHandler — Abstract Base\n";
echo "══════════════════════════════════════════════════════════════════\n\n";

echo "── isValidHash (shared implementation)\n";

// Use a concrete handler to test the inherited implementation
$handler = new TiffSignatureHandler();

test('accepts valid SHA-256 hex string', function () use ($handler) {
    assertTrue($handler->isValidHash('abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789'));
});

test('rejects short string', function () {
    $h = new TiffSignatureHandler();
    assertFalse($h->isValidHash('abc'));
});

test('rejects string with non-hex characters', function () {
    $h = new TiffSignatureHandler();
    assertFalse($h->isValidHash(str_repeat('g', 64)));
});

test('rejects empty string', function () {
    $h = new TiffSignatureHandler();
    assertFalse($h->isValidHash(''));
});

echo "\n── Exceptions\n";

test('ChainOfCustodyException is throwable', function () {
    assertThrows(ChainOfCustodyException::class, function () {
        throw new ChainOfCustodyException('test');
    });
});

test('InvalidImageException extends ChainOfCustodyException', function () {
    assertThrows(ChainOfCustodyException::class, function () {
        throw new InvalidImageException('test');
    });
});

// ===========================================================================
// 2. TiffSignatureHandler — unit tests
// ===========================================================================

echo "\n══════════════════════════════════════════════════════════════════\n";
echo "  TiffSignatureHandler — Unit Tests\n";
echo "══════════════════════════════════════════════════════════════════\n\n";

$tiff = new TiffSignatureHandler();

echo "── detect()\n";

test('detects little-endian TIFF', function () use ($tiff) {
    assertTrue($tiff->detect(readTiff()));
});

test('rejects data smaller than 8 bytes', function () use ($tiff) {
    assertFalse($tiff->detect('II'));
});

test('rejects unknown byte order', function () use ($tiff) {
    assertFalse($tiff->detect("XX\x2a\x00\x08\x00\x00\x00"));
});

test('rejects wrong TIFF magic number', function () use ($tiff) {
    assertFalse($tiff->detect("II\x01\x00\x08\x00\x00\x00"));
});

test('rejects JPEG data', function () use ($tiff) {
    $jpeg = createTestJpeg();
    assertFalse($tiff->detect($jpeg));
});

echo "\n── getFormatName()\n";

test('returns "TIFF"', function () use ($tiff) {
    assertEquals('TIFF', $tiff->getFormatName());
});

// --- find() on unsigned file ------------------------------------------------

echo "\n── find() — unsigned file\n";

test('returns null when no signature tag exists', function () use ($tiff) {
    $data   = readTiff();
    $result = $tiff->find($data);
    assertNull($result);
});

// --- getUnsignedInfo() -------------------------------------------------------

echo "\n── getUnsignedInfo()\n";

test('returns the last IFD position for unsigned file', function () use ($tiff) {
    $data = readTiff();
    $info = $tiff->getUnsignedInfo($data);
    assertTrue($info['nextOffsetPos'] > 0, 'nextOffsetPos should be > 0');
    assertEquals('II', $info['byteOrder']);
});

// --- First-time signing round-trip -------------------------------------------

echo "\n── Signing round-trip (in-memory)\n";

test('signs an unsigned file by appending IFD', function () use ($tiff) {
    $data = readTiff();
    $originalHash = hash('sha256', $data);

    $unsignedInfo = $tiff->getUnsignedInfo($data);
    $signed = $tiff->signUnsigned($data, $originalHash, $unsignedInfo);

    assertTrue(strlen($signed) > strlen($data), 'Signed file should be larger');
    assertEquals(strlen($data) + 83, strlen($signed),
        'File should grow by exactly 83 bytes (18 IFD + 65 hash)');
});

test('find() locates the signature after signing', function () use ($tiff) {
    $data = readTiff();
    $originalHash = hash('sha256', $data);

    $unsignedInfo = $tiff->getUnsignedInfo($data);
    $signed = $tiff->signUnsigned($data, $originalHash, $unsignedInfo);

    $info = $tiff->find($signed);
    assertNotNull($info, 'find() should return info for signed file');
    assertEquals($originalHash, $info['hash'], 'Stored hash should match original file hash');
    assertEquals('II', $info['byteOrder']);
    assertTrue($info['sigIfdPos'] > 0, 'sigIfdPos should be > 0');
});

test('computeOriginalHash matches the original file hash', function () use ($tiff) {
    $data = readTiff();
    $originalHash = hash('sha256', $data);

    $unsignedInfo = $tiff->getUnsignedInfo($data);
    $signed = $tiff->signUnsigned($data, $originalHash, $unsignedInfo);

    $info = $tiff->find($signed);
    assertNotNull($info);

    $computedHash = $tiff->computeOriginalHash($signed, $info);
    assertEquals($originalHash, $computedHash,
        'computeOriginalHash should reconstruct the original file bytes');
});

test('verification succeeds after signing', function () use ($tiff) {
    $data = readTiff();
    $originalHash = hash('sha256', $data);

    $unsignedInfo = $tiff->getUnsignedInfo($data);
    $signed = $tiff->signUnsigned($data, $originalHash, $unsignedInfo);

    $info = $tiff->find($signed);
    assertNotNull($info);

    $computedHash = $tiff->computeOriginalHash($signed, $info);
    assertTrue(
        hash_equals($info['hash'], $computedHash),
        'Stored hash should match computed hash (verification should pass)'
    );
});

// --- Tamper detection -------------------------------------------------------

echo "\n── Tamper detection\n";

test('verification fails when file is tampered with after signing', function () use ($tiff) {
    $data = readTiff();
    $unsignedInfo = $tiff->getUnsignedInfo($data);
    $signed = $tiff->signUnsigned($data, hash('sha256', $data), $unsignedInfo);

    // Flip a byte in the image data
    $tampered       = $signed;
    $tampered[5000] = chr(ord($tampered[5000]) ^ 0xFF);

    $info = $tiff->find($tampered);
    assertNotNull($info);

    $computedHash = $tiff->computeOriginalHash($tampered, $info);
    assertFalse(
        hash_equals($info['hash'], $computedHash),
        'Hash should NOT match after tampering'
    );
});

test('verification fails when IFD entry count is altered', function () use ($tiff) {
    $data = readTiff();
    $unsignedInfo = $tiff->getUnsignedInfo($data);
    $signed = $tiff->signUnsigned($data, hash('sha256', $data), $unsignedInfo);

    // Flip a bit in the TIFF header's first-IFD offset
    $tampered     = $signed;
    $tampered[6]  = chr(ord($tampered[6]) ^ 0x01);

    $info = $tiff->find($tampered);
    assertNotNull($info);

    $computedHash = $tiff->computeOriginalHash($tampered, $info);
    assertFalse(hash_equals($info['hash'], $computedHash));
});

// --- Re-signing -------------------------------------------------------------

echo "\n── Re-signing\n";

test('re-signing produces matching hash for unchanged file', function () use ($tiff) {
    $data = readTiff();
    $unsignedInfo = $tiff->getUnsignedInfo($data);
    $hash1 = hash('sha256', $data);
    $signed = $tiff->signUnsigned($data, $hash1, $unsignedInfo);

    // Verify first signature
    $info1 = $tiff->find($signed);
    $computed1 = $tiff->computeOriginalHash($signed, $info1);
    assertTrue(hash_equals($info1['hash'], $computed1));

    // Re-sign
    $hash2 = $tiff->computeOriginalHash($signed, $info1);
    $resigned = $tiff->updateSignature($signed, $hash2, $info1);

    $info2 = $tiff->find($resigned);
    assertNotNull($info2);

    $computed2 = $tiff->computeOriginalHash($resigned, $info2);
    assertTrue(hash_equals($info2['hash'], $computed2));
});

// --- Big-endian pack/unpack -------------------------------------------------

echo "\n── Byte order (private helpers via reflection)\n";

test('pack/unpack round-trip for both byte orders', function () {
    $handler    = new TiffSignatureHandler();
    $reflection = new ReflectionClass(TiffSignatureHandler::class);
    $getPrivate = function (string $name) use ($reflection) {
        $m = $reflection->getMethod($name);
        $m->setAccessible(true);
        return $m;
    };

    $pack16   = fn($v, $bo) => $getPrivate('pack16')->invoke($handler, $v, $bo);
    $pack32   = fn($v, $bo) => $getPrivate('pack32')->invoke($handler, $v, $bo);
    $unpack16 = fn($d, $o, $bo) => $getPrivate('unpack16')->invoke($handler, $d, $o, $bo);
    $unpack32 = fn($d, $o, $bo) => $getPrivate('unpack32')->invoke($handler, $d, $o, $bo);

    $values16 = [0, 1, 255, 32767, 65535];
    $values32 = [0, 1, 255, 65535, 16777215, 0x7FFFFFFF, 0xFFFFFFFF];

    foreach (['II', 'MM'] as $bo) {
        foreach ($values16 as $v) {
            $packed = $pack16($v, $bo);
            assertEquals(2, strlen($packed));
            assertEquals($v, $unpack16($packed, 0, $bo), "16-bit {$v} in {$bo}");
        }
        foreach ($values32 as $v) {
            $packed = $pack32($v, $bo);
            assertEquals(4, strlen($packed));
            assertEquals($v, $unpack32($packed, 0, $bo), "32-bit {$v} in {$bo}");
        }
    }
});

// ===========================================================================
// 3. JpegSignatureHandler — unit tests
// ===========================================================================

echo "\n══════════════════════════════════════════════════════════════════\n";
echo "  JpegSignatureHandler — Unit Tests\n";
echo "══════════════════════════════════════════════════════════════════\n\n";

$jpeg = new JpegSignatureHandler();

echo "── detect()\n";

test('detects JPEG by SOI marker', function () use ($jpeg) {
    assertTrue($jpeg->detect(createTestJpeg()));
});

test('rejects TIFF data', function () use ($jpeg) {
    assertFalse($jpeg->detect(readTiff()));
});

test('rejects empty data', function () use ($jpeg) {
    assertFalse($jpeg->detect(''));
});

test('rejects single byte', function () use ($jpeg) {
    assertFalse($jpeg->detect("\xFF"));
});

echo "\n── getFormatName()\n";

test('returns "JPEG"', function () use ($jpeg) {
    assertEquals('JPEG', $jpeg->getFormatName());
});

// --- find() on unsigned file ------------------------------------------------

echo "\n── find() — unsigned file\n";

test('returns null for JPEG without CoC marker', function () use ($jpeg) {
    assertNull($jpeg->find(createTestJpeg()));
});

// --- First-time signing round-trip -------------------------------------------

echo "\n── Signing round-trip (in-memory)\n";

test('signs an unsigned JPEG by inserting APP8 marker', function () use ($jpeg) {
    $data = createTestJpeg();
    $originalHash = hash('sha256', $data);

    $info   = $jpeg->getUnsignedInfo($data);
    $signed = $jpeg->signUnsigned($data, $originalHash, $info);

    assertTrue(strlen($signed) > strlen($data), 'Signed JPEG should be larger');
    assertEquals(strlen($data) + 73, strlen($signed),
        'JPEG should grow by exactly 73 bytes (APP8 segment)');
});

test('signUnsigned inserts APP8 with our identifier', function () use ($jpeg) {
    $data = createTestJpeg();
    $originalHash = hash('sha256', $data);

    $info   = $jpeg->getUnsignedInfo($data);
    $signed = $jpeg->signUnsigned($data, $originalHash, $info);

    // Check the marker bytes are at position 2
    assertEquals("\xFF\xE8", substr($signed, 2, 2), 'Should have APP8 marker at position 2');
    assertEquals("CoC\0", substr($signed, 6, 4), 'Should have CoC identifier');
});

test('find() locates the signature after signing JPEG', function () use ($jpeg) {
    $data = createTestJpeg();
    $originalHash = hash('sha256', $data);

    $info   = $jpeg->getUnsignedInfo($data);
    $signed = $jpeg->signUnsigned($data, $originalHash, $info);

    $found = $jpeg->find($signed);
    assertNotNull($found, 'find() should return info for signed JPEG');
    assertEquals($originalHash, $found['hash']);
    assertEquals(2, $found['markerPos'], 'Marker should be at position 2');
    assertEquals(73, $found['totalSegmentBytes']);
});

test('computeOriginalHash matches original JPEG hash', function () use ($jpeg) {
    $data = createTestJpeg();
    $originalHash = hash('sha256', $data);

    $info   = $jpeg->getUnsignedInfo($data);
    $signed = $jpeg->signUnsigned($data, $originalHash, $info);

    $found        = $jpeg->find($signed);
    $computedHash = $jpeg->computeOriginalHash($signed, $found);
    assertEquals($originalHash, $computedHash);
});

test('verification succeeds after signing JPEG', function () use ($jpeg) {
    $data = createTestJpeg();
    $originalHash = hash('sha256', $data);

    $info   = $jpeg->getUnsignedInfo($data);
    $signed = $jpeg->signUnsigned($data, $originalHash, $info);

    $found        = $jpeg->find($signed);
    $computedHash = $jpeg->computeOriginalHash($signed, $found);
    assertTrue(hash_equals($found['hash'], $computedHash));
});

// --- JPEG tamper detection --------------------------------------------------

echo "\n── Tamper detection (JPEG)\n";

test('JPEG verification fails after tampering', function () use ($jpeg) {
    $data = createTestJpeg();
    $originalHash = hash('sha256', $data);

    $info   = $jpeg->getUnsignedInfo($data);
    $signed = $jpeg->signUnsigned($data, $originalHash, $info);

    // Modify a byte in the image data (after SOS)
    $tampered          = $signed;
    $sosEnd            = strpos($tampered, "\xFF\xDA") + 8; // past SOS segment
    $tampered[$sosEnd] = chr(ord($tampered[$sosEnd]) ^ 0xFF);

    $found        = $jpeg->find($tampered);
    assertNotNull($found);

    $computedHash = $jpeg->computeOriginalHash($tampered, $found);
    assertFalse(hash_equals($found['hash'], $computedHash));
});

// --- JPEG re-signing --------------------------------------------------------

echo "\n── Re-signing (JPEG)\n";

test('JPEG re-signing produces matching hash', function () use ($jpeg) {
    $data = createTestJpeg();
    $hash1 = hash('sha256', $data);

    $info   = $jpeg->getUnsignedInfo($data);
    $signed = $jpeg->signUnsigned($data, $hash1, $info);

    $info1 = $jpeg->find($signed);
    $computed1 = $jpeg->computeOriginalHash($signed, $info1);
    assertTrue(hash_equals($info1['hash'], $computed1));

    // Re-sign
    $hash2    = $jpeg->computeOriginalHash($signed, $info1);
    $resigned = $jpeg->updateSignature($signed, $hash2, $info1);

    $info2 = $jpeg->find($resigned);
    assertNotNull($info2);

    $computed2 = $jpeg->computeOriginalHash($resigned, $info2);
    assertTrue(hash_equals($info2['hash'], $computed2));
});

// ===========================================================================
// 3b. PngSignatureHandler — unit tests
// ===========================================================================

echo "\n══════════════════════════════════════════════════════════════════\n";
echo "  PngSignatureHandler — Unit Tests\n";
echo "══════════════════════════════════════════════════════════════════\n\n";

$png = new PngSignatureHandler();

echo "── detect()\n";

test('detects PNG by signature', function () use ($png) {
    assertTrue($png->detect(createTestPng()));
});

test('rejects TIFF data', function () use ($png) {
    assertFalse($png->detect(readTiff()));
});

test('rejects JPEG data', function () use ($png) {
    assertFalse($png->detect(createTestJpeg()));
});

test('rejects empty data', function () use ($png) {
    assertFalse($png->detect(''));
});

echo "\n── getFormatName()\n";

test('returns "PNG"', function () use ($png) {
    assertEquals('PNG', $png->getFormatName());
});

// --- find() on unsigned PNG ------------------------------------------------

echo "\n── find() — unsigned file\n";

test('returns null for PNG without coCs chunk', function () use ($png) {
    assertNull($png->find(createTestPng()));
});

// --- First-time signing round-trip -------------------------------------------

echo "\n── Signing round-trip (in-memory)\n";

test('signs an unsigned PNG by inserting coCs chunk', function () use ($png) {
    $data = createTestPng();
    $originalHash = hash('sha256', $data);

    $info   = $png->getUnsignedInfo($data);
    $signed = $png->signUnsigned($data, $originalHash, $info);

    assertTrue(strlen($signed) > strlen($data), 'Signed PNG should be larger');
    assertEquals(strlen($data) + 77, strlen($signed),
        'PNG should grow by exactly 77 bytes (coCs chunk)');
});

test('signUnsigned inserts coCs with correct structure', function () use ($png) {
    $data = createTestPng();
    $originalHash = hash('sha256', $data);

    $info   = $png->getUnsignedInfo($data);
    $signed = $png->signUnsigned($data, $originalHash, $info);

    // After PNG sig (8) + IHDR chunk (25), coCs should be at position 33
    assertEquals(65, unpack('N', substr($signed, 33, 4))[1], 'Data length should be 65');
    assertEquals('coCs', substr($signed, 37, 4), 'Chunk type should be coCs');
});

test('find() locates the signature after signing PNG', function () use ($png) {
    $data = createTestPng();
    $originalHash = hash('sha256', $data);

    $info   = $png->getUnsignedInfo($data);
    $signed = $png->signUnsigned($data, $originalHash, $info);

    $found = $png->find($signed);
    assertNotNull($found, 'find() should return info for signed PNG');
    assertEquals($originalHash, $found['hash']);
    assertEquals(33, $found['chunkPos'], 'coCs chunk should be at position 33');
    assertEquals(77, $found['totalChunkBytes']);
});

test('computeOriginalHash matches original PNG hash', function () use ($png) {
    $data = createTestPng();
    $originalHash = hash('sha256', $data);

    $info   = $png->getUnsignedInfo($data);
    $signed = $png->signUnsigned($data, $originalHash, $info);

    $found        = $png->find($signed);
    $computedHash = $png->computeOriginalHash($signed, $found);
    assertEquals($originalHash, $computedHash);
});

test('verification succeeds after signing PNG', function () use ($png) {
    $data = createTestPng();
    $originalHash = hash('sha256', $data);

    $info   = $png->getUnsignedInfo($data);
    $signed = $png->signUnsigned($data, $originalHash, $info);

    $found        = $png->find($signed);
    $computedHash = $png->computeOriginalHash($signed, $found);
    assertTrue(hash_equals($found['hash'], $computedHash));
});

// --- CRC integrity ----------------------------------------------------------

echo "\n── CRC integrity\n";

test('updateSignature recalculates CRC correctly', function () use ($png) {
    $data = createTestPng();
    $hash1 = hash('sha256', $data);

    $info   = $png->getUnsignedInfo($data);
    $signed = $png->signUnsigned($data, $hash1, $info);

    $info1 = $png->find($signed);

    // Re-sign with a different hash
    $hash2    = str_repeat('a', 64); // dummy hash
    $resigned = $png->updateSignature($signed, $hash2, $info1);

    // Verify the CRC is valid for the new data
    $crcPos  = 33 + 8 + 65; // chunkPos + len+type + hash
    $storedCrc = unpack('N', substr($resigned, $crcPos, 4))[1];
    $expectedCrc = crc32('coCs' . str_pad($hash2, 65, "\0")) & 0xFFFFFFFF;
    assertEquals($expectedCrc, $storedCrc, 'CRC should be recalculated');
});

// --- PNGC tamper detection --------------------------------------------------

echo "\n── Tamper detection (PNG)\n";

test('PNG verification fails after tampering', function () use ($png) {
    $data = createTestPng();
    $originalHash = hash('sha256', $data);

    $info   = $png->getUnsignedInfo($data);
    $signed = $png->signUnsigned($data, $originalHash, $info);

    // Modify a byte after IHDR (in the coCs chunk itself would corrupt CRC,
    // but computeOriginalHash removes the entire chunk, so tamper elsewhere)
    $tampered       = $signed;
    $tampered[20]   = chr(ord($tampered[20]) ^ 0xFF); // flip a byte in IHDR data

    $found        = $png->find($tampered);
    assertNotNull($found);

    $computedHash = $png->computeOriginalHash($tampered, $found);
    assertFalse(hash_equals($found['hash'], $computedHash));
});

test('PNG verification fails when coCs chunk data is corrupted', function () use ($png) {
    $data = createTestPng();
    $originalHash = hash('sha256', $data);

    $info   = $png->getUnsignedInfo($data);
    $signed = $png->signUnsigned($data, $originalHash, $info);

    // Corrupt a byte inside the hash data (after type), but don't update CRC
    $tampered          = $signed;
    $tampered[50]      = chr(ord($tampered[50]) ^ 0xFF); // flip byte in hash at offset 50
    // Note: CRC is now invalid, but find() just reads chunk type, not CRC

    $found = $png->find($tampered);
    assertNotNull($found);

    $computedHash = $png->computeOriginalHash($tampered, $found);
    // Since we removed the chunk, hash should match original
    assertEquals($originalHash, $computedHash,
        'Tampered chunk is removed, so original hash should match');

    // But the stored hash should NOT match if we compare (stored hash was corrupted)
    assertFalse(hash_equals($found['hash'], $originalHash),
        'Corrupted stored hash should not match');
});

// --- PNG re-signing --------------------------------------------------------

echo "\n── Re-signing (PNG)\n";

test('PNG re-signing produces matching hash', function () use ($png) {
    $data = createTestPng();
    $hash1 = hash('sha256', $data);

    $info   = $png->getUnsignedInfo($data);
    $signed = $png->signUnsigned($data, $hash1, $info);

    $info1 = $png->find($signed);
    $computed1 = $png->computeOriginalHash($signed, $info1);
    assertTrue(hash_equals($info1['hash'], $computed1));

    // Re-sign
    $hash2    = $png->computeOriginalHash($signed, $info1);
    $resigned = $png->updateSignature($signed, $hash2, $info1);

    $info2 = $png->find($resigned);
    assertNotNull($info2);

    $computed2 = $png->computeOriginalHash($resigned, $info2);
    assertTrue(hash_equals($info2['hash'], $computed2));
});

// ===========================================================================
// 4. ChainOfCustody — integration tests (require database)
// ===========================================================================

echo "\n══════════════════════════════════════════════════════════════════\n";
echo "  ChainOfCustody — Integration Tests\n";
echo "══════════════════════════════════════════════════════════════════\n\n";

// Check DB connectivity
$dbAvailable = false;
try {
    $testPdo = new PDO(
        'mysql:host=127.0.0.1;port=3306;dbname=chain_of_custody_test;charset=utf8mb4',
        'coc_test',
        'coc_test_pass',
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_TIMEOUT => 2]
    );
    $testPdo->query('SELECT 1');
    $dbAvailable = true;
    echo "  Database connection OK\n\n";
} catch (PDOException $e) {
    echo "  Database unavailable — skipping integration tests.\n";
    echo "  (" . $e->getMessage() . ")\n\n";
}

if (! $dbAvailable) {
    skip('createSignature', 'No DB');
    skip('createSignedFile', 'No DB');
    skip('checkSignature (pass)', 'No DB');
    skip('checkSignature (tampered)', 'No DB');
    skip('checkChainOfCustody', 'No DB');
    skip('updateChainOfCustody', 'No DB');
    skip('handler detection', 'No DB');
} else {
    // Clean test table
    $testPdo->exec('DELETE FROM chain_of_custody_signatures');
    $testPdo->exec('DELETE FROM users');

    // Create test users
    $hash   = password_hash('test', PASSWORD_DEFAULT);
    $stmt   = $testPdo->prepare(
        'INSERT INTO users (email, password_hash, name, email_verified) VALUES (:email, :pass, :name, 1)'
    );
    $stmt->execute([':email' => 'alice@test.local', ':pass' => $hash, ':name' => 'Alice']);
    $aliceId = (int) $testPdo->lastInsertId();
    $stmt->execute([':email' => 'bob@test.local', ':pass' => $hash, ':name' => 'Bob']);
    $bobId = (int) $testPdo->lastInsertId();

    // Create a fresh ChainOfCustody instance
    $coc = new ChainOfCustody(__DIR__ . '/config.php');

    // Clean up any previous test.tif
    cleanup();

    // ---- createSignature (first-time) ---------------------------------------

    echo "── createSignature (first-time)\n";

    test('createSignature returns a valid SHA-256 hash', function () use ($coc, $aliceId) {
        $path = copyTif();
        try {
            $hash = $coc->createSignature($path, $aliceId);
            $h = new TiffSignatureHandler();
            assertTrue($h->isValidHash($hash), 'Should return a valid SHA-256 hex string');
        } finally {
            if (is_file($path)) {
                unlink($path);
            }
        }
    });

    test('createSignature produces a file with a CoC signature tag', function () use ($coc, $aliceId) {
        $path = copyTif();
        try {
            $coc->createSignature($path, $aliceId);
            $data = file_get_contents($path);
            $tiff = new TiffSignatureHandler();
            $info = $tiff->find($data);
            assertNotNull($info, 'Signed file should contain tag 65000');
        } finally {
            if (is_file($path)) {
                unlink($path);
            }
        }
    });

    test('createSignature stores the record in the database', function () use ($testPdo, $coc, $aliceId) {
        $path = copyTif();
        try {
            // Unique hash via one modified byte
            $data = file_get_contents($path);
            $data[100] = chr(ord($data[100]) ^ 0x01);
            file_put_contents($path, $data);

            $hash = $coc->createSignature($path, $aliceId);

            $stmt   = $testPdo->prepare('SELECT id FROM chain_of_custody_signatures WHERE signature_hash = :hash');
            $stmt->execute([':hash' => $hash]);
            $record = $stmt->fetch();
            assertNotNull($record, 'Should have a DB record for this hash');
        } finally {
            if (is_file($path)) {
                unlink($path);
            }
        }
    });

    // ---- createSignedFile ---------------------------------------------------

    echo "\n── createSignedFile\n";

    test('createSignedFile returns binary data (not a hash string)', function () use ($coc, $aliceId) {
        $path = copyTif();
        try {
            $signed = $coc->createSignedFile($path, $aliceId);
            assertIsString($signed, 'Should return a string');
            assertTrue(strlen($signed) > 100, 'Should contain substantial binary data');
            assertTrue(strlen($signed) > strlen(file_get_contents($path)),
                'Signed data should be larger than original');
        } finally {
            if (is_file($path)) {
                unlink($path);
            }
        }
    });

    test('createSignedFile does NOT modify the original file', function () use ($coc, $aliceId) {
        $path = copyTif();
        try {
            $original    = file_get_contents($path);
            $originalHash = hash('sha256', $original);

            $coc->createSignedFile($path, $aliceId);

            $after  = file_get_contents($path);
            $afterHash = hash('sha256', $after);
            assertEquals($originalHash, $afterHash, 'File should be unchanged by createSignedFile');
        } finally {
            if (is_file($path)) {
                unlink($path);
            }
        }
    });

    test('createSignedFile data passes checkSignature', function () use ($coc, $aliceId) {
        $path = copyTif();
        try {
            $signedData = $coc->createSignedFile($path, $aliceId);

            // Write signed data to a temp file and verify
            $tmp = __DIR__ . '/_verify_me.tif';
            file_put_contents($tmp, $signedData);

            try {
                $result = $coc->checkSignature($tmp);
                assertTrue($result['authenticated'], 'createSignedFile output should pass verification');
            } finally {
                if (is_file($tmp)) {
                    unlink($tmp);
                }
            }
        } finally {
            if (is_file($path)) {
                unlink($path);
            }
        }
    });

    test('createSignedFile still stores in the database', function () use ($testPdo, $coc, $aliceId) {
        $path = copyTif();
        try {
            $data = file_get_contents($path);
            $data[200] = chr(ord($data[200]) ^ 0x01);
            file_put_contents($path, $data);

            $hash  = hash('sha256', $data); // what the hash SHOULD be
            $coc->createSignedFile($path, $aliceId);

            $stmt   = $testPdo->prepare('SELECT id FROM chain_of_custody_signatures WHERE signature_hash = :hash');
            $stmt->execute([':hash' => $hash]);
            assertNotNull($stmt->fetch(), 'Record should exist in DB after createSignedFile');
        } finally {
            if (is_file($path)) {
                unlink($path);
            }
        }
    });

    // ---- handler detection --------------------------------------------------

    echo "\n── Format detection in ChainOfCustody\n";

    test('ChainOfCustody uses TiffSignatureHandler for .tif files', function () {
        $reflection = new ReflectionClass(ChainOfCustody::class);
        $method     = $reflection->getMethod('detectHandler');
        $method->setAccessible(true);

        $coc    = new ChainOfCustody(__DIR__ . '/config.php');
        $handler = $method->invoke($coc, readTiff());

        assertTrue($handler instanceof TiffSignatureHandler, 'TIFF data should return TiffSignatureHandler');
    });

    test('ChainOfCustody uses JpegSignatureHandler for .jpg data', function () {
        $reflection = new ReflectionClass(ChainOfCustody::class);
        $method     = $reflection->getMethod('detectHandler');
        $method->setAccessible(true);

        $coc     = new ChainOfCustody(__DIR__ . '/config.php');
        $jpegData = createTestJpeg();
        $handler  = $method->invoke($coc, $jpegData);

        assertTrue($handler instanceof JpegSignatureHandler, 'JPEG data should return JpegSignatureHandler');
    });

    test('ChainOfCustody uses PngSignatureHandler for PNG data', function () {
        $reflection = new ReflectionClass(ChainOfCustody::class);
        $method     = $reflection->getMethod('detectHandler');
        $method->setAccessible(true);

        $coc     = new ChainOfCustody(__DIR__ . '/config.php');
        $pngData = createTestPng();
        $handler = $method->invoke($coc, $pngData);

        assertTrue($handler instanceof PngSignatureHandler, 'PNG data should return PngSignatureHandler');
    });

    test('detectHandler throws for unknown format', function () {
        $reflection = new ReflectionClass(ChainOfCustody::class);
        $method     = $reflection->getMethod('detectHandler');
        $method->setAccessible(true);

        $coc = new ChainOfCustody(__DIR__ . '/config.php');

        assertThrows(ChainOfCustodyException::class, function () use ($method, $coc) {
            $method->invoke($coc, "some random data\x00\x01\x02");
        });
    });

    // ---- checkSignature -----------------------------------------------------

    echo "\n── checkSignature\n";

    test('checkSignature returns authenticated=true for a properly signed file', function () use ($coc, $aliceId) {
        $path = copyTif();
        try {
            $coc->createSignature($path, $aliceId);
            $result = $coc->checkSignature($path);
            assertTrue($result['authenticated'], 'Should be authenticated');
            assertNotNull($result['hash'], 'Hash should be present');
            assertNotNull($result['signature'], 'DB record should be present');
        } finally {
            if (is_file($path)) {
                unlink($path);
            }
        }
    });

    test('checkSignature returns authenticated=false for unsigned file', function () use ($coc) {
        $path = copyTif();
        try {
            $result = $coc->checkSignature($path);
            assertFalse($result['authenticated'], 'Should NOT be authenticated');
            assertNull($result['hash_valid']);
            assertNull($result['hash']);
            assertNull($result['signature']);
        } finally {
            if (is_file($path)) {
                unlink($path);
            }
        }
    });

    test('checkSignature returns authenticated=false for tampered file', function () use ($coc, $aliceId) {
        $path = copyTif();
        try {
            $coc->createSignature($path, $aliceId);

            $data = file_get_contents($path);
            $data[5000] = chr(ord($data[5000]) ^ 0xFF);
            file_put_contents($path, $data);

            $result = $coc->checkSignature($path);
            assertFalse($result['authenticated'], 'Tampered file should NOT be authenticated');
            assertFalse($result['hash_valid'], 'hash_valid should be false when content is tampered');
            assertNotNull($result['hash'], 'Hash should still be extractable');
            assertNull($result['signature'], 'DB record should be null when authentication fails');
        } finally {
            if (is_file($path)) {
                unlink($path);
            }
        }
    });

    test('checkSignature returns authenticated=false when DB record is missing', function () use ($testPdo, $coc, $aliceId) {
        $path = copyTif();
        try {
            $coc->createSignature($path, $aliceId);

            // Extract the stored hash from the signed file, then delete the DB record
            $check = $coc->checkSignature($path);
            $storedHash = $check['hash'];
            assertNotNull($storedHash, 'Hash should be extractable from signed file');

            $stmt = $testPdo->prepare('DELETE FROM chain_of_custody_signatures WHERE signature_hash = :hash');
            $stmt->execute([':hash' => $storedHash]);

            $result = $coc->checkSignature($path);
            assertFalse($result['authenticated'], 'Should NOT be authenticated without DB record');
            assertTrue($result['hash_valid'], 'hash_valid should be true — content is untampered');
            assertNotNull($result['hash'], 'Hash should be present');
            assertNull($result['signature'], 'DB record should be null');
        } finally {
            if (is_file($path)) {
                unlink($path);
            }
        }
    });

    // ---- checkChainOfCustody ------------------------------------------------

    echo "\n── checkChainOfCustody\n";

    test('checkChainOfCustody returns single-entry chain for first signature', function () use ($coc, $aliceId) {
        $path = copyTif();
        try {
            $coc->createSignature($path, $aliceId);
            $result = $coc->checkChainOfCustody($path);
            assertTrue($result['authenticated']);
            assertEquals(1, count($result['chain']));
            assertEquals('Alice', $result['chain'][0]['author_name']);
        } finally {
            if (is_file($path)) {
                unlink($path);
            }
        }
    });

    // ---- re-signing ---------------------------------------------------------

    echo "\n── createSignature (re-sign)\n";

    test('re-signing creates a second DB record with proper chain linkage', function () use ($coc, $aliceId, $bobId) {
        $path = copyTif();
        try {
            $firstHash  = $coc->createSignature($path, $aliceId);
            $secondHash = $coc->createSignature($path, $bobId);

            assertEquals($firstHash, $secondHash, 'Hash should be same for unchanged file');

            $result = $coc->checkChainOfCustody($path);
            assertTrue($result['authenticated']);
            assertEquals(2, count($result['chain']));
            assertEquals('Bob', $result['chain'][0]['author_name']);
            assertEquals('Alice', $result['chain'][1]['author_name']);
            assertNotNull($result['chain'][0]['previous_id']);
        } finally {
            if (is_file($path)) {
                unlink($path);
            }
        }
    });

    test('re-signed file still verifies', function () use ($coc, $aliceId, $bobId) {
        $path = copyTif();
        try {
            $coc->createSignature($path, $aliceId);
            $coc->createSignature($path, $bobId);
            $result = $coc->checkSignature($path);
            assertTrue($result['authenticated']);
        } finally {
            if (is_file($path)) {
                unlink($path);
            }
        }
    });

    test('checkChainOfCustody returns 2-entry chain after re-sign', function () use ($coc, $aliceId, $bobId) {
        $path = copyTif();
        try {
            $coc->createSignature($path, $aliceId);
            $coc->createSignature($path, $bobId);
            $result = $coc->checkChainOfCustody($path);
            assertTrue($result['authenticated']);
            assertEquals(2, count($result['chain']));
            assertEquals('Bob', $result['chain'][0]['author_name']);
            assertEquals('Alice', $result['chain'][1]['author_name']);
            assertNotNull($result['chain'][0]['previous_id']);
        } finally {
            if (is_file($path)) {
                unlink($path);
            }
        }
    });

    // ---- updateChainOfCustody -----------------------------------------------

    echo "\n── updateChainOfCustody\n";

    test('updateChainOfCustody signs modified file when userId matches', function () use ($coc, $aliceId) {
        $origPath = copyTif();
        $modPath  = copyModifiedTif();
        try {
            // First sign the original
            $coc->createSignature($origPath, $aliceId);

            // Now update with the modified file — should succeed
            $result = $coc->updateChainOfCustody($origPath, $modPath, $aliceId);
            assertIsString($result['data'], 'Should return signed binary data');
            assertTrue(strlen($result['data']) > 100, 'Should contain binary data');
            assertEquals($aliceId, $result['original']['user_id']);

            // The signed modified data should pass verification
            $tmp = __DIR__ . '/test_signed.tif';
            file_put_contents($tmp, $result['data']);
            try {
                $check = $coc->checkSignature($tmp);
                assertTrue($check['authenticated'], 'Signed modified file should verify');
            } finally {
                if (is_file($tmp)) {
                    unlink($tmp);
                }
            }
        } finally {
            if (is_file($origPath)) {
                unlink($origPath);
            }
            if (is_file($modPath)) {
                unlink($modPath);
            }
        }
    });

    test('updateChainOfCustody throws when userId does not match', function () use ($coc, $aliceId, $bobId) {
        $origPath = copyTif();
        $modPath  = copyModifiedTif();
        try {
            // Sign the original as Alice
            $coc->createSignature($origPath, $aliceId);

            // Try to update as Bob — should throw
            assertThrows(ChainOfCustodyException::class, function () use ($coc, $origPath, $modPath, $bobId) {
                $coc->updateChainOfCustody($origPath, $modPath, $bobId);
            });
        } finally {
            if (is_file($origPath)) {
                unlink($origPath);
            }
            if (is_file($modPath)) {
                unlink($modPath);
            }
        }
    });

    test('updateChainOfCustody links new signature to original in database', function () use ($coc, $aliceId) {
        $origPath = copyTif();
        $modPath  = copyModifiedTif();
        try {
            $coc->createSignature($origPath, $aliceId);
            $result = $coc->updateChainOfCustody($origPath, $modPath, $aliceId);

            // Write signed modified to a temp file and check the chain
            $tmp = __DIR__ . '/test_signed.tif';
            file_put_contents($tmp, $result['data']);
            try {
                $chain = $coc->checkChainOfCustody($tmp);
                assertTrue($chain['authenticated']);
                assertEquals(2, count($chain['chain']), 'Chain should have original + modified');
                assertEquals($result['original']['id'], $chain['chain'][1]['id'], 'Original should be second in chain');
            } finally {
                if (is_file($tmp)) {
                    unlink($tmp);
                }
            }
        } finally {
            if (is_file($origPath)) {
                unlink($origPath);
            }
            if (is_file($modPath)) {
                unlink($modPath);
            }
        }
    });

    test('updateChainOfCustody throws when original file is not signed', function () use ($aliceId) {
        $coc = new ChainOfCustody(__DIR__ . '/config.php');
        $modPath = copyModifiedTif();
        try {
            assertThrows(ChainOfCustodyException::class, function () use ($coc, $modPath, $aliceId) {
                // origPath is a non-existent file — never signed
                $coc->updateChainOfCustody('/tmp/nonexistent_orig.tif', $modPath, $aliceId);
            });
        } finally {
            if (is_file($modPath)) {
                unlink($modPath);
            }
        }
    });

    // ---- Edge cases ---------------------------------------------------------

    echo "\n── Edge cases\n";

    test('checkSignature on non-existent file throws exception', function () use ($coc) {
        assertThrows(ChainOfCustodyException::class, function () use ($coc) {
            $coc->checkSignature('/tmp/nonexistent_file_xyz.tif');
        });
    });

    test('createSignedFile on non-existent file throws exception', function () use ($coc, $aliceId) {
        assertThrows(ChainOfCustodyException::class, function () use ($coc, $aliceId) {
            $coc->createSignedFile('/tmp/nonexistent_file_xyz.tif', $aliceId);
        });
    });
}

// Clean up database after integration tests
if (isset($testPdo)) {
    $testPdo->exec('DELETE FROM chain_of_custody_signatures');
}

// ===========================================================================
// Summary
// ===========================================================================

echo "\n══════════════════════════════════════════════════════════════════\n";
$total = $GLOBALS['passed'] + $GLOBALS['failed'] + $GLOBALS['skipped'];
echo "  Results: {$GLOBALS['passed']} passed, {$GLOBALS['failed']} failed, {$GLOBALS['skipped']} skipped (of {$total})\n";
echo "══════════════════════════════════════════════════════════════════\n\n";

// Cleanup temporary files
cleanup();

exit($GLOBALS['failed'] > 0 ? 1 : 0);
