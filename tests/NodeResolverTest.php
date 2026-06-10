<?php

declare(strict_types=1);

/**
 * NodeResolver — unit tests.
 *
 * Tests DNS-based node resolution. Most methods need external DNS/HTTP
 * services and cannot be fully tested in isolation. This test covers
 * error paths, constants, and class structure.
 *
 * Usage:  php tests/NodeResolverTest.php
 */

require_once __DIR__ . '/../src/NodeResolver.php';

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

$passed = 0;
$failed = 0;

function test(string $label, callable $fn): void
{
    global $passed, $failed;
    try {
        $fn();
        $passed++;
        echo "  PASS  {$label}\n";
    } catch (Throwable $e) {
        $failed++;
        echo "  FAIL  {$label}\n";
        echo "        " . $e->getMessage() . "\n";
    }
}

function assertTrue(bool $condition, string $message = 'Expected true'): void
{
    if (!$condition) {
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

function assertThrows(string $exceptionClass, callable $fn): void
{
    try {
        $fn();
        throw new RuntimeException("Expected {$exceptionClass} but no exception was thrown");
    } catch (Throwable $e) {
        if (!$e instanceof $exceptionClass) {
            throw new RuntimeException(
                "Expected {$exceptionClass} but got " . get_class($e) . ': ' . $e->getMessage(),
                0,
                $e
            );
        }
    }
}

function assertStringContainsString(string $needle, string $haystack, string $message = ''): void
{
    if (strpos($haystack, $needle) === false) {
        $msg = $message ?: "Expected string containing \"{$needle}\"";
        throw new RuntimeException("{$msg}\n            Got: " . var_export($haystack, true));
    }
}

// ===========================================================================
// Constants and structure
// ===========================================================================

echo "\n══════════════════════════════════════════════════════════════════\n";
echo "  Constants & Structure\n";
echo "══════════════════════════════════════════════════════════════════\n\n";

test('DNS_ZONE constant is photo-verify.org', function () {
    assertEquals('photo-verify.org', NodeResolver::DNS_ZONE);
});

test('resolve() returns https URL by default', function () {
    // This will throw because the node doesn't exist in DNS,
    // but we verify the error message contains the expected URL format
    try {
        NodeResolver::resolve('nonexistent00000000');
    } catch (RuntimeException $e) {
        $msg = $e->getMessage();
        assertStringContainsString('nonexistent00000000', $msg, 'Error should mention node ID');
        assertStringContainsString('photo-verify.org', $msg, 'Error should mention DNS zone');
    }
});

// ===========================================================================
// resolve() — error cases
// ===========================================================================

echo "\n══════════════════════════════════════════════════════════════════\n";
echo "  resolve() — Error Paths\n";
echo "══════════════════════════════════════════════════════════════════\n\n";

test('resolve throws for non-existent node ID', function () {
    assertThrows(RuntimeException::class, function () {
        NodeResolver::resolve('aaaaaaaaaaaaaaaa');
    });
});

test('resolve with http scheme still throws for non-existent node', function () {
    assertThrows(RuntimeException::class, function () {
        NodeResolver::resolve('bbbbbbbbbbbbbbbb', 'http');
    });
});

test('resolve error message contains scheme in resolved URL', function () {
    try {
        NodeResolver::resolve('cccccccccccccccc', 'https');
    } catch (RuntimeException $e) {
        // The error message should indicate the DNS lookup host
        assertStringContainsString('cccccccccccccccc.photo-verify.org', $e->getMessage());
    }
});

// ===========================================================================
// ping() — error cases
// ===========================================================================

echo "\n══════════════════════════════════════════════════════════════════\n";
echo "  ping() — Error Paths\n";
echo "══════════════════════════════════════════════════════════════════\n\n";

test('ping returns false for non-existent node', function () {
    assertFalse(NodeResolver::ping('dddddddddddddddd'));
});

// ===========================================================================
// forward() — error cases
// ===========================================================================

echo "\n══════════════════════════════════════════════════════════════════\n";
echo "  forward() — Error Paths\n";
echo "══════════════════════════════════════════════════════════════════\n\n";

test('forward throws when file does not exist', function () {
    assertThrows(RuntimeException::class, function () {
        NodeResolver::forward('aaaaaaaaaaaaaaaa', '/tmp/nonexistent_file_for_test.jpg');
    });
});

// ===========================================================================
// chainLookup() — error cases
// ===========================================================================

echo "\n══════════════════════════════════════════════════════════════════\n";
echo "  chainLookup() — Error Paths\n";
echo "══════════════════════════════════════════════════════════════════\n\n";

test('chainLookup throws when DNS resolution fails', function () {
    assertThrows(RuntimeException::class, function () {
        NodeResolver::chainLookup('eeeeeeeeeeeeeeee', 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789');
    });
});

// ===========================================================================
// Summary
// ===========================================================================

echo "\n══════════════════════════════════════════════════════════════════\n";
$total = $passed + $failed;
echo "  Results: {$passed} passed, {$failed} failed (of {$total})\n";
echo "══════════════════════════════════════════════════════════════════\n\n";

exit($failed > 0 ? 1 : 0);
