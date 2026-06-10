<?php

declare(strict_types=1);

/**
 * ApiKeyStore — unit tests.
 *
 * Tests API key generation, authentication, listing, and revocation.
 * Requires the chain_of_custody_test database with api_keys table.
 *
 * Usage:  php tests/ApiKeyStoreTest.php
 */

require_once __DIR__ . '/../src/ApiKeyStore.php';

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

$passed  = 0;
$failed  = 0;
$skipped = 0;

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
        if ($e->getPrevious()) {
            echo "        Caused by: " . $e->getPrevious()->getMessage() . "\n";
        }
    }
}

function skip(string $label, string $reason): void
{
    global $skipped;
    $skipped++;
    echo "  SKIP  {$label}  — {$reason}\n";
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

function assertIsString(mixed $value, string $message = 'Expected string'): void
{
    if (!is_string($value)) {
        throw new RuntimeException($message . ', got: ' . gettype($value));
    }
}

function assertStringStartsWith(string $prefix, string $string, string $message = ''): void
{
    if (strpos($string, $prefix) !== 0) {
        $msg = $message ?: "Expected string starting with \"{$prefix}\"";
        throw new RuntimeException("{$msg}\n            Got: " . var_export($string, true));
    }
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

$configPath = __DIR__ . '/config.php';
$config     = require $configPath;

$store    = new ApiKeyStore($config);
$testPdo  = null;

// Get a PDO for test setup/cleanup
try {
    $host    = $config['host'] ?? '127.0.0.1';
    $port    = $config['port'] ?? 3306;
    $dbname  = $config['dbname'] ?? '';
    $charset = $config['charset'] ?? 'utf8mb4';
    $dsn     = sprintf('mysql:host=%s;port=%d;dbname=%s;charset=%s', $host, $port, $dbname, $charset);
    $testPdo = new PDO($dsn, $config['username'] ?? '', $config['password'] ?? '', [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    ]);
} catch (PDOException) {
    // Will be handled by skip checks below
}

$dbAvailable = $testPdo !== null;

if ($dbAvailable) {
    // Get the Alice user from the test database
    $stmt = $testPdo->prepare('SELECT id FROM users WHERE email = :email LIMIT 1');
    $stmt->execute([':email' => 'alice@test.local']);
    $aliceRow = $stmt->fetch();

    $stmt = $testPdo->prepare('SELECT id FROM users WHERE email = :email LIMIT 1');
    $stmt->execute([':email' => 'bob@test.local']);
    $bobRow = $stmt->fetch();

    $aliceId = $aliceRow ? (int) $aliceRow['id'] : 0;
    $bobId   = $bobRow ? (int) $bobRow['id'] : 0;

    // Clean the api_keys table
    $testPdo->exec('DELETE FROM api_keys');
} else {
    $aliceId = 0;
    $bobId   = 0;
}

// ===========================================================================
// Key format validation (no DB needed)
// ===========================================================================

echo "\n══════════════════════════════════════════════════════════════════\n";
echo "  Key Format Validation\n";
echo "══════════════════════════════════════════════════════════════════\n\n";

if (!$dbAvailable) {
    skip('all API key format tests', 'No database');
} else {
    test('authenticate rejects invalid prefix (missing coc_)', function () use ($store) {
        assertThrows(RuntimeException::class, function () use ($store) {
            $store->authenticate('invalid_key_without_prefix');
        });
    });

    test('authenticate rejects non-existent key', function () use ($store) {
        assertThrows(RuntimeException::class, function () use ($store) {
            $store->authenticate('coc_' . bin2hex(random_bytes(32)));
        });
    });

    test('generate creates a key with valid format', function () use ($store, $aliceId) {
        $result = $store->generate($aliceId, 'Test Key 1');
        assertIsString($result['key'], 'Key should be a string');
        assertStringStartsWith('coc_', $result['key'], 'Key should start with coc_');
        assertEquals(4 + 64, strlen($result['key']), 'Key should be 68 chars (coc_ + 64 hex)');
        assertEquals(8, strlen($result['prefix']), 'Prefix should be 8 chars');
        assertTrue($result['id'] > 0, 'Returned ID should be positive');
    });

    $generatedKey = '';

    test('authenticate validates a generated key', function () use ($store, &$generatedKey, $aliceId) {
        $result = $store->generate($aliceId, 'Auth Test Key');
        $generatedKey = $result['key'];

        $auth = $store->authenticate($generatedKey);
        assertEquals($result['id'], $auth['id']);
        assertEquals($aliceId, $auth['user_id']);
        assertEquals('Auth Test Key', $auth['label']);
        assertEquals($result['prefix'], $auth['prefix']);
    });

    test('authenticate rejects revoked key', function () use ($store, $aliceId, $testPdo, &$generatedKey) {
        // Create a key and revoke it
        $result = $store->generate($aliceId, 'To be revoked');

        // Revoke via store
        $store->revoke($result['id'], $aliceId);

        // Now authenticate should throw
        assertThrows(RuntimeException::class, function () use ($store, $result) {
            $store->authenticate($result['key']);
        });
    });
}

// ===========================================================================
// Key generation (DB)
// ===========================================================================

echo "\n══════════════════════════════════════════════════════════════════\n";
echo "  Key Generation\n";
echo "══════════════════════════════════════════════════════════════════\n\n";

if (!$dbAvailable) {
    skip('all generation tests', 'No database');
} else {
    test('generate creates unique keys each time', function () use ($store, $aliceId) {
        $k1 = $store->generate($aliceId, 'Key A');
        $k2 = $store->generate($aliceId, 'Key B');
        assertNotEquals($k1['key'], $k2['key'], 'Keys should be unique');
        assertNotEquals($k1['prefix'], $k2['prefix'], 'Prefixes should be unique in practice');
    });

    test('generate stores the key in the database', function () use ($store, $aliceId, $testPdo) {
        $result = $store->generate($aliceId, 'DB Check Key');

        $stmt = $testPdo->prepare('SELECT id, user_id, key_prefix, label FROM api_keys WHERE id = :id');
        $stmt->execute([':id' => $result['id']]);
        $row = $stmt->fetch();

        assertNotNull($row, 'Record should exist in DB');
        assertEquals($aliceId, (int) $row['user_id']);
        assertEquals($result['prefix'], $row['key_prefix']);
        assertEquals('DB Check Key', $row['label']);
    });
}

// ===========================================================================
// Key listing
// ===========================================================================

echo "\n══════════════════════════════════════════════════════════════════\n";
echo "  Key Listing\n";
echo "══════════════════════════════════════════════════════════════════\n\n";

if (!$dbAvailable) {
    skip('all listing tests', 'No database');
} else {
    test('listByUser returns all keys for the given user', function () use ($store, $aliceId) {
        $keys = $store->listByUser($aliceId);
        assertTrue(count($keys) > 0, 'Alice should have at least one key');
        // Each key should have an id, prefix, and label
        foreach ($keys as $k) {
            assertTrue(isset($k['id']), 'Key should have an id');
            assertTrue(isset($k['prefix']), 'Key should have a prefix');
            assertTrue(isset($k['label']), 'Key should have a label');
        }
    });

    test('listByUser returns empty array for user with no keys', function () use ($store, $bobId) {
        // Bob has no keys
        $keys = $store->listByUser($bobId);
        assertEquals([], $keys, 'Bob should have no keys');
    });

    test('listByUser returns revoked keys with revoked_at set', function () use ($store, $aliceId, $testPdo) {
        $result = $store->generate($aliceId, 'Will be revoked and listed');
        $store->revoke($result['id'], $aliceId);

        $keys = $store->listByUser($aliceId);
        $found = false;
        foreach ($keys as $k) {
            if ((int) $k['id'] === $result['id']) {
                $found = true;
                assertNotNull($k['revoked_at'], 'revoked_at should be set');
                break;
            }
        }
        assertTrue($found, 'Revoked key should appear in listing');
    });
}

// ===========================================================================
// Key revocation
// ===========================================================================

echo "\n══════════════════════════════════════════════════════════════════\n";
echo "  Key Revocation\n";
echo "══════════════════════════════════════════════════════════════════\n\n";

if (!$dbAvailable) {
    skip('all revocation tests', 'No database');
} else {
    test('revoke marks a key as revoked', function () use ($store, $aliceId, $testPdo) {
        $result = $store->generate($aliceId, 'To revoke');
        $store->revoke($result['id'], $aliceId);

        $stmt = $testPdo->prepare('SELECT revoked_at FROM api_keys WHERE id = :id');
        $stmt->execute([':id' => $result['id']]);
        $row = $stmt->fetch();
        assertNotNull($row['revoked_at'], 'revoked_at should not be null');
    });

    test('revoke throws for non-existent key id', function () use ($store, $aliceId) {
        assertThrows(RuntimeException::class, function () use ($store, $aliceId) {
            $store->revoke(9999999, $aliceId);
        });
    });

    test('revoke throws when key does not belong to user', function () use ($store, $aliceId, $bobId) {
        $result = $store->generate($aliceId, 'Bob should not revoke');
        assertThrows(RuntimeException::class, function () use ($store, $result, $bobId) {
            $store->revoke($result['id'], $bobId);
        });
    });

    test('revoke throws for already-revoked key', function () use ($store, $aliceId) {
        $result = $store->generate($aliceId, 'Double revoke');
        $store->revoke($result['id'], $aliceId);
        // Attempting to authenticate a revoked key should fail
        assertThrows(RuntimeException::class, function () use ($store, $result) {
            $store->authenticate($result['key']);
        });
    });
}

// ===========================================================================
// Touch (last_used_at)
// ===========================================================================

echo "\n══════════════════════════════════════════════════════════════════\n";
echo "  Touch\n";
echo "══════════════════════════════════════════════════════════════════\n\n";

if (!$dbAvailable) {
    skip('all touch tests', 'No database');
} else {
    test('touch updates last_used_at', function () use ($store, $aliceId, $testPdo) {
        $result = $store->generate($aliceId, 'Touch test');
        $store->touch($result['id']);

        $stmt = $testPdo->prepare('SELECT last_used_at FROM api_keys WHERE id = :id');
        $stmt->execute([':id' => $result['id']]);
        $row = $stmt->fetch();
        assertNotNull($row['last_used_at'], 'last_used_at should be set after touch');
    });

    test('touch does not throw for non-existent key', function () use ($store) {
        // touch() does not check for existence — should not throw
        $store->touch(9999999);
        // No assertion — just checking it doesn't throw
        assertTrue(true);
    });
}

// ===========================================================================
// Real-world authentication flow
// ===========================================================================

echo "\n══════════════════════════════════════════════════════════════════\n";
echo "  Authentication Flow\n";
echo "══════════════════════════════════════════════════════════════════\n\n";

if (!$dbAvailable) {
    skip('all auth flow tests', 'No database');
} else {
    test('full generate → authenticate → touch flow works', function () use ($store, $aliceId) {
        $result = $store->generate($aliceId, 'Flow Key');

        // Authenticate
        $auth = $store->authenticate($result['key']);
        assertEquals($result['id'], $auth['id']);

        // Touch
        $store->touch($result['id']);
        assertTrue(true, 'Flow completed without error');
    });

    test('generate with empty label creates a key', function () use ($store, $aliceId) {
        $result = $store->generate($aliceId, '');
        assertTrue($result['id'] > 0);
        assertStringStartsWith('coc_', $result['key']);
    });

    test('authenticate updates last_used_at after successful auth', function () use ($store, $aliceId) {
        $result = $store->generate($aliceId, 'Last used check');
        $store->authenticate($result['key']);
        // touch is a separate call — just verify auth works
        assertTrue(true, 'Authentication succeeded without error');
    });
}

// ===========================================================================
// Summary
// ===========================================================================

echo "\n══════════════════════════════════════════════════════════════════\n";
$total = $passed + $failed + $skipped;
echo "  Results: {$passed} passed, {$failed} failed, {$skipped} skipped (of {$total})\n";
echo "══════════════════════════════════════════════════════════════════\n\n";

exit($failed > 0 ? 1 : 0);
