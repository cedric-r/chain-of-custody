<?php

declare(strict_types=1);

/**
 * OAuthProvider — unit tests.
 *
 * Tests config validation, URL generation, and error handling
 * for OAuth authentication with Google and GitHub.
 *
 * Usage:  php tests/OAuthProviderTest.php
 */

require_once __DIR__ . '/../src/OAuthProvider.php';

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

function assertNotNull(mixed $value, string $message = 'Expected non-null'): void
{
    if ($value === null) {
        throw new RuntimeException($message);
    }
}

function assertStringContainsString(string $needle, string $haystack, string $message = ''): void
{
    if (strpos($haystack, $needle) === false) {
        $msg = $message ?: "Expected string containing \"{$needle}\"";
        throw new RuntimeException("{$msg}\n            Got: " . var_export($haystack, true));
    }
}

// ---------------------------------------------------------------------------
// Test data
// ---------------------------------------------------------------------------

const OAUTH_GOOGLE_CONFIG = [
    'google' => [
        'client_id'     => 'google-client-id-123.apps.googleusercontent.com',
        'client_secret' => 'GOCSPX-secret',
        'redirect_uri'  => 'https://example.org/?action=oauth_callback&provider=google',
    ],
];

const OAUTH_GITHUB_CONFIG = [
    'github' => [
        'client_id'     => 'Iv1.githubclient',
        'client_secret' => 'github_secret_abc123',
        'redirect_uri'  => 'https://example.org/?action=oauth_callback&provider=github',
    ],
];

const OAUTH_BOTH_CONFIG = OAUTH_GOOGLE_CONFIG + OAUTH_GITHUB_CONFIG;

// ===========================================================================
// getProviderConfig()
// ===========================================================================

echo "\n══════════════════════════════════════════════════════════════════\n";
echo "  getProviderConfig\n";
echo "══════════════════════════════════════════════════════════════════\n\n";

test('returns Google config with client_id and client_secret', function () {
    $cfg = OAuthProvider::getProviderConfig('google', OAUTH_GOOGLE_CONFIG);
    assertEquals('google-client-id-123.apps.googleusercontent.com', $cfg['client_id']);
    assertEquals('GOCSPX-secret', $cfg['client_secret']);
    assertEquals(
        'https://example.org/?action=oauth_callback&provider=google',
        $cfg['redirect_uri']
    );
});

test('returns GitHub config with client_id and client_secret', function () {
    $cfg = OAuthProvider::getProviderConfig('github', OAUTH_GITHUB_CONFIG);
    assertEquals('Iv1.githubclient', $cfg['client_id']);
    assertEquals('github_secret_abc123', $cfg['client_secret']);
});

test('throws for unknown provider name', function () {
    assertThrows(RuntimeException::class, function () {
        OAuthProvider::getProviderConfig('twitter', OAUTH_BOTH_CONFIG);
    });
});

test('throws for empty provider string', function () {
    assertThrows(RuntimeException::class, function () {
        OAuthProvider::getProviderConfig('', OAUTH_BOTH_CONFIG);
    });
});

test('throws when client_id is missing', function () {
    $incomplete = ['google' => ['client_secret' => 'secret', 'redirect_uri' => 'https://x.com/cb']];
    assertThrows(RuntimeException::class, function () use ($incomplete) {
        OAuthProvider::getProviderConfig('google', $incomplete);
    });
});

test('throws when client_secret is missing', function () {
    $incomplete = ['google' => ['client_id' => 'id123', 'redirect_uri' => 'https://x.com/cb']];
    assertThrows(RuntimeException::class, function () use ($incomplete) {
        OAuthProvider::getProviderConfig('google', $incomplete);
    });
});

test('throws for empty oauth config section', function () {
    assertThrows(RuntimeException::class, function () {
        OAuthProvider::getProviderConfig('google', []);
    });
});

test('throws when provider config is null', function () {
    assertThrows(RuntimeException::class, function () {
        OAuthProvider::getProviderConfig('google', ['google' => null]);
    });
});

// ===========================================================================
// getAuthorizationUrl()
// ===========================================================================

echo "\n══════════════════════════════════════════════════════════════════\n";
echo "  getAuthorizationUrl\n";
echo "══════════════════════════════════════════════════════════════════\n\n";

test('builds Google authorization URL with correct base', function () {
    $url = OAuthProvider::getAuthorizationUrl('google', OAUTH_GOOGLE_CONFIG, 'csrf_token_abc');
    assertStringContainsString('https://accounts.google.com/o/oauth2/v2/auth', $url, 'Should point to Google');
});

test('builds Google URL with client_id parameter', function () {
    $url = OAuthProvider::getAuthorizationUrl('google', OAUTH_GOOGLE_CONFIG, 'csrf_token_abc');
    assertStringContainsString('client_id=google-client-id-123.apps.googleusercontent.com', $url);
});

test('builds Google URL with redirect_uri parameter', function () {
    $url = OAuthProvider::getAuthorizationUrl('google', OAUTH_GOOGLE_CONFIG, 'csrf_token_abc');
    assertStringContainsString(urlencode('https://example.org/?action=oauth_callback&provider=google'), $url);
});

test('builds Google URL with state parameter (CSRF)', function () {
    $url = OAuthProvider::getAuthorizationUrl('google', OAUTH_GOOGLE_CONFIG, 'csrf_token_abc');
    assertStringContainsString('state=csrf_token_abc', $url);
});

test('builds Google URL with scope=email+profile', function () {
    $url = OAuthProvider::getAuthorizationUrl('google', OAUTH_GOOGLE_CONFIG, 'csrf_token_abc');
    assertStringContainsString('scope=email+profile', $url);
});

test('builds Google URL with access_type=offline', function () {
    $url = OAuthProvider::getAuthorizationUrl('google', OAUTH_GOOGLE_CONFIG, 'csrf_token_abc');
    assertStringContainsString('access_type=offline', $url);
});

test('builds Google URL with prompt=consent', function () {
    $url = OAuthProvider::getAuthorizationUrl('google', OAUTH_GOOGLE_CONFIG, 'csrf_token_abc');
    assertStringContainsString('prompt=consent', $url);
});

test('builds GitHub authorization URL with correct base', function () {
    $url = OAuthProvider::getAuthorizationUrl('github', OAUTH_GITHUB_CONFIG, 'csrf_xyz');
    assertStringContainsString('https://github.com/login/oauth/authorize', $url, 'Should point to GitHub');
});

test('builds GitHub URL with scope=user%3Aemail', function () {
    $url = OAuthProvider::getAuthorizationUrl('github', OAUTH_GITHUB_CONFIG, 'csrf_xyz');
    assertStringContainsString('scope=user%3Aemail', $url);
});

test('getAuthorizationUrl throws for unknown provider', function () {
    assertThrows(RuntimeException::class, function () {
        OAuthProvider::getAuthorizationUrl('twitter', OAUTH_BOTH_CONFIG, 'state');
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
