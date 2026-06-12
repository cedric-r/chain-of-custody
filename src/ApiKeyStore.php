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
 * Chain of Custody — API key store.
 *
 * Manages API key generation, authentication, and lifecycle for
 * remote access to the signing API.
 *
 * Key format: "coc_" + 64 hex characters (32 random bytes).
 * Only the SHA-256 hash of the key is stored in the database.
 */

class ApiKeyStore
{
    private PDO $pdo;

    /**
     * @param  array<string, mixed>  $config  DB connection parameters.
     */
    public function __construct(array $config)
    {
        $host    = $config['host'] ?? '127.0.0.1';
        $port    = $config['port'] ?? 3306;
        $dbname  = $config['dbname'] ?? '';
        $charset = $config['charset'] ?? 'utf8mb4';

        $dsn = sprintf('mysql:host=%s;port=%d;dbname=%s;charset=%s', $host, $port, $dbname, $charset);

        $this->pdo = new PDO($dsn, $config['username'] ?? '', $config['password'] ?? '', [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]);
    }

    /**
     * Generate a new API key for a user.
     *
     * @param  int     $userId  Owner of the key.
     * @param  string  $label   Human-readable label.
     * @return array{id: int, key: string, prefix: string}
     */
    public function generate(int $userId, string $label): array
    {
        $raw    = bin2hex(random_bytes(32));
        $key    = 'coc_' . $raw;
        $prefix = substr($raw, 0, 8);
        $hash   = hash('sha256', $key);

        $stmt = $this->pdo->prepare(
            'INSERT INTO api_keys (user_id, key_prefix, key_hash, label)
             VALUES (:user_id, :prefix, :hash, :label)'
        );
        $stmt->execute([
            ':user_id' => $userId,
            ':prefix'  => $prefix,
            ':hash'    => $hash,
            ':label'   => $label,
        ]);

        return [
            'id'     => (int) $this->pdo->lastInsertId(),
            'key'    => $key,
            'prefix' => $prefix,
        ];
    }

    /**
     * Authenticate an API key.
     *
     * @param  string  $key  The full key (coc_...).
     * @return array          Key record (id, user_id, label, prefix).
     * @throws RuntimeException  When the key is invalid or revoked.
     */
    public function authenticate(string $key): array
    {
        if (!str_starts_with($key, 'coc_')) {
            throw new RuntimeException('Invalid API key format.');
        }

        $hash = hash('sha256', $key);

        $stmt = $this->pdo->prepare(
            'SELECT id, user_id, label, key_prefix AS prefix, revoked_at FROM api_keys
             WHERE key_hash = :hash
             LIMIT 1'
        );
        $stmt->execute([':hash' => $hash]);
        $row = $stmt->fetch();

        if ($row === false) {
            throw new RuntimeException('API key not found.');
        }

        if ($row['revoked_at'] !== null) {
            throw new RuntimeException('API key has been revoked.');
        }

        return $row;
    }

    /**
     * Update the last_used_at timestamp for a key.
     */
    public function touch(int $keyId): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE api_keys SET last_used_at = NOW() WHERE id = :id'
        );
        $stmt->execute([':id' => $keyId]);
    }

    /**
     * List all keys for a user.
     *
     * @return array[]  Each row: id, prefix, label, last_used_at, created_at, revoked_at.
     */
    public function listByUser(int $userId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT id, key_prefix AS prefix, label, last_used_at, created_at, revoked_at
             FROM api_keys
             WHERE user_id = :user_id
             ORDER BY created_at DESC'
        );
        $stmt->execute([':user_id' => $userId]);

        return $stmt->fetchAll();
    }

    /**
     * Revoke a key (mark as revoked).
     *
     * @throws RuntimeException  When the key does not belong to the user.
     */
    public function revoke(int $keyId, int $userId): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE api_keys SET revoked_at = NOW()
             WHERE id = :id AND user_id = :user_id'
        );
        $stmt->execute([':id' => $keyId, ':user_id' => $userId]);

        if ($stmt->rowCount() === 0) {
            throw new RuntimeException('API key not found or does not belong to you.');
        }
    }
}
