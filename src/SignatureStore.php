<?php

declare(strict_types=1);

/**
 * Chain of Custody — Database store for signature records.
 *
 * Wraps PDO access to the chain_of_custody_signatures table.
 */

class SignatureStore
{
    private PDO $pdo;

    /**
     * @param  array<string, mixed>  $config  DB connection parameters.
     * @phpstan-param array{host: string, port: int, dbname: string, username: string, password: string, charset?: string} $config
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
     * Store a new signature record.
     *
     * @param  string     $hash        SHA-256 hex digest.
     * @param  string     $author      Name of the author.
     * @param  string     $fileName    Original file name.
     * @param  int|null   $previousId  ID of the previous signature in the chain, or NULL.
     * @return int                     Auto-increment ID of the new record.
     */
    public function store(string $hash, string $author, string $fileName, ?int $previousId): int
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO chain_of_custody_signatures (signature_hash, author_name, file_name, previous_id)
             VALUES (:hash, :author, :file_name, :previous_id)'
        );

        $stmt->execute([
            ':hash'        => $hash,
            ':author'      => $author,
            ':file_name'   => $fileName,
            ':previous_id' => $previousId,
        ]);

        return (int) $this->pdo->lastInsertId();
    }

    /**
     * Look up a signature record by its hash.
     *
     * @param  string       $hash  SHA-256 hex digest.
     * @return array|null          Record row or NULL if not found.
     */
    public function findByHash(string $hash): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT id, signature_hash, author_name, file_name, previous_id, created_at
             FROM chain_of_custody_signatures
             WHERE signature_hash = :hash
             ORDER BY id DESC
             LIMIT 1'
        );

        $stmt->execute([':hash' => $hash]);

        $row = $stmt->fetch();

        return $row !== false ? $row : null;
    }

    /**
     * Follow the chain of custody backwards from a signature ID.
     *
     * Returns an ordered array of records from newest to oldest.
     *
     * @param  int    $signatureId  Starting signature ID.
     * @return array                Ordered chain records.
     */
    public function getChain(int $signatureId): array
    {
        $chain  = [];
        $nextId = $signatureId;

        while ($nextId !== null) {
            $stmt = $this->pdo->prepare(
                'SELECT id, signature_hash, author_name, file_name, previous_id, created_at
                 FROM chain_of_custody_signatures
                 WHERE id = :id
                 LIMIT 1'
            );

            $stmt->execute([':id' => $nextId]);
            $row = $stmt->fetch();

            if ($row === false) {
                break;
            }

            $chain[] = $row;
            $nextId  = $row['previous_id'] !== null ? (int) $row['previous_id'] : null;
        }

        return $chain;
    }
}
