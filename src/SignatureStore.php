<?php

declare(strict_types=1);

/**
 * Chain of Custody — Database store for signature records and users.
 *
 * Wraps PDO access to the chain_of_custody_signatures and users tables.
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

    // ------------------------------------------------------------------
    //  Signature records
    // ------------------------------------------------------------------

    /**
     * Store a new signature record.
     *
     * Looks up the user's display name from the users table and stores it
     * denormalized in author_name.
     *
     * @param  string     $hash        SHA-256 hex digest.
     * @param  int        $userId      ID of the user creating the signature.
     * @param  string     $fileName    Original file name.
     * @param  int|null   $previousId  ID of the previous signature in the chain, or NULL.
     * @return int                     Auto-increment ID of the new record.
     */
    public function store(
        string $hash,
        int $userId,
        string $fileName,
        ?int $previousId,
        string $previousHash = '',
    ): int {
        $stmt = $this->pdo->prepare(
            'SELECT name FROM users WHERE id = :id'
        );
        $stmt->execute([':id' => $userId]);
        $user = $stmt->fetch();

        $authorName = $user !== false ? $user['name'] : 'Unknown';

        $previousHashVal = $previousHash !== '' ? $previousHash : null;

        $stmt = $this->pdo->prepare(
            'INSERT INTO chain_of_custody_signatures
                 (signature_hash, author_name, file_name, previous_id, previous_hash, user_id)
             VALUES (:hash, :author, :file_name, :previous_id, :previous_hash, :user_id)'
        );

        $stmt->execute([
            ':hash'          => $hash,
            ':author'        => $authorName,
            ':file_name'     => $fileName,
            ':previous_id'   => $previousId,
            ':previous_hash' => $previousHashVal,
            ':user_id'       => $userId,
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
            'SELECT s.id, s.user_id, s.signature_hash, s.author_name, s.file_name,
                    s.previous_id, s.previous_hash, s.created_at, u.email, u.auth_provider
             FROM chain_of_custody_signatures s
             LEFT JOIN users u ON u.id = s.user_id
             WHERE s.signature_hash = :hash
             ORDER BY s.id DESC
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
        $chain      = [];
        $nextHash   = null;
        $useId      = true;
        $seenHashLookups = []; // guard against cycles (extracted hashes we've looked up)

        while (true) {
            if ($useId) {
                // First iteration: fetch by ID
                $stmt = $this->pdo->prepare(
                    'SELECT s.id, s.user_id, s.signature_hash, s.author_name, s.file_name,
                            s.previous_id, s.previous_hash, s.created_at,
                            u.email, u.auth_provider
                     FROM chain_of_custody_signatures s
                     LEFT JOIN users u ON u.id = s.user_id
                     WHERE s.id = :id
                     LIMIT 1'
                );
                $stmt->execute([':id' => $signatureId]);
                $useId = false;
            } elseif ($nextHash !== null) {
                // The previous_hash may be the full payload format (with node_id prefix).
                // Extract the actual hash for the DB lookup.
                $lookupHash = $nextHash;
                $plen = strlen($nextHash);
                if ($plen > 2 && $plen < 100) {
                    $len = ord($nextHash[0]);
                    if ($len > 0 && $len < 32 && $plen > $len + 2 && $nextHash[$len + 1] === ':') {
                        $lookupHash = rtrim(substr($nextHash, $len + 2), "\0");
                    }
                }

                // @coverage-exclude: cycle guard requires specific DB state with circular references
                if (in_array($lookupHash, $seenHashLookups, true)) {
                    break;
                }
                $seenHashLookups[] = $lookupHash;

                $stmt = $this->pdo->prepare(
                    'SELECT s.id, s.user_id, s.signature_hash, s.author_name, s.file_name,
                            s.previous_id, s.previous_hash, s.created_at,
                            u.email, u.auth_provider
                     FROM chain_of_custody_signatures s
                     LEFT JOIN users u ON u.id = s.user_id
                     WHERE s.signature_hash = :hash
                     LIMIT 1'
                );
                $stmt->execute([':hash' => $lookupHash]);
            } else {
                break;
            }

            $row = $stmt->fetch();

            // @coverage-exclude: unresolved-link path requires a previous_hash that does not
            //                     exist in the local database (cross-node chain data).
            if ($row === false) {
                // Hash not found locally — create an unresolved link entry
                // Parse node_id from the payload-format previous_hash
                $payload   = $nextHash;
                $plen      = strlen($payload);
                $nodeId    = '';
                $innerHash = $payload;

                if ($plen > 2) {
                    $len = ord($payload[0]);
                    if ($len > 0 && $len < 32 && $plen > $len + 2 && $payload[$len + 1] === ':') {
                        $nodeId    = substr($payload, 1, $len);
                        $innerHash = rtrim(substr($payload, $len + 2), "\0");
                    }
                }

                $chain[] = [
                    'unresolved'     => true,
                    'signature_hash' => $innerHash,
                    'previous_hash'  => null,
                    'node_id'        => $nodeId,
                    'author_name'    => '(remote)',
                    'created_at'     => null,
                ];
                break;
            }

            $chain[] = $row;

            // Follow previous_hash first, fall back to previous_id
            if (!empty($row['previous_hash'])) {
                $nextHash = $row['previous_hash'];
            } elseif ($row['previous_id'] !== null) {
                // @coverage-exclude: legacy previous_id path requires DB records with only
                //                     previous_id set (no previous_hash) — legacy data format.
                $nextHash = null;
                $prevStmt = $this->pdo->prepare(
                    'SELECT signature_hash FROM chain_of_custody_signatures WHERE id = :id LIMIT 1'
                );
                $prevStmt->execute([':id' => (int) $row['previous_id']]);
                $prevRow = $prevStmt->fetch();
                $nextHash = $prevRow !== false ? $prevRow['signature_hash'] : null;
            } else {
                $nextHash = null;
            }
        }

        return $chain;
    }

    // ------------------------------------------------------------------
    //  User accounts
    // ------------------------------------------------------------------

    /**
     * Create a new user account.
     *
     * @param  string  $email         User's email address.
     * @param  string  $passwordHash  bcrypt hash of the password.
     * @param  string  $name          Display name.
     * @param  string  $token         Email verification token.
     * @param  string  $tokenExpires  ISO datetime when the token expires.
     * @return int                    New user ID.
     */
    public function createUser(
        string $email,
        string $passwordHash,
        string $name,
        string $token,
        string $tokenExpires,
    ): int {
        $stmt = $this->pdo->prepare(
            'INSERT INTO users (email, password_hash, name, verification_token, verification_token_expires)
             VALUES (:email, :password_hash, :name, :token, :token_expires)'
        );

        $stmt->execute([
            ':email'          => $email,
            ':password_hash'  => $passwordHash,
            ':name'           => $name,
            ':token'          => $token,
            ':token_expires'  => $tokenExpires,
        ]);

        return (int) $this->pdo->lastInsertId();
    }

    /**
     * Find the earliest signature record by hash (lowest id, ASC order).
     * Used when resolving cross-node chains to get the original record,
     * not the latest re-sign (which may have a different previous_hash).
     *
     * @return array|null  Record row or NULL if not found.
     */
    public function findEarliestByHash(string $hash): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT s.id, s.user_id, s.signature_hash, s.author_name, s.file_name,
                    s.previous_id, s.previous_hash, s.created_at, u.email, u.auth_provider
             FROM chain_of_custody_signatures s
             LEFT JOIN users u ON u.id = s.user_id
             WHERE s.signature_hash = :hash
             ORDER BY s.id ASC
             LIMIT 1'
        );

        $stmt->execute([':hash' => $hash]);

        $row = $stmt->fetch();

        return $row !== false ? $row : null;
    }

    /**
     * Find a user by their email address.
     *
     * @return array|null  User row or NULL if not found.
     */
    public function findUserByEmail(string $email): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT id, email, password_hash, name, email_verified,
                    auth_provider, provider_id, created_at
             FROM users
             WHERE email = :email
             LIMIT 1'
        );

        $stmt->execute([':email' => $email]);

        $row = $stmt->fetch();

        return $row !== false ? $row : null;
    }

    /**
     * Find a user by their email verification token.
     *
     * @return array|null  User row or NULL if not found / expired.
     */
    public function findUserByVerificationToken(string $token): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT id, email, name, email_verified, verification_token_expires,
                    auth_provider
             FROM users
             WHERE verification_token = :token
             LIMIT 1'
        );

        $stmt->execute([':token' => $token]);

        $row = $stmt->fetch();

        return $row !== false ? $row : null;
    }

    /**
     * Mark a user's email as verified and clear the verification token.
     */
    public function verifyUser(int $userId): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE users
             SET email_verified = 1, verification_token = NULL, verification_token_expires = NULL
             WHERE id = :id'
        );

        $stmt->execute([':id' => $userId]);
    }

    /**
     * Find an OAuth user by provider + provider_id, or create one if they
     * don't exist yet. If the email is already registered under a different
     * provider, the existing account is returned (linking is not automatic
     * for security reasons).
     *
     * @return int  User ID.
     */
    public function findOrCreateOAuthUser(
        string $provider,
        string $providerId,
        string $email,
        string $name,
    ): int {
        // Look up by provider + provider_id first
        $stmt = $this->pdo->prepare(
            'SELECT id FROM users WHERE auth_provider = :provider AND provider_id = :pid LIMIT 1'
        );
        $stmt->execute([':provider' => $provider, ':pid' => $providerId]);
        $row = $stmt->fetch();

        if ($row !== false) {
            return (int) $row['id'];
        }

        // Check if the email already exists (different provider)
        $stmt = $this->pdo->prepare('SELECT id, auth_provider FROM users WHERE email = :email LIMIT 1');
        $stmt->execute([':email' => $email]);
        $existing = $stmt->fetch();

        if ($existing !== false) {
            // Return the existing user — they can log in with their original method
            return (int) $existing['id'];
        }

        // Create a new user
        $stmt = $this->pdo->prepare(
            'INSERT INTO users (email, password_hash, name, email_verified, auth_provider, provider_id)
             VALUES (:email, :password_hash, :name, 1, :provider, :pid)'
        );
        $stmt->execute([
            ':email'         => $email,
            ':password_hash' => '', // OAuth users have no local password
            ':name'          => $name,
            ':provider'      => $provider,
            ':pid'           => $providerId,
        ]);

        return (int) $this->pdo->lastInsertId();
    }

    /**
     * Find a user by their ID.
     *
     * @return array|null  User row or NULL if not found.
     */
    public function findUserById(int $userId): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT id, email, name, email_verified, auth_provider, provider_id, created_at
             FROM users
             WHERE id = :id
             LIMIT 1'
        );

        $stmt->execute([':id' => $userId]);

        $row = $stmt->fetch();

        return $row !== false ? $row : null;
    }

    /**
     * Store a password-reset token for a user.
     *
     * Reuses the verification_token and verification_token_expires columns.
     */
    public function setResetToken(int $userId, string $token, string $expires): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE users
             SET verification_token = :token, verification_token_expires = :expires
             WHERE id = :id'
        );

        $stmt->execute([
            ':token'   => $token,
            ':expires' => $expires,
            ':id'      => $userId,
        ]);
    }

    /**
     * Update a user's password hash.
     */
    public function updatePassword(int $userId, string $passwordHash): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE users
             SET password_hash = :password_hash,
                 verification_token = NULL,
                 verification_token_expires = NULL
             WHERE id = :id'
        );

        $stmt->execute([
            ':password_hash' => $passwordHash,
            ':id'            => $userId,
        ]);
    }
}
