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
    public function store(string $hash, int $userId, string $fileName, ?int $previousId): int
    {
        $stmt = $this->pdo->prepare(
            'SELECT name FROM users WHERE id = :id'
        );
        $stmt->execute([':id' => $userId]);
        $user = $stmt->fetch();

        $authorName = $user !== false ? $user['name'] : 'Unknown';

        $stmt = $this->pdo->prepare(
            'INSERT INTO chain_of_custody_signatures
                 (signature_hash, author_name, file_name, previous_id, user_id)
             VALUES (:hash, :author, :file_name, :previous_id, :user_id)'
        );

        $stmt->execute([
            ':hash'        => $hash,
            ':author'      => $authorName,
            ':file_name'   => $fileName,
            ':previous_id' => $previousId,
            ':user_id'     => $userId,
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
                    s.previous_id, s.created_at, u.email, u.auth_provider
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
        $chain  = [];
        $nextId = $signatureId;

        while ($nextId !== null) {
            $stmt = $this->pdo->prepare(
                'SELECT s.id, s.user_id, s.signature_hash, s.author_name, s.file_name,
                        s.previous_id, s.created_at, u.email, u.auth_provider
                 FROM chain_of_custody_signatures s
                 LEFT JOIN users u ON u.id = s.user_id
                 WHERE s.id = :id
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
     * Find a user by email address.
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
