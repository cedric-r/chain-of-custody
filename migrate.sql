-- Chain of Custody — Database Migration (users table + user_id + auth_provider)
--
-- Run this against an existing chain_of_custody database to add the
-- users table and link existing signature records to it.
--
-- Usage:
--   mysql -u root -p chain_of_custody < migrate.sql

-- ---------------------------------------------------------------------------
-- 1. Create the users table
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS users (
    id                        BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    email                     VARCHAR(255)    NOT NULL,
    password_hash             VARCHAR(255)    NOT NULL COMMENT 'bcrypt hash of the user password',
    name                      VARCHAR(255)    NOT NULL COMMENT 'Display name of the user',
    email_verified            TINYINT(1)      NOT NULL DEFAULT 0 COMMENT '1 once the user verifies their email',
    verification_token        VARCHAR(64)     DEFAULT NULL COMMENT 'Random token for email verification',
    verification_token_expires DATETIME       DEFAULT NULL COMMENT 'Expiry time for the verification token',
    auth_provider             VARCHAR(32)     NOT NULL DEFAULT 'local' COMMENT 'Authentication method: local, google, github, ...',
    provider_id               VARCHAR(255)    DEFAULT NULL COMMENT 'Unique ID from the OAuth provider',
    created_at                TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE INDEX idx_users_email (email),
    INDEX idx_provider (auth_provider, provider_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Registered users who can create and verify signatures';

-- ---------------------------------------------------------------------------
-- 2. Add user_id to the signatures table
-- ---------------------------------------------------------------------------

ALTER TABLE chain_of_custody_signatures
    ADD COLUMN user_id BIGINT UNSIGNED NULL AFTER id,
    ADD INDEX idx_user_id (user_id);

-- ---------------------------------------------------------------------------
-- 3. Create a default "legacy" user for existing signatures
-- ---------------------------------------------------------------------------

INSERT INTO users (email, password_hash, name, email_verified)
SELECT 'legacy@migrated.local', '', 'Legacy User', 1
WHERE NOT EXISTS (SELECT 1 FROM users WHERE email = 'legacy@migrated.local');

SET @legacyUserId = (SELECT id FROM users WHERE email = 'legacy@migrated.local');

UPDATE chain_of_custody_signatures
SET user_id = @legacyUserId
WHERE user_id IS NULL;

ALTER TABLE chain_of_custody_signatures
    MODIFY COLUMN user_id BIGINT UNSIGNED NOT NULL;

-- ---------------------------------------------------------------------------
-- 4. Foreign key
-- ---------------------------------------------------------------------------

ALTER TABLE chain_of_custody_signatures
    ADD CONSTRAINT fk_user_signature
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE RESTRICT ON UPDATE CASCADE;

-- ---------------------------------------------------------------------------
-- 5. Add auth_provider and provider_id to existing users table
--    (skipped if the columns were already added in the CREATE TABLE above)
-- ---------------------------------------------------------------------------

SET @hasProvider = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users'
    AND COLUMN_NAME = 'auth_provider');

SET @sql = IF(@hasProvider = 0, 'ALTER TABLE users
    ADD COLUMN auth_provider VARCHAR(32) NOT NULL DEFAULT ''local''
        COMMENT ''Authentication method: local, google, github, ...''
        AFTER verification_token_expires,
    ADD COLUMN provider_id VARCHAR(255) DEFAULT NULL
        COMMENT ''Unique ID from the OAuth provider''
        AFTER auth_provider,
    ADD INDEX idx_provider (auth_provider, provider_id)', 'SELECT ''auth_provider already exists''');

PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
