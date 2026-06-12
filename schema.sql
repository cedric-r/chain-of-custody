-- Copyright © 2026 Cedric Raguenaud <cedric@raguenaud.earth>
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program.  If not, see <https://www.gnu.org/licenses/>.

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

CREATE TABLE IF NOT EXISTS chain_of_custody_signatures (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id         BIGINT UNSIGNED NOT NULL     COMMENT 'The user who created this signature',
    signature_hash  CHAR(64)        NOT NULL COMMENT 'SHA-256 hex of the file at signing time (excluding the CoC IFD)',
    author_name     VARCHAR(255)    NOT NULL COMMENT 'Denormalized display name of the user at signing time',
    file_name       VARCHAR(1024)   NOT NULL COMMENT 'Original file name at signing time',
    previous_id     BIGINT UNSIGNED NULL     COMMENT 'ID of the previous signature in the chain, NULL for first signature',
    previous_hash   VARCHAR(128)    NULL     COMMENT 'Full signature payload (with node_id) of the previous link in the chain',
    created_at      TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_signature_hash (signature_hash),
    INDEX idx_user_id (user_id),
    INDEX idx_previous_hash (previous_hash),

    CONSTRAINT fk_previous_signature
        FOREIGN KEY (previous_id) REFERENCES chain_of_custody_signatures(id)
        ON DELETE SET NULL
        ON UPDATE CASCADE,

    CONSTRAINT fk_user_signature
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE RESTRICT
        ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Chain of Custody signatures for file authentication';

-- ---------------------------------------------------------------------------
-- Migration notes for existing installations
-- ---------------------------------------------------------------------------
--
-- If you already have the chain_of_custody_signatures table, run these
-- ALTER statements instead of dropping and re-creating:
--
--   CREATE TABLE IF NOT EXISTS users (
--       id                        BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
--       email                     VARCHAR(255)    NOT NULL,
--       password_hash             VARCHAR(255)    NOT NULL,
--       name                      VARCHAR(255)    NOT NULL,
--       email_verified            TINYINT(1)      NOT NULL DEFAULT 0,
--       verification_token        VARCHAR(64)     DEFAULT NULL,
--       verification_token_expires DATETIME       DEFAULT NULL,
--       created_at                TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
--       UNIQUE INDEX idx_users_email (email)
--   ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
--
--   ALTER TABLE chain_of_custody_signatures
--       ADD COLUMN user_id BIGINT UNSIGNED NOT NULL AFTER id,
--       ADD INDEX idx_user_id (user_id),
--       ADD CONSTRAINT fk_user_signature
--           FOREIGN KEY (user_id) REFERENCES users(id)
--           ON DELETE RESTRICT ON UPDATE CASCADE;
