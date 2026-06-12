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

CREATE TABLE IF NOT EXISTS api_keys (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id     BIGINT UNSIGNED NOT NULL COMMENT 'The user who owns this key',
    key_prefix  VARCHAR(8)      NOT NULL COMMENT 'First 8 chars of the key for display',
    key_hash    VARCHAR(255)    NOT NULL COMMENT 'SHA-256 hash of the full API key',
    label       VARCHAR(255)    NOT NULL DEFAULT '' COMMENT 'Human-readable label for the key',
    last_used_at DATETIME       DEFAULT NULL COMMENT 'Last time this key was used',
    created_at  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at  DATETIME        DEFAULT NULL COMMENT 'If set, the key is revoked',

    INDEX idx_key_hash (key_hash),
    INDEX idx_user_id (user_id),

    CONSTRAINT fk_apikey_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='API keys for remote access';
