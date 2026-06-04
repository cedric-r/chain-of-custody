CREATE TABLE IF NOT EXISTS chain_of_custody_signatures (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    signature_hash  CHAR(64)        NOT NULL COMMENT 'SHA-256 hex of the file at signing time (excluding the CoC IFD)',
    author_name     VARCHAR(255)    NOT NULL COMMENT 'Name of the person who created this signature',
    file_name       VARCHAR(1024)   NOT NULL COMMENT 'Original file name at signing time',
    previous_id     BIGINT UNSIGNED NULL     COMMENT 'ID of the previous signature in the chain, NULL for first signature',
    created_at      TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_signature_hash (signature_hash),
    CONSTRAINT fk_previous_signature
        FOREIGN KEY (previous_id) REFERENCES chain_of_custody_signatures(id)
        ON DELETE SET NULL
        ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Chain of Custody signatures for file authentication';
