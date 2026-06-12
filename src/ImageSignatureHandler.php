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
 * Chain of Custody — Abstract image-signature handler.
 *
 * Each supported image format implements this interface. Handlers are
 * responsible for embedding, locating, updating, and removing the
 * Chain of Custody signature from the file's binary data.
 */

// ---------------------------------------------------------------------------
// Exceptions
// ---------------------------------------------------------------------------

class ChainOfCustodyException extends RuntimeException {}
class InvalidImageException extends ChainOfCustodyException {}
class SignatureNotFoundException extends ChainOfCustodyException {}

// ---------------------------------------------------------------------------
// Abstract base
// ---------------------------------------------------------------------------

abstract class ImageSignatureHandler
{
    /** Length of a SHA-256 hex digest. */
    const HASH_HEX_LEN = 64;

    /** Total bytes stored for the hash (hex + NUL), including optional node_id prefix.
     *  With node_id: 1 + 16 + 1 + 64 + 1 = 83. Without: 64 + 1 = 65. */
    const HASH_STORED_BYTES = 83;

    // ------------------------------------------------------------------
    //  Abstract — each format must implement
    // ------------------------------------------------------------------

    /**
     * Human-readable format name (e.g. "TIFF", "JPEG").
     */
    abstract public function getFormatName(): string;

    /**
     * Probe raw bytes and return TRUE if this handler supports the file.
     */
    abstract public function detect(string $data): bool;

    /**
     * Locate an existing Chain of Custody signature embedded in the data.
     *
     * Returns structured position info when found, or NULL when no signature
     * is present.
     *
     * @return array|null  Keys vary by handler; at minimum 'hash' and 'hashDataPos'.
     */
    abstract public function find(string $data): ?array;

    /**
     * Return metadata about the file needed to sign it for the first time.
     *
     * @return array  Handler-specific info (position, byte-order, etc.).
     */
    abstract public function getUnsignedInfo(string $data): array;

    /**
     * Embed a signature hash into unsigned file data.
     *
     * @param  string  $data  Original (unsigned) file bytes.
     * @param  string  $hash  SHA-256 hex string (64 chars) to embed.
     * @param  array   $info  Return value from getUnsignedInfo().
     * @return string         Signed file data.
     */
    abstract public function signUnsigned(string $data, string $hash, array $info): string;

    /**
     * Overwrite the hash in an existing signature in-place.
     *
     * @param  string  $data  Currently signed file bytes.
     * @param  string  $hash  New SHA-256 hex string.
     * @param  array   $info  Return value from find().
     * @return string         Modified file data.
     */
    abstract public function updateSignature(string $data, string $hash, array $info): string;

    /**
     * Reconstruct the file as it was before the signature was embedded and
     * return its SHA-256 digest.
     *
     * @param  string  $data  Currently signed file bytes.
     * @param  array   $info  Return value from find().
     * @return string         SHA-256 hex digest of the original file.
     */
    abstract public function computeOriginalHash(string $data, array $info): string;

    // ------------------------------------------------------------------
    //  Shared utility
    // ------------------------------------------------------------------

    /**
     * Validate that a string looks like a SHA-256 hex digest.
     */
    public function isValidHash(string $hash): bool
    {
        return strlen($hash) === self::HASH_HEX_LEN
            && preg_match('/^[a-f0-9]{64}$/i', $hash) === 1;
    }
}
