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
 * Chain of Custody — Main library API.
 *
 * Provides high-level operations for image file authentication:
 *   - createSignature()       — sign a file on disk
 *   - createSignedFile()      — sign and return signed binary data
 *   - checkSignature()        — verify that the file matches its stored hash
 *                             (both hash and DB record required for authentication)
 *   - checkChainOfCustody()   — verify and return the linked signature chain
 *   - lookupSignature()       — look up an unsigned file by content hash
 *   - updateChainOfCustody()  — verify original, sign modified, link records
 *
 * Automatically detects the image format (TIFF, JPEG, …) and delegates
 * to the appropriate format handler.
 *
 * Usage:
 *   $coc = new ChainOfCustody('/path/to/config.php');
 *   $hash   = $coc->createSignature('/path/to/image.tif', 1);     // userId 1
 *   $signed = $coc->createSignedFile('/path/to/image.jpg', 1);    // userId 1
 *   $result = $coc->checkSignature('/path/to/image.tif');
 *   $chain  = $coc->checkChainOfCustody('/path/to/image.tif');
 *   $update = $coc->updateChainOfCustody('/path/to/original.tif', '/path/to/modified.jpg', 1);
 */

require_once __DIR__ . '/ImageSignatureHandler.php';
require_once __DIR__ . '/SignatureStore.php';
require_once __DIR__ . '/TiffSignatureHandler.php';
require_once __DIR__ . '/JpegSignatureHandler.php';
require_once __DIR__ . '/PngSignatureHandler.php';
require_once __DIR__ . '/Cr3SignatureHandler.php';

class ChainOfCustody
{
    /** @var ImageSignatureHandler[] */
    private array $handlers;

    private SignatureStore $store;

    /** Secret salt appended to the hash input. */
    private string $hashSalt = '';

    /** This node's unique identifier (16 hex chars, 8 random bytes). */
    private string $nodeId = '';

    /** Length of a node identifier in bytes. */
    const NODE_ID_LEN = 16;

    /**
     * @param  string  $configPath  Path to a PHP file returning a DB-config array.
     * @throws ChainOfCustodyException  When the config file cannot be loaded.
     */
    public function __construct(string $configPath)
    {
        // Order matters: JPEG detection first so TIFF's detect() doesn't
        // accidentally match JPEG files that happen to have 0x49 0x49
        // in the first two bytes (extremely unlikely, but prudent).
        $this->handlers = [
            new PngSignatureHandler(), // most specific signature check first
            new JpegSignatureHandler(),
            new Cr3SignatureHandler(),
            new TiffSignatureHandler(),
        ];

        if (! is_file($configPath) || ! is_readable($configPath)) {
            throw new ChainOfCustodyException(
                "Database configuration file not found or not readable: {$configPath}"
            );
        }

        /** @var array<string, mixed> $config */
        $config = require $configPath;

        if (! is_array($config)) {
            throw new ChainOfCustodyException(
                "Configuration file must return an array."
            );
        }

        $this->hashSalt = (string) ($config['hash_salt'] ?? '');
        $this->nodeId   = (string) ($config['node_id'] ?? '');
        $this->store    = new SignatureStore($config);
    }

    /**
     * Get this node's identifier.
     */
    public function getNodeId(): string
    {
        return $this->nodeId;
    }

    /**
     * Build the signature payload for embedding in a file.
     * Format: [1 byte: node_id_len] [node_id] [':'] [inner_data...]
     */
    private function buildSignaturePayload(string $innerData): string
    {
        if ($this->nodeId === '') {
            return $innerData;
        }
        return pack('C', strlen($this->nodeId)) . $this->nodeId . ':' . $innerData;
    }

    /**
     * Extract the node_id and actual hash from a signature payload.
     * Handles both the new format (with node_id) and legacy format (no node_id).
     *
     * @return array{nodeId: string, hashData: string}
     */
    private function parseSignaturePayload(string $payload): array
    {
        if ($payload === '' || strlen($payload) < 2) {
            return ['nodeId' => '', 'hashData' => $payload];
        }

        $len = ord($payload[0]);

        // Validate: length byte should be reasonable (0-32) and match expected format
        if ($len > 0 && $len < 32 && strlen($payload) > $len + 2 && $payload[$len + 1] === ':') {
            $nodeId   = substr($payload, 1, $len);
            $hashData = substr($payload, $len + 2);
            return ['nodeId' => $nodeId, 'hashData' => $hashData];
        }

        // Legacy format — no node_id prefix
        return ['nodeId' => '', 'hashData' => $payload];
    }

    // ------------------------------------------------------------------
    //  Salt helpers
    // ------------------------------------------------------------------

    /**
     * Compute a salted hash from an inner (file-content) hash.
     *
     * hash = SHA-256(innerHash || salt)
     *
     * The salt prevents pre-computed hash lookups. When the salt is empty
     * the returned hash is identical to the inner hash (backward-compatible).
     */
    private function applyHashSalt(string $innerHash): string
    {
        if ($this->hashSalt === '') {
            return $innerHash;
        }

        return hash('sha256', $innerHash . $this->hashSalt);
    }

    // ------------------------------------------------------------------
    //  Public API
    // ------------------------------------------------------------------

    /**
     * Create a Chain of Custody signature for an image file.
     *
     * The file is modified in-place to embed the signature.
     *
     * @param  string  $filePath  Path to the image file.
     * @param  int     $userId    ID of the user creating the signature.
     * @return string             SHA-256 hex digest that was stored.
     *
     * @throws ChainOfCustodyException  On I/O, format detection, or TIFF parse failure.
     */
    public function createSignature(string $filePath, int $userId): string
    {
        $data   = $this->readFile($filePath);
        $result = $this->signData($data, basename($filePath), $userId);
        $this->writeFile($filePath, $result['data']);

        return $result['hash'];
    }

    /**
     * Create a Chain of Custody signature and return the signed binary data.
     *
     * Unlike createSignature(), this does NOT write to the original file.
     * The signed data is returned as a binary string, and the signature
     * record is still persisted in the database.
     *
     * @param  string  $filePath  Path to the unsigned image file.
     * @param  int     $userId    ID of the user creating the signature.
     * @return string             Signed image file binary data.
     *
     * @throws ChainOfCustodyException  On I/O, format detection, or parse failure.
     */
    public function createSignedFile(string $filePath, int $userId): string
    {
        $data   = $this->readFile($filePath);
        $result = $this->signData($data, basename($filePath), $userId);

        return $result['data'];
    }

    /**
     * Check the authenticity of a signed image file.
     *
     * Extracts the stored hash from the file, reconstructs the original
     * content (without the signature), computes its checksum, and compares.
     *
     * Returns authenticated=true only when BOTH:
     *   1. The embedded hash matches the file content (hash_valid),
     *   2. A matching record exists in the database.
     *
     * @param  string  $filePath  Path to the signed image file.
     * @return array{
     *     authenticated: bool,
     *     hash_valid: bool|null,
     *     hash: string|null,
     *     signature: array|null,
     * }
     */
    public function checkSignature(string $filePath): array
    {
        $data = $this->readFile($filePath);

        $handler = $this->detectHandler($data);
        $existing = $handler->find($data);

        if ($existing === null) {
            return [
                'authenticated' => false,
                'hash_valid'    => null,
                'hash'          => null,
                'signature'     => null,
            ];
        }

        $storedPayload  = $existing['hash'];
        $parsed         = $this->parseSignaturePayload($storedPayload);
        $storedHash     = rtrim($parsed['hashData'], "\0");
        $nodeId         = $parsed['nodeId'];

        $computedInner  = $handler->computeOriginalHash($data, $existing);
        $computedSalted = $this->applyHashSalt($computedInner);
        $hashValid      = hash_equals($storedHash, $computedSalted);

        $dbRecord = $hashValid ? $this->store->findByHash($storedHash) : null;

        // If the file was signed by a different node, mark it as requiring
        // remote verification (the caller can forward to the owning node).
        $isRemote = $nodeId !== '' && $nodeId !== $this->nodeId;

        return [
            'authenticated' => $hashValid && $dbRecord !== null,
            'hash_valid'    => $hashValid,
            'hash'          => $storedHash,
            'signature'     => $dbRecord,
            'node_id'       => $nodeId,
            'requires_remote' => $isRemote,
        ];
    }

    /**
     * Check the signature and return the full chain of custody from the database.
     *
     * The chain is ordered newest-first (current signature → previous → oldest).
     *
     * @param  string  $filePath  Path to the signed image file.
     * @return array{
     *     authenticated: bool,
     *     chain: array,
     * }
     */
    public function checkChainOfCustody(string $filePath): array
    {
        $result = $this->checkSignature($filePath);

        if (! $result['authenticated'] || $result['signature'] === null) {
            // Still try to get node_id for remote files
            return [
                'authenticated' => false,
                'chain'         => [],
                'node_id'       => $result['node_id'] ?? '',
            ];
        }

        $chain = $this->store->getChain((int) $result['signature']['id']);

        // Recursively resolve cross-node chain links
        $startHash = $result['signature']['signature_hash'] ?? '';
        $chain = $this->resolveRemoteChainLinks($chain, $startHash ? [$startHash] : []);

        return [
            'authenticated' => true,
            'chain'         => $chain,
        ];
    }

    /**
     * Look up an unsigned file by its content hash.
     *
     * Computes the salted SHA-256 of the file contents and searches the
     * database for a matching signature record. Useful for finding whether
     * a known unsigned version of a file exists in the chain.
     *
     * @param  string  $filePath  Path to the unsigned file.
     * @return array{
     *     found: bool,
     *     hash: string|null,
     *     record: array|null,
     *     chain: array,
     * }
     */
    public function lookupSignature(string $filePath): array
    {
        $data      = $this->readFile($filePath);
        $innerHash = hash('sha256', $data);
        $hash      = $this->applyHashSalt($innerHash);

        $record = $this->store->findByHash($hash);

        if ($record === null) {
            return [
                'found'  => false,
                'hash'   => $hash,
                'record' => null,
                'chain'  => [],
            ];
        }

        $chain = $this->store->getChain((int) $record['id']);

        return [
            'found'  => true,
            'hash'   => $hash,
            'record' => $record,
            'chain'  => $chain,
        ];
    }

    /**
     * Update the chain of custody by signing a modified file.
     *
     * Verifies that the original signed file is authentic, then signs the
     * modified file and links the new signature to the original record in
     * the database so the chain reads: … → original → modified.
     *
     * The modified file is signed as a first-time signature (any existing
     * signature on the modified file is ignored — pass the unsigned
     * modified file, not a separately-signed copy).
     *
     * @param  string  $originalSignedPath  Path to the authentic, signed original file.
     * @param  string  $modifiedPath        Path to the (unsigned) modified file.
     * @param  int     $userId              ID of the user creating the new signature.
     * @return array{
     *     data: string,
     *     hash: string,
     *     original: array|null,
     * }
     *
     * @throws ChainOfCustodyException  When the original file is not authentic,
     *                                  has no database record, or on I/O failure.
     */
    public function updateChainOfCustody(
        string $originalSignedPath,
        string $modifiedPath,
        int $userId
    ): array {
        // 1. Check the original signed file
        $checkResult = $this->checkSignature($originalSignedPath);

        // Extract the full payload (with node_id) from the original file
        $origData    = $this->readFile($originalSignedPath);
        $origHandler = $this->detectHandler($origData);
        $origExisting = $origHandler->find($origData);
        $origPayload  = $origExisting ? $origExisting['hash'] : '';

        $originalHash    = null;
        $originalRecord  = null;

        // @coverage-exclude: remote-file path requires a file signed by a different node
        if (!empty($checkResult['requires_remote'])) {
            $originalHash  = $checkResult['hash'];
            $origPayload   = $origPayload ?: '';
        } elseif ($checkResult['authenticated']) {
            $originalRecord = $checkResult['signature'];
            // @coverage-exclude: null-record path requires DB state that cannot occur in normal flow
            if ($originalRecord === null) {
                throw new ChainOfCustodyException(
                    'Cannot update: no database record found for the original signature.'
                );
            }
            $originalHash = $originalRecord['signature_hash'];
        } else {
            throw new ChainOfCustodyException(
                'Cannot update: the original signed file is not authentic or has no valid signature.'
            );
        }

        // 2. Read and sign the modified file as a first-time signature
        $data   = $this->readFile($modifiedPath);
        $handler = $this->detectHandler($data);

        $innerHash   = hash('sha256', $data);
        $saltedHash  = $this->applyHashSalt($innerHash);
        $payload     = $this->buildSignaturePayload($saltedHash);
        $unsignedInfo = $handler->getUnsignedInfo($data);
        $signedData  = $handler->signUnsigned($data, $payload, $unsignedInfo);

        // 4. Store with previous_id and previous_hash linking to the original record
        $prevId   = $originalRecord !== null ? (int) $originalRecord['id'] : null;
        // Use the full payload (with node_id) as previous_hash
        $prevHash = $origPayload ?: ($originalHash ?? '');

        $this->store->store($saltedHash, $userId, basename($modifiedPath), $prevId, $prevHash);

        return [
            'data'     => $signedData,
            'hash'     => $saltedHash,
            'original' => $originalRecord,
        ];
    }

    // ------------------------------------------------------------------
    //  Internal helpers
    // ------------------------------------------------------------------

    /**
     * Verify a file signed by a remote node using that node's published salt.
     *
     * This allows offline verification when a remote node publishes its
     * `hash_salt` via `/.well-known/chain-of-custody`. The file's embedded
     * hash is compared against `SHA-256(innerHash || remoteSalt)` instead
     * of this node's own salt.
     *
     * @param  string  $filePath   Path to the signed file.
     * @param  string  $remoteSalt The remote node's hash_salt (empty = no salt).
     * @return array{
     *     hash_valid: bool|null,
     *     hash: string|null,
     *     node_id: string,
     * }
     */
    public function verifyWithRemoteSalt(string $filePath, string $remoteSalt): array
    {
        $data = $this->readFile($filePath);

        $handler  = $this->detectHandler($data);
        $existing = $handler->find($data);

        if ($existing === null) {
            return [
                'hash_valid' => null,
                'hash'       => null,
                'node_id'    => '',
            ];
        }

        $storedPayload = $existing['hash'];
        $parsed        = $this->parseSignaturePayload($storedPayload);
        $storedHash    = rtrim($parsed['hashData'], "\0");
        $nodeId        = $parsed['nodeId'];

        $computedInner = $handler->computeOriginalHash($data, $existing);
        $computed      = $remoteSalt !== ''
            ? hash('sha256', $computedInner . $remoteSalt)
            : $computedInner;
        $hashValid     = hash_equals($storedHash, $computed);

        return [
            'hash_valid' => $hashValid,
            'hash'       => $storedHash,
            'node_id'    => $nodeId,
        ];
    }

    /**
     * Fully resolve a chain from a given hash, including cross-node links.
     *
     * @coverage-exclude: Requires running multi-node setup with HTTP access.
     *
     * Called by the /chain API endpoint to return a completely resolved chain
     * segment. This prevents recursive loops between nodes.
     */
    public function resolveFullChain(string $hash): array
    {
        // Use findEarliestByHash to get the original record, not the latest re-sign
        $record = $this->store->findEarliestByHash($hash);
        if ($record === null) {
            return [];
        }

        $chain = $this->store->getChain((int) $record['id']);
        return $this->resolveRemoteChainLinks($chain, [$hash]);
    }

    /**
     * Recursively resolve cross-node chain links.
     *
     * @coverage-exclude: Requires multi-node HTTP setup with real remote nodes.
     *
     * When the local chain ends with an unresolved entry containing a node_id,
     * forward to that node's /chain endpoint to get the next segment.
     * The $visited parameter tracks already-resolved hashes to prevent loops.
     */
    private function resolveRemoteChainLinks(array $chain, array $visited = []): array
    {
        $lastIdx = count($chain) - 1;
        if ($lastIdx < 0) {
            return $chain;
        }

        $last = $chain[$lastIdx];
        if (empty($last['unresolved']) || empty($last['node_id'])) {
            return $chain;
        }

        $nodeId   = $last['node_id'];
        $hash     = $last['signature_hash'];

        // Guard against infinite loops
        if (in_array($hash, $visited, true)) {
            return $chain;
        }
        $visited[] = $hash;

        // Forward to the remote node's /chain endpoint
        require_once __DIR__ . '/NodeResolver.php';
        try {
            $remoteResult = NodeResolver::chainLookup($nodeId, $hash);
            if (!empty($remoteResult['chain'])) {
                array_pop($chain); // remove the unresolved entry
                foreach ($remoteResult['chain'] as $entry) {
                    $chain[] = $entry;
                }
                // Recurse — the remote chain may itself have unresolved links
                return $this->resolveRemoteChainLinks($chain, $visited);
            }
        } catch (\RuntimeException) {
            // Remote node unreachable — keep the unresolved entry
        }

        return $chain;
    }

    /**
     * Core signing logic — shared by createSignature and createSignedFile.
     *
     * @return array{data: string, hash: string}
     */
    private function signData(string $data, string $fileName, int $userId): array
    {
        $handler = $this->detectHandler($data);

        $existing     = $handler->find($data);
        $previousId   = null;
        $previousHash = '';

        if ($existing !== null) {
            // ----- Re-sign ---------------------------------------------------
            $oldPayload = $existing['hash'];
            $oldHash    = rtrim($this->parseSignaturePayload($oldPayload)['hashData'], "\0");

            // Always capture the previous payload as previous_hash for chain linking
            $previousHash = $oldPayload;

            $cleanHash = $this->applyHashSalt(
                $handler->computeOriginalHash($data, $existing)
            );

            if ($cleanHash === $oldHash) {
                $oldRecord = $this->store->findByHash($oldHash);
                if ($oldRecord !== null) {
                    $previousId = (int) $oldRecord['id'];
                }
            }

            $innerHash  = $handler->computeOriginalHash($data, $existing);
            $saltedHash = $this->applyHashSalt($innerHash);
            $payload    = $this->buildSignaturePayload($saltedHash);
            $signedData = $handler->updateSignature($data, $payload, $existing);
        } else {
            // ----- First-time signature --------------------------------------
            $innerHash   = hash('sha256', $data);
            $saltedHash  = $this->applyHashSalt($innerHash);
            $payload     = $this->buildSignaturePayload($saltedHash);
            $unsignedInfo = $handler->getUnsignedInfo($data);
            $signedData  = $handler->signUnsigned($data, $payload, $unsignedInfo);
        }

        $this->store->store($saltedHash, $userId, $fileName, $previousId, $previousHash);

        return ['data' => $signedData, 'hash' => $saltedHash];
    }

    /**
     * Probe raw bytes against all registered handlers and return the first match.
     *
     * @throws ChainOfCustodyException  When no handler claims the data.
     */
    private function detectHandler(string $data): ImageSignatureHandler
    {
        foreach ($this->handlers as $handler) {
            if ($handler->detect($data)) {
                return $handler;
            }
        }

        throw new ChainOfCustodyException(
            'Unsupported image format — no handler claims this file.'
        );
    }

    /**
     * Read a file into a binary string.
     *
     * @throws ChainOfCustodyException
     */
    private function readFile(string $path): string
    {
        if (! is_file($path) || ! is_readable($path)) {
            throw new ChainOfCustodyException("File not found or not readable: {$path}");
        }

        // @coverage-exclude: requires OS-level I/O failure after exists-check
        $data = file_get_contents($path);

        // @coverage-exclude: requires OS-level I/O failure after exists-check
        if ($data === false) {
            throw new ChainOfCustodyException("Failed to read file: {$path}");
        }

        return $data;
    }

    /**
     * Write a binary string to a file.
     *
     * @throws ChainOfCustodyException
     */
    private function writeFile(string $path, string $data): void
    {
        // @coverage-exclude: requires OS-level I/O failure (disk full, permissions)
        $bytes = file_put_contents($path, $data);

        // @coverage-exclude: requires OS-level I/O failure (disk full, permissions)
        if ($bytes === false) {
            throw new ChainOfCustodyException("Failed to write file: {$path}");
        }
    }
}
