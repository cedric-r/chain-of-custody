<?php

declare(strict_types=1);

/**
 * Chain of Custody — Main library API.
 *
 * Provides three high-level operations for image file authentication:
 *   - createSignature()      — sign a file on disk
 *   - createSignedFile()     — sign and return signed binary data
 *   - checkSignature()       — verify that the file matches its stored hash
 *                            (both hash and DB record required for authentication)
 *   - checkChainOfCustody()  — verify and return the linked signature chain
 *   - updateChainOfCustody() — verify original, sign modified, link records
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

        $this->store = new SignatureStore($config);
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

        $storedHash   = $existing['hash'];
        $computedHash = $handler->computeOriginalHash($data, $existing);
        $hashValid    = hash_equals($storedHash, $computedHash);

        $dbRecord = $hashValid ? $this->store->findByHash($storedHash) : null;

        return [
            'authenticated' => $hashValid && $dbRecord !== null,
            'hash_valid'    => $hashValid,
            'hash'          => $storedHash,
            'signature'     => $dbRecord,
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
            return [
                'authenticated' => false,
                'chain'         => [],
            ];
        }

        $chain = $this->store->getChain((int) $result['signature']['id']);

        return [
            'authenticated' => true,
            'chain'         => $chain,
        ];
    }

    /**
     * Update the chain of custody by signing a modified file.
     *
     * Verifies that the original signed file is authentic and that the
     * given user is the same user who created the original signature,
     * then signs the modified file and links the new signature to the
     * original record in the database so the chain reads:
     * … → original → modified.
     *
     * The modified file is signed as a first-time signature (any existing
     * signature on the modified file is ignored — pass the unsigned
     * modified file, not a separately-signed copy).
     *
     * @param  string  $originalSignedPath  Path to the authentic, signed original file.
     * @param  string  $modifiedPath        Path to the (unsigned) modified file.
     * @param  int     $userId              ID of the user — must match the original signature's user.
     * @return array{
     *     data: string,
     *     hash: string,
     *     original: array|null,
     * }
     *
     * @throws ChainOfCustodyException  When the original file is not authentic,
     *                                  has no database record, the user does not
     *                                  match the original signer, or on I/O failure.
     */
    public function updateChainOfCustody(
        string $originalSignedPath,
        string $modifiedPath,
        int $userId
    ): array {
        // 1. Verify the original signed file
        $checkResult = $this->checkSignature($originalSignedPath);

        if (! $checkResult['authenticated']) {
            throw new ChainOfCustodyException(
                'Cannot update: the original signed file is not authentic or has no valid signature.'
            );
        }

        $originalRecord = $checkResult['signature'];
        if ($originalRecord === null) {
            throw new ChainOfCustodyException(
                'Cannot update: no database record found for the original signature.'
            );
        }

        // 2. Verify the user matches the original signature's owner
        if ((int) $originalRecord['user_id'] !== $userId) {
            throw new ChainOfCustodyException(
                'Cannot update: the original signature belongs to a different user.'
            );
        }

        // 3. Read and sign the modified file as a first-time signature
        $data   = $this->readFile($modifiedPath);
        $handler = $this->detectHandler($data);

        $newHash      = hash('sha256', $data);
        $unsignedInfo = $handler->getUnsignedInfo($data);
        $signedData   = $handler->signUnsigned($data, $newHash, $unsignedInfo);

        // 4. Store with previous_id linking to the original record
        $this->store->store($newHash, $userId, basename($modifiedPath), (int) $originalRecord['id']);

        return [
            'data'     => $signedData,
            'hash'     => $newHash,
            'original' => $originalRecord,
        ];
    }

    // ------------------------------------------------------------------
    //  Internal helpers
    // ------------------------------------------------------------------

    /**
     * Core signing logic — shared by createSignature and createSignedFile.
     *
     * @return array{data: string, hash: string}
     */
    private function signData(string $data, string $fileName, int $userId): array
    {
        $handler = $this->detectHandler($data);

        $existing   = $handler->find($data);
        $previousId = null;

        if ($existing !== null) {
            // ----- Re-sign ---------------------------------------------------
            $oldHash   = $existing['hash'];
            $cleanHash = $handler->computeOriginalHash($data, $existing);

            if ($cleanHash === $oldHash) {
                $oldRecord = $this->store->findByHash($oldHash);
                if ($oldRecord !== null) {
                    $previousId = (int) $oldRecord['id'];
                }
            }

            $newHash     = $handler->computeOriginalHash($data, $existing);
            $signedData  = $handler->updateSignature($data, $newHash, $existing);
        } else {
            // ----- First-time signature --------------------------------------
            $newHash     = hash('sha256', $data);
            $unsignedInfo = $handler->getUnsignedInfo($data);
            $signedData   = $handler->signUnsigned($data, $newHash, $unsignedInfo);
        }

        $this->store->store($newHash, $userId, $fileName, $previousId);

        return ['data' => $signedData, 'hash' => $newHash];
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

        $data = file_get_contents($path);

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
        $bytes = file_put_contents($path, $data);

        if ($bytes === false) {
            throw new ChainOfCustodyException("Failed to write file: {$path}");
        }
    }
}
