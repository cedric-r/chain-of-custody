<?php

declare(strict_types=1);

/**
 * Chain of Custody — Main library API.
 *
 * Provides three high-level operations for image file authentication:
 *   - createSignature()    — sign a file on disk
 *   - createSignedFile()   — sign and return signed binary data
 *   - checkSignature()     — verify that the file matches its stored hash
 *   - checkChainOfCustody() — verify and return the linked signature chain
 *
 * Automatically detects the image format (TIFF, JPEG, …) and delegates
 * to the appropriate format handler.
 *
 * Usage:
 *   $coc = new ChainOfCustody('/path/to/config.php');
 *   $hash = $coc->createSignature('/path/to/image.tif', 'Alice');
 *   $signed = $coc->createSignedFile('/path/to/image.jpg', 'Bob');
 *   $result = $coc->checkSignature('/path/to/image.tif');
 *   $chain = $coc->checkChainOfCustody('/path/to/image.tif');
 */

require_once __DIR__ . '/ImageSignatureHandler.php';
require_once __DIR__ . '/SignatureStore.php';
require_once __DIR__ . '/TiffSignatureHandler.php';
require_once __DIR__ . '/JpegSignatureHandler.php';
require_once __DIR__ . '/PngSignatureHandler.php';

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
     * @param  string  $filePath    Path to the image file.
     * @param  string  $authorName  Name of the person creating the signature.
     * @return string               SHA-256 hex digest that was stored.
     *
     * @throws ChainOfCustodyException  On I/O, format detection, or TIFF parse failure.
     */
    public function createSignature(string $filePath, string $authorName): string
    {
        $data   = $this->readFile($filePath);
        $result = $this->signData($data, basename($filePath), $authorName);
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
     * @param  string  $filePath    Path to the unsigned image file.
     * @param  string  $authorName  Name of the person creating the signature.
     * @return string               Signed image file binary data.
     *
     * @throws ChainOfCustodyException  On I/O, format detection, or parse failure.
     */
    public function createSignedFile(string $filePath, string $authorName): string
    {
        $data   = $this->readFile($filePath);
        $result = $this->signData($data, basename($filePath), $authorName);

        return $result['data'];
    }

    /**
     * Check the authenticity of a signed image file.
     *
     * Extracts the stored hash from the file, reconstructs the original
     * content (without the signature), computes its checksum, and compares.
     *
     * @param  string  $filePath  Path to the signed image file.
     * @return array{
     *     authenticated: bool,
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
                'hash'          => null,
                'signature'     => null,
            ];
        }

        $storedHash    = $existing['hash'];
        $computedHash  = $handler->computeOriginalHash($data, $existing);
        $authenticated = hash_equals($storedHash, $computedHash);

        $dbRecord = $authenticated ? $this->store->findByHash($storedHash) : null;

        return [
            'authenticated' => $authenticated,
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

    // ------------------------------------------------------------------
    //  Internal helpers
    // ------------------------------------------------------------------

    /**
     * Core signing logic — shared by createSignature and createSignedFile.
     *
     * @return array{data: string, hash: string}
     */
    private function signData(string $data, string $fileName, string $authorName): array
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

        $this->store->store($newHash, $authorName, $fileName, $previousId);

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
