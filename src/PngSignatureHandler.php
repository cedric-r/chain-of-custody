<?php

declare(strict_types=1);

/**
 * Chain of Custody — PNG signature handler.
 *
 * Stores the SHA-256 signature in a private ancillary chunk `coCs`
 * inserted right after IHDR.
 *
 * PNG chunk structure:  [Length:4] [Type:4] [Data:N] [CRC-32:4]
 *
 * coCs chunk:            [65]      ["coCs"]  [hash+NUL] [CRC]
 *
 * Reference: ISO/IEC 15948 (PNG specification).
 */

require_once __DIR__ . '/ImageSignatureHandler.php';

class PngSignatureHandler extends ImageSignatureHandler
{
    /** PNG 8-byte signature. */
    const PNG_SIG = "\x89PNG\r\n\x1a\n";

    /** Our custom chunk type (private ancillary, safe-to-copy). */
    const CHUNK_TYPE = 'coCs';

    /** IHDR chunk type. */
    const IHDR_TYPE = 'IHDR';

    /** IEND chunk type. */
    const IEND_TYPE = 'IEND';

    /**
     * Total size of the coCs chunk:
     *   4 (length) + 4 (type) + HASH_STORED_BYTES + 4 (CRC) = 95 bytes
     */
    const CHUNK_BYTES = 95;

    // ------------------------------------------------------------------
    //  ImageSignatureHandler implementation
    // ------------------------------------------------------------------

    public function getFormatName(): string
    {
        return 'PNG';
    }

    /**
     * Detect PNG by checking the 8-byte signature.
     */
    public function detect(string $data): bool
    {
        return strlen($data) >= 8 && substr($data, 0, 8) === self::PNG_SIG;
    }

    /**
     * Scan PNG chunks for a `coCs` chunk.
     *
     * @return array|null Keys: hash, chunkPos, hashDataPos, totalChunkBytes.
     */
    public function find(string $data): ?array
    {
        $pos = 8; // after PNG signature
        $len = strlen($data);

        while ($pos + 8 <= $len) {
            $chunkLen = unpack('N', substr($data, $pos, 4))[1];
            $type     = substr($data, $pos + 4, 4);

            if ($type === self::CHUNK_TYPE) {
                $hashStart = $pos + 8; // after length + type
                $hash = rtrim(substr($data, $hashStart, self::HASH_STORED_BYTES), "\0");

                return [
                    'hash'            => $hash,
                    'chunkPos'        => $pos,
                    'hashDataPos'     => $hashStart,
                    'totalChunkBytes' => 12 + $chunkLen, // 4+4+N+4
                ];
            }

            // Stop if we reach IEND (coCs must come before IDAT)
            if ($type === self::IEND_TYPE) {
                break;
            }

            $total = 12 + $chunkLen; // 4 (len) + 4 (type) + N (data) + 4 (CRC)
            $pos  += $total;
        }

        return null;
    }

    /**
     * Return the position right after IHDR's CRC, where coCs should be inserted.
     *
     * @return array{insertPos: int}
     */
    public function getUnsignedInfo(string $data): array
    {
        $pos        = 8; // after PNG signature
        $ihdrLen    = unpack('N', substr($data, $pos, 4))[1];
        $insertPos  = $pos + 12 + $ihdrLen; // after IHDR chunk (sig(8) + len(4) + type(4) + data(N) + CRC(4))

        return ['insertPos' => $insertPos];
    }

    /**
     * Insert a `coCs` chunk right after IHDR.
     */
    public function signUnsigned(string $data, string $hash, array $info): string
    {
        $chunk    = $this->buildChunk($hash);
        $insertAt = $info['insertPos'];

        return substr($data, 0, $insertAt) . $chunk . substr($data, $insertAt);
    }

    /**
     * Overwrite the hash data and recalculate the CRC-32 of the coCs chunk.
     */
    public function updateSignature(string $data, string $hash, array $info): string
    {
        $hashData = $this->padHash($hash);

        // Overwrite hash bytes
        $result = substr_replace($data, $hashData, $info['hashDataPos'], self::HASH_STORED_BYTES);

        // Recalculate CRC-32 over type + data
        $newCrc  = crc32(self::CHUNK_TYPE . $hashData) & 0xFFFFFFFF;
        $crcPos  = $info['chunkPos'] + 8 + self::HASH_STORED_BYTES; // after len + type + hash
        $result  = substr_replace($result, pack('N', $newCrc), $crcPos, 4);

        return $result;
    }

    /**
     * Remove the coCs chunk and hash the remainder.
     */
    public function computeOriginalHash(string $data, array $info): string
    {
        $chunkPos = $info['chunkPos'];
        $total    = $info['totalChunkBytes'];

        $clean = substr($data, 0, $chunkPos) . substr($data, $chunkPos + $total);

        return hash('sha256', $clean);
    }

    // ------------------------------------------------------------------
    //  Internal helpers
    // ------------------------------------------------------------------

    /**
     * Build a complete coCs chunk (length + type + hash + CRC).
     */
    private function buildChunk(string $hash): string
    {
        $hashData = $this->padHash($hash);

        $chunk  = pack('N', self::HASH_STORED_BYTES); // data length
        $chunk .= self::CHUNK_TYPE;
        $chunk .= $hashData;
        $chunk .= pack('N', crc32(self::CHUNK_TYPE . $hashData) & 0xFFFFFFFF);

        return $chunk;
    }

    /**
     * Pad/truncate a hash to exactly HASH_STORED_BYTES (hex + NUL).
     */
    private function padHash(string $hash): string
    {
        $hashData = str_pad($hash, self::HASH_STORED_BYTES, "\0");
        return substr($hashData, 0, self::HASH_STORED_BYTES);
    }
}
