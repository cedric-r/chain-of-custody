<?php

declare(strict_types=1);

/**
 * Chain of Custody — JPEG signature handler (custom APP8 marker).
 *
 * Stores the SHA-256 signature in a dedicated JPEG APP8 marker:
 *
 *   FF E8 [length:2 BE] "CoC\0" [hash: 64 hex chars + NUL]
 *
 * This is independent of EXIF — no TIFF IFD structures are involved.
 * The marker is inserted right after SOI and is spliced out during
 * verification to reconstruct the original file.
 *
 * Reference: ITU-T T.81 | ISO 10918-1 (JPEG specification).
 */

require_once __DIR__ . '/ImageSignatureHandler.php';

class JpegSignatureHandler extends ImageSignatureHandler
{
    /** APP8 marker bytes. */
    const APP8_MARKER = "\xFF\xE8";

    /** 4-byte identifier that distinguishes our APP8 from other APP8 users. */
    const COC_ID = "CoC\0";

    /**
     * Total size of the APP8 segment in the file:
     *   2 (FF E8) + 2 (length) + 4 (CoC\0) + HASH_STORED_BYTES = 91 bytes
     */
    const SEGMENT_BYTES = 91;

    /** Marker type for SOS — after this comes compressed data, not markers. */
    const SOS_MARKER = "\xDA";

    // ------------------------------------------------------------------
    //  ImageSignatureHandler implementation
    // ------------------------------------------------------------------

    public function getFormatName(): string
    {
        return 'JPEG';
    }

    /**
     * Detect JPEG by checking for the SOI marker (0xFF 0xD8).
     */
    public function detect(string $data): bool
    {
        return strlen($data) >= 2
            && $data[0] === "\xFF"
            && $data[1] === "\xD8";
    }

    /**
     * Scan JPEG markers before SOS for an APP8 segment with our identifier.
     *
     * Returns NULL if no CoC signature is found.
     *
     * @return array|null  Keys: hash, markerPos, segmentLen (incl. length field),
     *                     hashDataPos, totalSegmentBytes (bytes to remove).
     */
    public function find(string $data): ?array
    {
        $pos = 2; // skip SOI
        $len = strlen($data);

        while ($pos + 1 < $len) {
            // Find the next 0xFF marker
            if ($data[$pos] !== "\xFF") {
                $pos++;
                continue;
            }

            $marker = $data[$pos + 1];
            $markerVal = ord($marker);

            // Byte-stuffed 0xFF (0xFF 0x00) — skip
            if ($markerVal === 0x00) {
                $pos += 2;
                continue;
            }

            // SOS — no more marker segments
            if ($marker === self::SOS_MARKER) {
                break;
            }

            // EOI — stop
            if ($markerVal === 0xD9) {
                break;
            }

            // Standalone markers (no length field)
            if (($markerVal >= 0xD0 && $markerVal <= 0xD7) || $markerVal === 0x01) {
                $pos += 2;
                continue;
            }

            // Segmented marker — read length
            if ($pos + 3 >= $len) {
                break;
            }

            $segLen = unpack('n', substr($data, $pos + 2, 2))[1];

            if ($segLen < 2) {
                break;
            }

            // Check for our APP8
            if ($markerVal === 0xE8 && $segLen >= 6) {
                $idStart = $pos + 4;
                if (substr($data, $idStart, 4) === self::COC_ID) {
                    $hashStart = $idStart + 4; // after "CoC\0"
                    $hash = rtrim(substr($data, $hashStart, self::HASH_STORED_BYTES), "\0");

                    return [
                        'hash'             => $hash,
                        'markerPos'        => $pos,
                        'segmentLen'       => $segLen,           // length field value
                        'hashDataPos'      => $hashStart,
                        'totalSegmentBytes' => 2 + $segLen,       // marker + segment
                    ];
                }
            }

            $pos += 2 + $segLen;
        }

        return null;
    }

    /**
     * Return insertion point for a new APP8 marker (right after SOI).
     */
    public function getUnsignedInfo(string $data): array
    {
        return ['insertPos' => 2];
    }

    /**
     * Insert a new CoC APP8 marker right after SOI.
     */
    public function signUnsigned(string $data, string $hash, array $info): string
    {
        $segment = $this->buildSegment($hash);
        $insertPos = $info['insertPos'] ?? 2;

        return substr($data, 0, $insertPos) . $segment . substr($data, $insertPos);
    }

    /**
     * Overwrite the hash bytes in an existing APP8 marker.
     */
    public function updateSignature(string $data, string $hash, array $info): string
    {
        $hashData = $this->padHash($hash);

        return substr_replace($data, $hashData, $info['hashDataPos'], self::HASH_STORED_BYTES);
    }

    /**
     * Remove the CoC APP8 marker and hash the remainder.
     */
    public function computeOriginalHash(string $data, array $info): string
    {
        $markerPos = $info['markerPos'];
        $totalLen  = $info['totalSegmentBytes'] ?? self::SEGMENT_BYTES;

        $clean = substr($data, 0, $markerPos) . substr($data, $markerPos + $totalLen);

        return hash('sha256', $clean);
    }

    // ------------------------------------------------------------------
    //  Internal helpers
    // ------------------------------------------------------------------

    /**
     * Build a complete APP8 segment (marker + length + id + hash).
     */
    private function buildSegment(string $hash): string
    {
        $payloadLen = 2 + 4 + self::HASH_STORED_BYTES; // length field + id + hash

        $seg  = self::APP8_MARKER;
        $seg .= pack('n', $payloadLen);
        $seg .= self::COC_ID;
        $seg .= $this->padHash($hash);

        return $seg;
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
