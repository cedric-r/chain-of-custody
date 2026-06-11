<?php

declare(strict_types=1);

/**
 * Chain of Custody — CR3 (Canon Raw v3) signature handler.
 *
 * CR3 is based on ISO Base Media File Format (ISOBMFF / ISO 14496-12).
 * The file is a sequence of boxes (atoms). Each box has:
 *   [4 bytes: big-endian size] [4 bytes: type] [data…]
 *
 * The signature is stored in a private top-level box with type "CoC\0"
 * appended to the end of the file.
 *
 * Reference: Canon CR3 specification (ISOBMFF with 'crx ' brand).
 */

require_once __DIR__ . '/ImageSignatureHandler.php';

class Cr3SignatureHandler extends ImageSignatureHandler
{
    /** Our custom box type. */
    const COC_BOX_TYPE = "CoC\0";

    /** Box header: 4 (size) + 4 (type) = 8 bytes. */
    const BOX_HEADER_BYTES = 8;

    /**
     * Total overhead of the CoC box:
     *   8 (header) + HASH_STORED_BYTES = 91 bytes.
     */
    const OVERHEAD_BYTES = 91;

    // ------------------------------------------------------------------
    //  ImageSignatureHandler implementation
    // ------------------------------------------------------------------

    public function getFormatName(): string
    {
        return 'CR3';
    }

    /**
     * Detect CR3 by checking for an 'ftyp' box with major brand 'crx '.
     */
    public function detect(string $data): bool
    {
        if (strlen($data) < 16) {
            return false;
        }

        // First box — must be ftyp
        $boxSize = unpack('N', substr($data, 0, 4))[1];
        $boxType = substr($data, 4, 4);

        if ($boxType !== 'ftyp') {
            return false;
        }

        // Must have at least 8 bytes for major brand + minor version
        if ($boxSize < 16) {
            return false;
        }

        // Check major brand
        $majorBrand = substr($data, 8, 4);

        return $majorBrand === 'crx ';
    }

    /**
     * Walk top-level boxes and look for a CoC box.
     *
     * @return array|null  Keys: hash, boxPos, hashDataPos, totalBoxBytes.
     */
    public function find(string $data): ?array
    {
        $boxes = $this->walkBoxes($data);

        foreach ($boxes as $box) {
            if ($box['type'] === self::COC_BOX_TYPE) {
                $hashStart = $box['offset'] + self::BOX_HEADER_BYTES;
                $hash      = rtrim(substr($data, $hashStart, self::HASH_STORED_BYTES), "\0");

                return [
                    'hash'          => $hash,
                    'boxPos'        => $box['offset'],
                    'hashDataPos'   => $hashStart,
                    'totalBoxBytes' => $box['size'],
                ];
            }
        }

        return null;
    }

    /**
     * Return structural info about an unsigned CR3 file.
     *
     * @return array  Keys: fileLength.
     */
    public function getUnsignedInfo(string $data): array
    {
        return [
            'fileLength' => strlen($data),
        ];
    }

    /**
     * Embed a signature by appending a CoC box at the end of the file.
     */
    public function signUnsigned(string $data, string $hash, array $info): string
    {
        $boxData = str_pad($hash, self::HASH_STORED_BYTES, "\0");
        $boxData = substr($boxData, 0, self::HASH_STORED_BYTES);
        $boxSize = self::BOX_HEADER_BYTES + strlen($boxData);

        $signed  = $data;
        $signed .= pack('N', $boxSize);
        $signed .= self::COC_BOX_TYPE;
        $signed .= $boxData;

        return $signed;
    }

    /**
     * Overwrite the hash in an existing CoC box in-place.
     */
    public function updateSignature(string $data, string $hash, array $info): string
    {
        // Replace the hash (and NUL terminator) at hashDataPos
        for ($i = 0; $i < self::HASH_STORED_BYTES; $i++) {
            $pos = $info['hashDataPos'] + $i;
            $data[$pos] = $i < 64 ? $hash[$i] : "\0";
        }

        return $data;
    }

    /**
     * Reconstruct the unsigned file by removing the CoC box, then hash.
     */
    public function computeOriginalHash(string $data, array $info): string
    {
        $before = substr($data, 0, $info['boxPos']);
        $after  = substr($data, $info['boxPos'] + $info['totalBoxBytes']);

        return hash('sha256', $before . $after);
    }

    // ------------------------------------------------------------------
    //  Internal helpers
    // ------------------------------------------------------------------

    /**
     * Walk all top-level boxes in the ISOBMFF file.
     *
     * @return array[]  Each entry: offset, size, type.
     */
    private function walkBoxes(string $data): array
    {
        $boxes  = [];
        $offset = 0;
        $length = strlen($data);

        while ($offset + 8 <= $length) {
            $size = unpack('N', substr($data, $offset, 4))[1];
            $type = substr($data, $offset + 4, 4);

            // @coverage-exclude: box-extends-to-EOF requires a box with size=0
            if ($size === 0) {
                $size = $length - $offset;
            }

            // @coverage-exclude: extended-size boxes require 64-bit size field; not used in CR3
            if ($size === 1) {
                break;
            }

            $boxes[] = [
                'offset' => $offset,
                'size'   => $size,
                'type'   => $type,
            ];

            $offset += $size;

            // @coverage-exclude: safety guard against infinite loop with corrupt files
            if ($size === 0) {
                break;
            }
        }

        return $boxes;
    }
}
