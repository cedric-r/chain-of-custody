<?php

declare(strict_types=1);

/**
 * Chain of Custody — TIFF signature handler.
 *
 * Reads/writes private TIFF tag 65000 using the appended-IFD approach:
 * the signature IFD is appended at the end of the file so existing
 * offsets in the original IFD chain do not need adjustment.
 */

require_once __DIR__ . '/ImageSignatureHandler.php';

class TiffSignatureHandler extends ImageSignatureHandler
{
    /** Private TIFF tag reserved for Chain of Custody. */
    const TAG_COC_SIGNATURE = 65000;

    /** TIFF data type: ASCII string. */
    const TYPE_ASCII = 2;

    // ------------------------------------------------------------------
    //  ImageSignatureHandler implementation
    // ------------------------------------------------------------------

    public function getFormatName(): string
    {
        return 'TIFF';
    }

    /**
     * Probe the first 8 bytes for a valid TIFF header.
     */
    public function detect(string $data): bool
    {
        if (strlen($data) < 8) {
            return false;
        }

        $order = substr($data, 0, 2);

        if ($order !== 'II' && $order !== 'MM') {
            return false;
        }

        try {
            $magic = $order === 'II'
                ? unpack('v', substr($data, 2, 2))[1]
                : unpack('n', substr($data, 2, 2))[1];

            return $magic === 42;
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Walk the IFD chain and find an existing Chain of Custody signature tag.
     *
     * Returns structured position info when found, or NULL when no tag 65000
     * exists in any IFD.
     *
     * @return array|null  Keys: prevNextOffsetPos, sigIfdPos, hash, hashDataPos, byteOrder.
     */
    public function find(string $data): ?array
    {
        $byteOrder = $this->detectByteOrder($data);

        $ifdOffset = $this->unpack32($data, 4, $byteOrder);

        $result = [
            'prevNextOffsetPos' => 4,   // position of the IFD pointer in the TIFF header
            'sigIfdPos'         => null,
            'hash'              => null,
            'hashDataPos'       => null,
            'byteOrder'         => $byteOrder,
        ];

        $fileLen = strlen($data);

        while ($ifdOffset !== 0) {
            if ($ifdOffset + 2 > $fileLen) {
                break;
            }

            $entryCount = $this->unpack16($data, $ifdOffset, $byteOrder);

            for ($i = 0; $i < $entryCount; $i++) {
                $entryOff = $ifdOffset + 2 + ($i * 12);

                if ($entryOff + 12 > $fileLen) {
                    break;
                }

                $tag = $this->unpack16($data, $entryOff, $byteOrder);

                if ($tag === self::TAG_COC_SIGNATURE) {
                    $type  = $this->unpack16($data, $entryOff + 2, $byteOrder);
                    $count = $this->unpack32($data, $entryOff + 4, $byteOrder);
                    $vo    = $this->unpack32($data, $entryOff + 8, $byteOrder);

                    $size  = $count * $this->tiffTypeSize($type);

                    if ($size <= 4) {
                        $result['hash']        = rtrim(substr($data, $entryOff + 8, $size), "\0");
                        $result['hashDataPos'] = $entryOff + 8;
                    } else {
                        $readLen = min($count, self::HASH_STORED_BYTES);
                        $result['hash']        = rtrim(substr($data, $vo, $readLen), "\0");
                        $result['hashDataPos'] = $vo;
                    }

                    $result['sigIfdPos'] = $ifdOffset;
                }
            }

            $nextOffPos  = $ifdOffset + 2 + ($entryCount * 12);
            $nextIfdOff  = $this->unpack32($data, $nextOffPos, $byteOrder);

            if ($nextIfdOff !== 0) {
                $result['prevNextOffsetPos'] = $nextOffPos;
                $ifdOffset = $nextIfdOff;
            } else {
                break;
            }
        }

        return $result['hash'] !== null ? $result : null;
    }

    /**
     * Walk to the end of the IFD chain and return info needed to append a new IFD.
     *
     * @return array  Keys: nextOffsetPos, byteOrder.
     */
    public function getUnsignedInfo(string $data): array
    {
        $byteOrder = $this->detectByteOrder($data);
        $ifdOffset = $this->unpack32($data, 4, $byteOrder);
        $fileLen   = strlen($data);

        $nextOffsetPos = 4;

        while ($ifdOffset !== 0) {
            if ($ifdOffset + 2 > $fileLen) {
                break;
            }

            $entryCount  = $this->unpack16($data, $ifdOffset, $byteOrder);
            $nextOffPos  = $ifdOffset + 2 + ($entryCount * 12);

            if ($nextOffPos + 4 > $fileLen) {
                break;
            }

            $nextIfdOff    = $this->unpack32($data, $nextOffPos, $byteOrder);
            $nextOffsetPos = $nextOffPos;
            $ifdOffset     = $nextIfdOff;
        }

        return [
            'nextOffsetPos' => $nextOffsetPos,
            'byteOrder'     => $byteOrder,
        ];
    }

    /**
     * Append a new Chain of Custody IFD at the end of the file.
     */
    public function signUnsigned(string $data, string $hash, array $info): string
    {
        $byteOrder         = $info['byteOrder'];
        $lastNextOffsetPos = $info['nextOffsetPos'];

        $hashData = $this->padHash($hash);

        $fileSize   = strlen($data);
        $newIfdPos  = $fileSize;
        $dataOffset = $newIfdPos + 18; // IFD header: 2 (count) + 12 (entry) + 4 (next IFD)

        $ifd  = $this->pack16(1, $byteOrder);
        $ifd .= $this->pack16(self::TAG_COC_SIGNATURE, $byteOrder);
        $ifd .= $this->pack16(self::TYPE_ASCII, $byteOrder);
        $ifd .= $this->pack32(self::HASH_STORED_BYTES, $byteOrder);
        $ifd .= $this->pack32($dataOffset, $byteOrder);
        $ifd .= $this->pack32(0, $byteOrder);

        $result = substr_replace($data, $this->pack32($newIfdPos, $byteOrder), $lastNextOffsetPos, 4);
        $result .= $ifd . $hashData;

        return $result;
    }

    /**
     * Overwrite hash bytes in an existing signature tag.
     */
    public function updateSignature(string $data, string $hash, array $info): string
    {
        $hashData = $this->padHash($hash);

        return substr_replace($data, $hashData, $info['hashDataPos'], self::HASH_STORED_BYTES);
    }

    /**
     * Reconstruct the original file (without CoC IFD) and return its hash.
     */
    public function computeOriginalHash(string $data, array $info): string
    {
        $pos = $info['prevNextOffsetPos'];
        $end = $info['sigIfdPos'];

        $clean = substr($data, 0, $pos)
               . "\x00\x00\x00\x00"
               . substr($data, $pos + 4, $end - ($pos + 4));

        return hash('sha256', $clean);
    }

    // ------------------------------------------------------------------
    //  TIFF binary helpers
    // ------------------------------------------------------------------

    /**
     * Detect byte-order marker from a TIFF header.
     *
     * @throws InvalidImageException
     */
    private function detectByteOrder(string $data): string
    {
        if (strlen($data) < 8) {
            throw new InvalidImageException('File is too small to be a valid TIFF.');
        }

        $order = substr($data, 0, 2);

        if ($order !== 'II' && $order !== 'MM') {
            throw new InvalidImageException(
                sprintf('Not a valid TIFF file: unknown byte order marker 0x%04x.', unpack('v', $order)[1])
            );
        }

        $magic = $order === 'II'
            ? unpack('v', substr($data, 2, 2))[1]
            : unpack('n', substr($data, 2, 2))[1];

        if ($magic !== 42) {
            throw new InvalidImageException(
                sprintf('Not a valid TIFF file: expected magic number 42, got %d.', $magic)
            );
        }

        return $order;
    }

    private function pack16(int $value, string $byteOrder): string
    {
        return pack($byteOrder === 'II' ? 'v' : 'n', $value & 0xFFFF);
    }

    private function pack32(int $value, string $byteOrder): string
    {
        return pack($byteOrder === 'II' ? 'V' : 'N', $value & 0xFFFFFFFF);
    }

    private function unpack16(string $data, int $offset, string $byteOrder): int
    {
        $fmt = $byteOrder === 'II' ? 'v' : 'n';
        return unpack($fmt, substr($data, $offset, 2))[1];
    }

    private function unpack32(string $data, int $offset, string $byteOrder): int
    {
        $fmt = $byteOrder === 'II' ? 'V' : 'N';
        return unpack($fmt, substr($data, $offset, 4))[1];
    }

    private function tiffTypeSize(int $type): int
    {
        return match ($type) {
            1       => 1,
            2       => 1,
            3       => 2,
            4       => 4,
            5       => 8,
            6       => 1,
            7       => 1,
            8       => 2,
            9       => 4,
            10      => 8,
            11      => 4,
            12      => 8,
            default => 1,
        };
    }

    private function padHash(string $hash): string
    {
        $hashData = str_pad($hash, self::HASH_STORED_BYTES, "\0");
        return substr($hashData, 0, self::HASH_STORED_BYTES);
    }
}
