<?php

declare(strict_types=1);

/**
 * Chain of Custody — DNS-based node resolver.
 *
 * Resolves a node identifier to its verification endpoint URL via DNS.
 * The convention is: <node_id>.photo-verify.org → CNAME or A record
 * pointing to the node's API server.
 *
 * The verification endpoint is always: https://<resolved-host>/verify
 */

class NodeResolver
{
    /** The DNS zone used for node discovery. */
    const DNS_ZONE = 'photo-verify.org';

    /**
     * Resolve a node ID to its verification URL.
     *
     * Looks up <node_id>.<zone> via DNS CNAME or A record.
     * Falls back to a configurable static mapping if DNS fails.
     *
     * @param  string  $nodeId       16-char hex node identifier.
     * @param  string  $scheme       http or https.
     * @return string                Full verification URL.
     *
     * @throws RuntimeException      When the node cannot be resolved.
     */
    public static function resolve(string $nodeId, string $scheme = 'https'): string
    {
        $host = "{$nodeId}." . self::DNS_ZONE;

        // Try CNAME first, then A record
        $records = dns_get_record($host, DNS_CNAME);

        if (!empty($records) && isset($records[0]['target'])) {
            $target = rtrim($records[0]['target'], '.');
            return "{$scheme}://{$target}/verify";
        }

        $records = dns_get_record($host, DNS_A);

        if (!empty($records) && isset($records[0]['ip'])) {
            return "{$scheme}://{$records[0]['ip']}/verify";
        }

        throw new RuntimeException(
            "Cannot resolve node '{$nodeId}': no DNS record found at {$host}."
        );
    }

    /**
     * Check whether a node ID is reachable.
     *
     * @return bool  True if the node resolves and responds to a HEAD request.
     */
    public static function ping(string $nodeId): bool
    {
        try {
            $url = self::resolve($nodeId);

            $ctx = stream_context_create(['http' => ['method' => 'HEAD', 'timeout' => 5]]);
            $headers = @get_headers($url, false, $ctx);

            return $headers !== false && strpos($headers[0] ?? '', '200') !== false;
        } catch (RuntimeException) {
            return false;
        }
    }

    /**
     * Forward a verification request to a remote node.
     *
     * POSTs the file to the remote node's /verify endpoint and returns
     * the parsed JSON response.
     *
     * @param  string  $nodeId   Target node identifier.
     * @param  string  $filePath Path to the signed file on disk.
     * @return array             Decoded JSON response from the remote node.
     *
     * @throws RuntimeException  When the remote node cannot be reached.
     */
    public static function forward(string $nodeId, string $filePath, string $originalName = ''): array
    {
        $url = self::resolve($nodeId);

        if (!is_file($filePath)) {
            throw new RuntimeException("File not found: {$filePath}");
        }

        // Use file_get_contents with ignore_errors to handle non-200 responses
        $boundary = '----FormBoundary' . bin2hex(random_bytes(12));
        $filename = $originalName !== '' ? $originalName : basename($filePath);
        $fileData = file_get_contents($filePath);

        if ($fileData === false) {
            throw new RuntimeException("Cannot read file: {$filePath}");
        }

        $body = "--{$boundary}\r\n"
              . "Content-Disposition: form-data; name=\"file\"; filename=\"{$filename}\"\r\n"
              . "Content-Type: application/octet-stream\r\n\r\n"
              . $fileData . "\r\n"
              . "--{$boundary}--\r\n";

        $context = stream_context_create([
            'http' => [
                'method'       => 'POST',
                'header'       => "Content-Type: multipart/form-data; boundary={$boundary}\r\n"
                                . "Content-Length: " . strlen($body) . "\r\n",
                'content'      => $body,
                'timeout'      => 60,
                'ignore_errors' => true,
            ],
            'ssl' => [
                'verify_peer'      => false,
                'verify_peer_name' => false,
            ],
        ]);

        $response = @file_get_contents($url, false, $context);

        if ($response === false || $response === '') {
            throw new RuntimeException("No response from remote node at {$url}.");
        }

        $data = json_decode($response, true);

        if (!is_array($data)) {
            throw new RuntimeException(
                "Invalid JSON response from remote node at {$url}."
            );
        }

        if (!empty($data['status']) && $data['status'] === 'error') {
            throw new RuntimeException(
                "Remote node error: " . ($data['message'] ?? 'unknown')
            );
        }

        return $data;
    }

    /**
     * Look up a chain segment from a remote node by hash.
     *
     * @param  string  $nodeId  The node to query.
     * @param  string  $hash    The signature_hash to start from.
     * @return array            The remote node's response (record + chain).
     *
     * @throws RuntimeException  When the remote node cannot be reached.
     */
    public static function chainLookup(string $nodeId, string $hash): array
    {
        $url = self::resolve($nodeId);
        // Replace /verify with /chain in the URL
        $chainUrl = preg_replace('/\/verify$/', '/chain', $url);

        if ($chainUrl === $url) {
            $chainUrl = $url . '/chain';
        }

        $context = stream_context_create([
            'http' => [
                'method'       => 'POST',
                'header'       => "Content-Type: application/json\r\n",
                'content'      => json_encode(['hash' => $hash]),
                'timeout'      => 15,
                'ignore_errors' => true,
            ],
            'ssl' => [
                'verify_peer'      => false,
                'verify_peer_name' => false,
            ],
        ]);

        $response = @file_get_contents($chainUrl, false, $context);

        if ($response === false) {
            throw new RuntimeException("Failed to reach remote node at {$chainUrl}.");
        }

        $data = json_decode($response, true);

        if (!is_array($data)) {
            throw new RuntimeException("Invalid response from remote node at {$chainUrl}.");
        }

        return $data;
    }
}
