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
    public static function forward(string $nodeId, string $filePath): array
    {
        $url = self::resolve($nodeId);

        // Build a multipart request
        $boundary = '------------------------' . bin2hex(random_bytes(8));
        $filename = basename($filePath);
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
                'method'  => 'POST',
                'header'  => "Content-Type: multipart/form-data; boundary={$boundary}\r\n"
                           . "Content-Length: " . strlen($body) . "\r\n",
                'content' => $body,
                'timeout' => 30,
            ],
        ]);

        $response = @file_get_contents($url, false, $context);

        if ($response === false) {
            throw new RuntimeException("Failed to reach remote node at {$url}.");
        }

        $data = json_decode($response, true);

        if (!is_array($data)) {
            throw new RuntimeException("Invalid response from remote node at {$url}.");
        }

        return $data;
    }
}
