<?php

namespace Moonito\Transport;

/**
 * Fallback for hosts without the cURL extension.
 *
 * Slower and less configurable, but the alternative on such a host is no
 * protection at all. The timeout is enforced through the stream context.
 */
final class StreamTransport implements Transport
{
    public static function available(): bool
    {
        return (bool) ini_get('allow_url_fopen');
    }

    public function post(string $url, array $payload, array $headers, float $connectTimeout, float $timeout): array
    {
        // Matches CurlTransport's ceiling; see the note there for why it moved.
        $timeout = max(0.5, min($timeout, 30.0));

        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => implode("\r\n", array_merge(['Content-Type: application/json'], $headers)),
                'content' => json_encode($payload),
                'timeout' => $timeout,
                'ignore_errors' => true,
                'follow_location' => 0,
            ],
            'ssl' => ['verify_peer' => true, 'verify_peer_name' => true],
        ]);

        $body = @file_get_contents($url, false, $context);
        $status = 0;

        if (isset($http_response_header[0]) && preg_match('#HTTP/\S+\s+(\d{3})#', $http_response_header[0], $m)) {
            $status = (int) $m[1];
        }

        return [
            'ok' => $body !== false && $body !== '',
            'status' => $status,
            'body' => $body === false ? '' : (string) $body,
            'error' => $body === false ? 'stream request failed' : '',
        ];
    }
}
