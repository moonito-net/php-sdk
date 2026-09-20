<?php

namespace Moonito\Transport;

/**
 * The normal transport.
 *
 * Timeouts are always set and are clamped in both directions. There is no
 * configuration value that means "wait forever", because that is how version
 * 2.0.1 turned a slow API into a hanging site.
 *
 * Redirects are never followed. The API does not redirect, and following one
 * on a security call is how a server-side request forgery becomes interesting.
 */
final class CurlTransport implements Transport
{
    public static function available(): bool
    {
        return function_exists('curl_init');
    }

    public function post(string $url, array $payload, array $headers, float $connectTimeout, float $timeout): array
    {
        $connectTimeout = max(0.3, min($connectTimeout, 2.0));
        $timeout = max(0.5, min($timeout, 5.0));

        $curl = curl_init();

        curl_setopt_array($curl, [
            CURLOPT_URL => $url,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => json_encode($payload),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_ENCODING => '',
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_CONNECTTIMEOUT_MS => (int) ($connectTimeout * 1000),
            CURLOPT_TIMEOUT_MS => (int) ($timeout * 1000),
            CURLOPT_HTTPHEADER => array_merge(['Content-Type: application/json'], $headers),
        ]);

        $body = curl_exec($curl);
        $status = (int) curl_getinfo($curl, CURLINFO_HTTP_CODE);
        $error = (string) curl_error($curl);
        curl_close($curl);

        return [
            'ok' => $body !== false && $body !== '',
            'status' => $status,
            'body' => $body === false ? '' : (string) $body,
            'error' => $error,
        ];
    }
}
