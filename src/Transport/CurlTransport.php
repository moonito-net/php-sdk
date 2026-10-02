<?php

namespace Moonito\Transport;

/**
 * The normal transport.
 *
 * A total timeout of 0 waits for as long as the API takes, as 2.0.1 did.
 * The connect timeout is always set, since it only covers reaching the server.
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
        // No ceiling on the total. Every cap tried so far (2, then 5, then 30
        // seconds) let through exactly the visitors the API needed longest
        // for, and blocking them is the reason this library is installed.
        $connectTimeout = max(0.3, min($connectTimeout, 30.0));
        $timeout = $timeout <= 0 ? 0.0 : max(0.5, $timeout);

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
