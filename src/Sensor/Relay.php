<?php

namespace Moonito\Sensor;

/**
 * The first-party side of the browser sensor (sensor 1.2.0, relay build).
 *
 * The page loads the sensor from its own URL with ?__vt=s, times a few
 * requests to ?__vt=p and posts its beacon to ?__vt=t. All three are answered
 * here, on the customer's server, before any decision is asked for, so the
 * browser never contacts another host: ad blockers have nothing to match and
 * the visitor never sees which service protects the site. The beacon is
 * forwarded to the API server to server, after the browser has its answer.
 */
final class Relay
{
    const MAX_BEACON = 8192;

    /**
     * The query parameter the sensor's requests use on this site. Derived
     * from the public key, so every site has its own: no single URL pattern
     * an ad blocker list could match across customers, and no clash with a
     * parameter the site uses itself. Same rule in every SDK:
     * "_" + the first 7 hex characters of sha256("sensor|" + public key).
     */
    public static function param(string $publicKey): string
    {
        return '_' . substr(hash('sha256', 'sensor|' . $publicKey), 0, 7);
    }

    /** 's' (script), 'p' (ping), 't' (beacon), or null for any other request. */
    public static function kind(array $server, string $publicKey): ?string
    {
        $param = self::param($publicKey);

        $query = isset($server['QUERY_STRING']) ? (string) $server['QUERY_STRING']
            : (string) parse_url(isset($server['REQUEST_URI']) ? (string) $server['REQUEST_URI'] : '', PHP_URL_QUERY);

        if ($query === '' || strpos($query, $param . '=') === false) {
            return null;
        }

        parse_str($query, $params);
        $kind = isset($params[$param]) && is_string($params[$param]) ? $params[$param] : null;
        $method = strtoupper(isset($server['REQUEST_METHOD']) ? (string) $server['REQUEST_METHOD'] : 'GET');

        if ($kind === 's' || $kind === 'p') {
            return $method === 'GET' || $method === 'HEAD' ? $kind : null;
        }

        return $kind === 't' && $method === 'POST' ? 't' : null;
    }

    /**
     * The path of the page being served, which is known to reach this SDK.
     * Written into the tag so the sensor always comes back to it, even on a
     * page with a <base href> or after a single-page app changes the address.
     */
    public static function pathOf(string $requestUri): string
    {
        $path = (string) parse_url($requestUri, PHP_URL_PATH);

        if ($path === '' || $path[0] !== '/' || strlen($path) > 2048 || preg_match('/[\x00-\x20"<>\\\\]/', $path)) {
            return '/';
        }

        return $path;
    }

    /** The script URL: this page's own path, so it always reaches this SDK. */
    public static function src(string $publicKey, string $path = ''): string
    {
        return $path . '?' . self::param($publicKey) . '=s&v=' . SensorScript::VERSION;
    }

    /** @return string[] response header lines for the script */
    public static function scriptHeaders(): array
    {
        return [
            'Content-Type: application/javascript; charset=utf-8',
            // Versioned URL, so it can be kept for a year.
            'Cache-Control: public, max-age=31536000, immutable',
            'X-Content-Type-Options: nosniff',
        ];
    }

    /** Send the response now and keep running, where the server allows it. */
    public static function finishResponse(): void
    {
        if (function_exists('fastcgi_finish_request')) {
            fastcgi_finish_request();
        } elseif (function_exists('litespeed_finish_request')) {
            litespeed_finish_request();
        } else {
            @ob_end_flush();
            flush();
        }
    }
}
