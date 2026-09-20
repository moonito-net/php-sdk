<?php

namespace Moonito\Identity;

/**
 * Reads and writes the visitor's identity cookie.
 *
 * The SDK never validates the token locally. It cannot: the signing key is
 * server side, and shipping it to every customer would make it public, which
 * would make the signature worthless.
 *
 * HttpOnly is off on purpose. The browser sensor has to read the token to echo
 * it, and the token confers no privilege: possessing it does not make a
 * visitor trusted, it only tells Moonito whose history to consult. A stolen
 * token used from elsewhere produces a worse score, not a better one.
 */
final class TokenJar
{
    const COOKIE = '__mo_ct';
    const CONTEXT_COOKIE = '__mo_cx';

    public function read(array $cookies): ?string
    {
        $value = isset($cookies[self::COOKIE]) ? $cookies[self::COOKIE] : null;

        if (!is_string($value) || $value === '' || strlen($value) > 96) {
            return null;
        }

        return $value;
    }

    /**
     * @param array $descriptor as returned by the API under set_client_token
     * @return bool false when output had already started, so nothing was sent
     */
    public function write(array $descriptor, string $host, bool $secure): bool
    {
        if (headers_sent()) {
            return false;
        }

        $name = isset($descriptor['name']) ? $descriptor['name'] : self::COOKIE;
        $value = isset($descriptor['value']) ? $descriptor['value'] : '';
        $maxAge = isset($descriptor['max_age']) ? (int) $descriptor['max_age'] : 7776000;

        if ($value === '') {
            return false;
        }

        $options = [
            'expires' => time() + $maxAge,
            'path' => '/',
            'domain' => $this->registrableDomain($host),
            'secure' => $secure,
            'httponly' => false,
            'samesite' => 'Lax',
        ];

        if (PHP_VERSION_ID >= 70300) {
            return setcookie($name, $value, $options);
        }

        return setcookie($name, $value, $options['expires'], '/', $options['domain'], $secure, false);
    }

    /**
     * The decision id and nonce, for the browser sensor to echo back.
     *
     * A meta tag is preferred because it adds no bytes to later requests. The
     * cookie is the fallback for customers who cannot edit their page head.
     */
    public function contextTag(?string $decisionId, ?string $nonce): string
    {
        if ($decisionId === null || $nonce === null) {
            return '';
        }

        return sprintf(
            '<meta name="moonito-ctx" content="%s">',
            htmlspecialchars($decisionId . ':' . $nonce, ENT_QUOTES)
        );
    }

    public function writeContextCookie(?string $decisionId, ?string $nonce, bool $secure): bool
    {
        if ($decisionId === null || $nonce === null || headers_sent()) {
            return false;
        }

        if (PHP_VERSION_ID >= 70300) {
            return setcookie(self::CONTEXT_COOKIE, $decisionId . ':' . $nonce, [
                'expires' => time() + 120,
                'path' => '/',
                'secure' => $secure,
                'httponly' => false,
                'samesite' => 'Lax',
            ]);
        }

        return setcookie(self::CONTEXT_COOKIE, $decisionId . ':' . $nonce, time() + 120, '/', '', $secure, false);
    }

    /**
     * eTLD+1, so subdomains share one identity.
     *
     * Deliberately simple: a full public suffix list is a megabyte of data and
     * a maintenance burden, and getting this slightly wrong costs a little
     * correlation rather than any security property.
     */
    private function registrableDomain(string $host): string
    {
        $host = strtolower(preg_replace('/:\d+$/', '', $host));

        if (filter_var($host, FILTER_VALIDATE_IP) || substr_count($host, '.') < 1) {
            return '';
        }

        $parts = explode('.', $host);
        $count = count($parts);

        if ($count <= 2) {
            return '.' . $host;
        }

        // Two-part public suffixes such as co.uk, com.au, co.id.
        $secondLast = $parts[$count - 2];
        $twoPart = ['co', 'com', 'net', 'org', 'gov', 'edu', 'ac', 'or', 'ne', 'my', 'sch'];

        $take = in_array($secondLast, $twoPart, true) ? 3 : 2;

        return '.' . implode('.', array_slice($parts, -$take));
    }
}
