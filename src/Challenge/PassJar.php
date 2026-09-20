<?php

namespace Moonito\Challenge;

/**
 * The challenge pass cookie, on the customer's own domain.
 *
 * Unlike the identity token, this one the SDK CAN verify by itself, and that
 * difference is deliberate. The identity token is signed with a server key
 * that must never leave Moonito. The pass is signed with a key derived from
 * this site's own API secret, which the SDK already holds, so checking it
 * costs one hash instead of one HTTP request.
 *
 * That matters for exactly one job: breaking the redirect loop. If Moonito
 * still says CHALLENGE for a visitor who is standing there holding a pass it
 * issued thirty seconds ago, sending them back to the interstitial would send
 * them round forever. The SDK has to be able to answer "have they already
 * done this" without asking anybody.
 *
 * This is the mirror of App\Services\Risk\Challenge\ChallengePass. The two
 * have to agree exactly, so any change to one is a change to both.
 */
final class PassJar
{
    const COOKIE = '__mo_pass';

    const PREFIX = 'mcp1';
    const CONTEXT = 'moonito/challenge-pass/v1';
    const KEY_CONTEXT = 'moonito/challenge-pass-key/v1';
    const SUBJECT_CONTEXT = 'moonito/challenge-subject/v1';
    const SUBJECT_LENGTH = 12;

    const MAX_LENGTH = 1024;

    public function read(array $cookies): ?string
    {
        $value = isset($cookies[self::COOKIE]) ? $cookies[self::COOKIE] : null;

        if (!is_string($value) || $value === '' || strlen($value) > self::MAX_LENGTH) {
            return null;
        }

        return $value;
    }

    /**
     * Signed, unexpired, this domain, this visitor.
     *
     * $domainId is not known to the SDK, so it is taken from the pass itself
     * and only checked for presence. That is safe: the signature already binds
     * the pass to this site's secret, so a pass minted for another customer
     * cannot verify here whatever domain id it claims.
     */
    public function isValid(?string $pass, string $secret, ?string $clientToken, string $ip, string $userAgent): bool
    {
        $claims = $this->decode($pass, $secret);

        if ($claims === null) {
            return false;
        }

        if (!isset($claims['s']) || !is_string($claims['s'])) {
            return false;
        }

        return hash_equals($this->subject($clientToken, $ip, $userAgent, $secret), $claims['s']);
    }

    /** Mirrors ClientToken::parse, which keeps only the random component. */
    public function tokenRandom(?string $clientToken): ?string
    {
        if (!is_string($clientToken) || substr_count($clientToken, '.') !== 2) {
            return null;
        }

        $parts = explode('.', $clientToken, 3);

        return preg_match('/^[A-Za-z0-9_-]{1,32}$/', $parts[1]) ? $parts[1] : null;
    }

    public function subject(?string $clientToken, string $ip, string $userAgent, string $secret): string
    {
        $random = $this->tokenRandom($clientToken);

        $anchor = $random !== null && $random !== ''
            ? 'ct:' . $random
            : 'ipua:' . $ip . '|' . $userAgent;

        return substr(
            hash_hmac('sha256', self::SUBJECT_CONTEXT . "\0" . $anchor, $secret),
            0,
            self::SUBJECT_LENGTH
        );
    }

    /**
     * Written by the bridge page's JavaScript rather than here, because the
     * pass comes home in the URL fragment and a fragment never reaches the
     * server. This method exists for the case where the SDK has the pass in
     * hand and wants to extend it, and for tests.
     *
     * @return bool false when output had already started
     */
    public function write(string $pass, bool $secure, int $maxAge = 1800): bool
    {
        if (headers_sent()) {
            return false;
        }

        if (PHP_VERSION_ID >= 70300) {
            return setcookie(self::COOKIE, $pass, [
                'expires' => time() + $maxAge,
                'path' => '/',
                'secure' => $secure,
                'httponly' => false,
                'samesite' => 'Lax',
            ]);
        }

        return setcookie(self::COOKIE, $pass, time() + $maxAge, '/', '', $secure, false);
    }

    private function decode(?string $token, string $secret): ?array
    {
        if (!is_string($token) || $token === '' || strlen($token) > self::MAX_LENGTH) {
            return null;
        }

        if (substr_count($token, '.') !== 2) {
            return null;
        }

        list($prefix, $payload, $tag) = explode('.', $token, 3);

        if (!hash_equals(self::PREFIX, $prefix)) {
            return null;
        }

        if (!preg_match('/^[A-Za-z0-9_-]+$/', $payload) || !preg_match('/^[A-Za-z0-9_-]+$/', $tag)) {
            return null;
        }

        $key = hash_hmac('sha256', self::KEY_CONTEXT, $secret, true);
        $body = $prefix . '.' . $payload;
        $mac = substr(hash_hmac('sha256', self::CONTEXT . "\0" . $body, $key, true), 0, 16);

        if (!hash_equals($this->b64($mac), $tag)) {
            return null;
        }

        $claims = json_decode($this->unb64($payload), true);

        if (!is_array($claims) || !isset($claims['x']) || !is_int($claims['x']) || $claims['x'] < time()) {
            return null;
        }

        return $claims;
    }

    private function b64(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    private function unb64(string $value): string
    {
        return (string) base64_decode(strtr($value, '-_', '+/'), true);
    }
}
