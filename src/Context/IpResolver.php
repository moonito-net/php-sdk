<?php

namespace Moonito\Context;

/**
 * Works out which address to score, and which one a naive resolver would have
 * picked.
 *
 * Versions before 3.0 read HTTP_CLIENT_IP first, then HTTP_X_FORWARDED_FOR,
 * then REMOTE_ADDR. Both of the first two are request headers, so on a site
 * that is not behind a proxy the visitor sets them: sending
 * "Client-IP: 8.8.8.8" made Moonito evaluate Google's address and return
 * Google's verdict, bypassing every IP-based check in the product.
 *
 * A forwarded header is believed only when the request reached us through a
 * proxy there is reason to trust, and the chain is walked right to left,
 * because the leftmost entry is the one an attacker prepends.
 */
final class IpResolver
{
    private $trustedProxies;
    private $cloudflare;

    public function __construct(array $trustedProxies = [], bool $cloudflare = false)
    {
        $this->trustedProxies = $trustedProxies;
        $this->cloudflare = $cloudflare;
    }

    /**
     * @return array{ip: string, claimed: string|null}
     *         claimed is what the old resolver would have used, when it differs.
     *         It is reported to Moonito as evidence and never used for lookup.
     */
    public function resolve(array $server): array
    {
        $remote = isset($server['REMOTE_ADDR']) ? $server['REMOTE_ADDR'] : '';

        if (!filter_var($remote, FILTER_VALIDATE_IP)) {
            return ['ip' => '', 'claimed' => null];
        }

        $trusted = $this->trustedProxies;
        $headers = ['HTTP_X_FORWARDED_FOR'];

        if ($this->cloudflare) {
            $trusted = array_merge($trusted, CloudflareRanges::all());
            array_unshift($headers, 'HTTP_CF_CONNECTING_IP');
        }

        $remoteIsTrusted = $this->inAnyRange($remote, $trusted);
        $remoteIsPrivate = $this->isPrivate($remote);

        $resolved = $remote;

        if ($remoteIsTrusted || $remoteIsPrivate) {
            foreach ($headers as $header) {
                if (empty($server[$header])) {
                    continue;
                }

                $chain = array_reverse(array_map('trim', explode(',', $server[$header])));

                foreach ($chain as $candidate) {
                    $candidate = trim($candidate, '[]');

                    if (!filter_var($candidate, FILTER_VALIDATE_IP)) {
                        continue;
                    }

                    if ($this->inAnyRange($candidate, $trusted)) {
                        continue;
                    }

                    if ($remoteIsPrivate && !$remoteIsTrusted && $this->isPrivate($candidate)) {
                        continue;
                    }

                    $resolved = $candidate;
                    break 2;
                }
            }
        }

        return ['ip' => $resolved, 'claimed' => $this->legacyChoice($server, $resolved)];
    }

    /** What the pre-3.0 resolver would have returned, when it differs. */
    private function legacyChoice(array $server, string $resolved): ?string
    {
        foreach (['HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'] as $key) {
            if (empty($server[$key])) {
                continue;
            }

            $value = trim(explode(',', $server[$key])[0]);

            if (filter_var($value, FILTER_VALIDATE_IP)) {
                return $value === $resolved ? null : $value;
            }
        }

        return null;
    }

    private function isPrivate(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false;
    }

    private function inAnyRange(string $ip, array $ranges): bool
    {
        foreach ($ranges as $range) {
            if ($this->inRange($ip, trim($range))) {
                return true;
            }
        }

        return false;
    }

    private function inRange(string $ip, string $cidr): bool
    {
        if (strpos($cidr, '/') === false) {
            return $ip === $cidr;
        }

        list($subnet, $bits) = explode('/', $cidr, 2);
        $bits = (int) $bits;

        $ipBin = @inet_pton($ip);
        $subnetBin = @inet_pton($subnet);

        if ($ipBin === false || $subnetBin === false || strlen($ipBin) !== strlen($subnetBin)) {
            return false;
        }

        $whole = (int) ($bits / 8);
        $left = $bits % 8;

        if ($whole > 0 && substr($ipBin, 0, $whole) !== substr($subnetBin, 0, $whole)) {
            return false;
        }

        if ($left === 0) {
            return true;
        }

        $mask = chr((0xFF << (8 - $left)) & 0xFF);

        return (substr($ipBin, $whole, 1) & $mask) === (substr($subnetBin, $whole, 1) & $mask);
    }
}
