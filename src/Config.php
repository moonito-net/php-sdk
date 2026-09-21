<?php

namespace Moonito;

/**
 * Every setting, with a safe default for each.
 *
 * "Safe" here means the default never makes the customer's site slower, less
 * available, or less correct than not installing the SDK at all. Anything that
 * trades availability for protection is opt in.
 */
final class Config
{
    /** @var string */
    public $publicKey = '';
    /** @var string */
    public $secretKey = '';
    /** @var string */
    public $endpoint = 'https://moonito.net';

    /** Protection off means the SDK does nothing at all. */
    public $enabled = true;

    /**
     * Timeouts, in seconds, clamped in Transport.
     *
     * There is no value meaning "wait forever". Version 2.0.1 shipped
     * CURLOPT_TIMEOUT => 0 and a slow API hung every page on the site.
     */
    public $timeout = 2.0;
    public $connectTimeout = 1.0;

    /**
     * open   on failure the visitor is allowed through, flagged as degraded
     * closed on failure the visitor is blocked
     *
     * Open is the default and is right for almost everyone: a protection
     * outage must not become a site outage.
     */
    public $failMode = 'open';

    /**
     * Proxies whose forwarded headers may be believed.
     *
     * Empty means nothing forwarded is trusted, which is correct for a site
     * that is not behind a proxy. Private addresses are handled automatically.
     */
    public $trustedProxies = [];
    public $cloudflare = false;

    /** Paths that skip the check entirely. Assets are not what gets attacked. */
    public $skipPaths = [
        '#\.(css|js|mjs|map|png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|eot|otf|mp4|webm|mp3|pdf|zip)(\?|$)#i',
    ];

    /** Seconds an allow decision may be reused. Blocks are never cached. */
    public $cacheTtl = 60;
    /** @var string|null */
    public $cacheDir = null;

    /**
     * What to do when the engine asks for a challenge.
     *
     *   allow      treat it as an allow and log it. The default, and what
     *              every install before 3.1 did.
     *   block      treat it as a block.
     *   challenge  actually show the interstitial.
     *
     * The default stays 'allow' on upgrade on purpose. Turning a scored
     * challenge into a real page interruption changes what a visitor sees, and
     * that is the site owner's decision to make, not a side effect of taking a
     * patch release.
     */
    public $challengeAction = 'allow';

    /** Unwanted visitor handling, unchanged from 2.0.1. */
    public $unwantedVisitorTo = 'https://google.com';
    public $unwantedVisitorAction = 1;

    /** Identity cookie and the context tag the browser sensor reads. */
    public $identityCookie = true;
    public $emitContext = true;

    /** @var string|null */
    public $debugLog = null;

    /** Throw instead of returning a degraded decision. Off by default. */
    public $throwOnError = false;

    public static function fromArray(array $values): self
    {
        $config = new self();

        $map = [
            'public_key' => 'publicKey',
            'secret_key' => 'secretKey',
            'endpoint' => 'endpoint',
            'enabled' => 'enabled',
            'timeout' => 'timeout',
            'connect_timeout' => 'connectTimeout',
            'fail_mode' => 'failMode',
            'trusted_proxies' => 'trustedProxies',
            'cloudflare' => 'cloudflare',
            'skip_paths' => 'skipPaths',
            'cache_ttl' => 'cacheTtl',
            'cache_dir' => 'cacheDir',
            'challenge_action' => 'challengeAction',
            'unwanted_visitor_to' => 'unwantedVisitorTo',
            'unwanted_visitor_action' => 'unwantedVisitorAction',
            'identity_cookie' => 'identityCookie',
            'emit_context' => 'emitContext',
            'debug_log' => 'debugLog',
            'throw_on_error' => 'throwOnError',
        ];

        foreach ($map as $key => $property) {
            if (array_key_exists($key, $values)) {
                $config->{$property} = $values[$key];
            }
            // Also accept the property name directly.
            if (array_key_exists($property, $values)) {
                $config->{$property} = $values[$property];
            }
        }

        return $config;
    }

    public function isConfigured(): bool
    {
        return $this->publicKey !== ''
            && $this->secretKey !== ''
            && strpos($this->publicKey, 'Your API') !== 0;
    }

    public function cacheDirectory(): string
    {
        // Named for what it holds, not for who wrote it. A directory called
        // moonito-sdk sitting in /tmp announces the product to anybody with a
        // shell on the box, which is a free hint nobody needs to give.
        return $this->cacheDir ?: rtrim(sys_get_temp_dir(), '/') . '/.req-cache';
    }
}
