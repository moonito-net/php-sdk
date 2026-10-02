<?php

namespace Moonito;

use Moonito\Cache\Store;
use Moonito\Challenge\Bridge;
use Moonito\Challenge\PassJar;
use Moonito\Context\IpResolver;
use Moonito\Enforcer\Enforcer;
use Moonito\Identity\TokenJar;
use Moonito\Transport\CurlTransport;
use Moonito\Transport\StreamTransport;
use Moonito\Transport\Transport;

/**
 * The SDK's entry point.
 *
 * Two promises govern everything here:
 *
 *   The SDK never emits anything into the customer's page. No warnings, no
 *   notices, no stack traces. A security library that prints a PHP warning
 *   above the doctype has broken the site it was installed to protect.
 *
 *   The SDK never throws into customer code by default. evaluate() always
 *   returns a Decision, with isDegraded() set when the check could not run.
 */
final class Client
{
    const VERSION = '3.4.0';

    private $config;
    private $store;
    private $breaker;
    private $transport;
    private $ipResolver;
    private $tokens;
    private $enforcer;
    private $passes;

    public function __construct(Config $config, ?Transport $transport = null)
    {
        $this->config = $config;
        $this->store = new Store($config->cacheDirectory());
        $this->breaker = new CircuitBreaker($this->store);
        $this->transport = $transport ?: $this->pickTransport();
        $this->ipResolver = new IpResolver($config->trustedProxies, $config->cloudflare);
        $this->tokens = new TokenJar();
        $this->enforcer = new Enforcer($config);
        $this->passes = new PassJar();
    }

    public static function fromArray(array $values): self
    {
        return new self(Config::fromArray($values));
    }

    public function evaluate(?array $server = null, ?array $cookies = null): Decision
    {
        $server = $server === null ? $_SERVER : $server;
        $cookies = $cookies === null ? $_COOKIE : $cookies;

        try {
            return $this->run($server, $cookies);
        } catch (\Throwable $e) {
            $this->log('unexpected error, failing ' . $this->config->failMode . ': ' . $e->getMessage());

            if ($this->config->throwOnError) {
                throw $e;
            }

            return Decision::degraded($this->config->failMode);
        }
    }

    public function enforce(Decision $decision): void
    {
        $this->enforcer->enforce($decision);
    }

    /** Evaluate, act on a block, and set the cookie. The drop-in path. */
    public function protect(?array $server = null, ?array $cookies = null): Decision
    {
        $decision = $this->evaluate($server, $cookies);

        $this->applySideEffects($decision, $server === null ? $_SERVER : $server);

        if ($decision->isChallenge() && $decision->challengeUrl() !== null
            && $this->config->challengeAction === Decision::CHALLENGE) {
            (new Bridge())->render($decision->challengeUrl(), $server === null ? $_SERVER : $server, $_POST);

            return $decision;
        }

        if ($decision->isBlock()) {
            $this->enforce($decision);
        }

        return $decision;
    }

    /** The meta tag the browser sensor reads, or an empty string. */
    public function contextTag(Decision $decision): string
    {
        return $this->tokens->contextTag($decision->decisionId(), $decision->nonce());
    }

    private function run(array $server, array $cookies): Decision
    {
        if (!$this->config->enabled) {
            return Decision::degraded('open');
        }

        if (!$this->config->isConfigured()) {
            $this->log('skipped: API keys are not configured');

            return Decision::degraded('open');
        }

        $uri = isset($server['REQUEST_URI']) ? $server['REQUEST_URI'] : '/';

        if ($this->shouldSkip($uri)) {
            return Decision::degraded('open');
        }

        $resolved = $this->ipResolver->resolve($server);

        if ($resolved['ip'] === '') {
            $this->log('skipped: could not determine the client IP');

            return Decision::degraded('open');
        }

        $token = $this->tokens->read($cookies);

        // Verified here, locally, with this site's own secret. The result is
        // forwarded so the server can credit the identity, and kept so that a
        // visitor holding a valid pass is never sent round the loop again.
        $pass = $this->passes->read($cookies);
        $passValid = $pass !== null && $this->passes->isValid(
            $pass,
            $this->config->secretKey,
            $token,
            $resolved['ip'],
            isset($server['HTTP_USER_AGENT']) ? $server['HTTP_USER_AGENT'] : ''
        );

        if ($pass !== null && !$passValid) {
            $this->log('challenge pass present but not valid for this visitor, ignoring it');
        }

        $cacheKey = $this->cacheKey($resolved['ip'], $uri, $server, $token, $passValid);

        $cached = $this->store->get($cacheKey);

        if (is_array($cached)) {
            return $this->settle(Decision::fromResponse($cached, $this->config->challengeAction), $passValid);
        }

        if (!$this->breaker->allows()) {
            // Circuit open: no request is made at all, so an outage costs
            // nothing per page view instead of a timeout per page view.
            return $this->degradedWithFallback($resolved['ip']);
        }

        $response = $this->transport->post(
            rtrim($this->config->endpoint, '/') . '/api/v2/decision',
            $this->payload($resolved, $uri, $server, $token, $passValid ? $pass : null),
            [
                'User-Agent: Moonito-PHP/' . self::VERSION,
                'X-Public-Key: ' . $this->config->publicKey,
                'X-Secret-Key: ' . $this->config->secretKey,
            ],
            (float) $this->config->connectTimeout,
            (float) $this->config->timeout
        );

        return $this->settle($this->interpret($response, $resolved['ip'], $cacheKey), $passValid);
    }

    private function interpret(array $response, string $ip, string $cacheKey): Decision
    {
        if (!$response['ok']) {
            $this->breaker->recordFailure();
            $this->log('request failed (' . $response['error'] . '), failing ' . $this->config->failMode);

            return $this->degradedWithFallback($ip);
        }

        $status = $response['status'];

        if ($status === 401 || $status === 403) {
            // Configuration, not weather. Retrying will not fix it, so the
            // circuit opens for long enough to stop hammering the API.
            $this->breaker->openFor(300);
            $this->log('API returned ' . $status . '. Check your keys and that the domain is verified.');

            return $this->degradedWithFallback($ip);
        }

        if ($status === 429) {
            $this->breaker->openFor(60);
            $this->log('API returned 429, quota exceeded.');

            return $this->degradedWithFallback($ip);
        }

        if ($status >= 500) {
            $this->breaker->recordFailure();

            return $this->degradedWithFallback($ip);
        }

        $decoded = json_decode($response['body'], true);

        if (!is_array($decoded) || !isset($decoded['data'])) {
            $this->breaker->recordFailure();
            $this->log('API returned a response that is not usable JSON');

            return $this->degradedWithFallback($ip);
        }

        $this->breaker->recordSuccess();

        $decision = Decision::fromResponse($decoded, $this->config->challengeAction);

        // Allow decisions only. Caching a block could poison a genuine
        // visitor sharing a key, and a passed challenge must take effect now.
        if ($decision->isCacheable() && $this->config->cacheTtl > 0) {
            $this->store->put($cacheKey, $decoded, (int) $this->config->cacheTtl);
            $this->store->put('last:' . $ip, $decoded, 300);
        }

        return $decision;
    }

    /**
     * Degraded mode, in order of preference:
     *   1. the last known decision for this address, if recent
     *   2. the configured fail mode
     */
    private function degradedWithFallback(string $ip): Decision
    {
        $last = $this->store->get('last:' . $ip);

        if (is_array($last)) {
            $decision = Decision::fromResponse($last, $this->config->challengeAction);

            if ($decision->isAllow()) {
                return $decision;
            }
        }

        return Decision::degraded($this->config->failMode);
    }

    /**
     * The loop breaker.
     *
     * A visitor who just solved a CAPTCHA and came back holding a valid pass
     * must not be sent to the interstitial again, whatever the server says.
     * The server has its own version of this check; this one exists because a
     * bug on either side should cost a wasted challenge, never an endless
     * redirect on somebody's checkout page.
     */
    private function settle(Decision $decision, bool $passValid): Decision
    {
        if (!$passValid || !$decision->isChallenge()) {
            return $decision;
        }

        $this->log('challenge requested for a visitor who already holds a valid pass, allowing');

        return $decision->withoutChallenge();
    }

    private function pathOnly(string $uri): string
    {
        if ($uri === '' || $uri[0] !== '/') {
            return '/';
        }

        // "//evil.example" is a protocol-relative URL wearing a path's clothes.
        if (isset($uri[1]) && $uri[1] === '/') {
            return '/';
        }

        return substr($uri, 0, 512);
    }

    private function payload(array $resolved, string $uri, array $server, ?string $token, ?string $pass = null): array
    {
        $payload = [
            'domain' => isset($server['HTTP_HOST']) ? strtolower($server['HTTP_HOST']) : '',
            'ip' => $resolved['ip'],
            'ua' => isset($server['HTTP_USER_AGENT']) ? $server['HTTP_USER_AGENT'] : '',
            'events' => $uri,
            'method' => isset($server['REQUEST_METHOD']) ? $server['REQUEST_METHOD'] : 'GET',
            'protocol' => isset($server['SERVER_PROTOCOL']) ? $server['SERVER_PROTOCOL'] : null,
            'headers' => $this->headers($server),
            'sdk' => 'php/' . self::VERSION,
        ];

        // A path, never a URL. The interstitial builds the return address from
        // the domain record, so nothing the visitor controls can steer it.
        $payload['path'] = $this->pathOnly($uri);

        if ($pass !== null) {
            $payload['challenge_pass'] = $pass;
        }

        if ($token !== null) {
            $payload['client_token'] = $token;
        }

        // What a naive resolver would have used, when it differs. Evidence for
        // Moonito, never an input to geolocation.
        if ($resolved['claimed'] !== null) {
            $payload['ip_claimed'] = $resolved['claimed'];
        }

        return $payload;
    }

    /** The request headers, reconstructed from $_SERVER, capped in size. */
    private function headers(array $server): array
    {
        $headers = [];

        foreach ($server as $key => $value) {
            if (!is_string($value) || strpos($key, 'HTTP_') !== 0) {
                continue;
            }

            $name = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($key, 5)))));

            // Never forward the visitor's cookies or credentials to Moonito.
            if (in_array(strtolower($name), ['cookie', 'authorization', 'proxy-authorization'], true)) {
                continue;
            }

            $headers[$name] = substr($value, 0, 2048);

            if (count($headers) >= 48) {
                break;
            }
        }

        return $headers;
    }

    private function applySideEffects(Decision $decision, array $server): void
    {
        $secure = (!empty($server['HTTPS']) && $server['HTTPS'] !== 'off')
            || (isset($server['SERVER_PORT']) && (int) $server['SERVER_PORT'] === 443)
            || (isset($server['HTTP_X_FORWARDED_PROTO']) && $server['HTTP_X_FORWARDED_PROTO'] === 'https');

        $cookie = $decision->clientTokenCookie();

        if ($this->config->identityCookie && $cookie !== null) {
            if (!$this->tokens->write($cookie, isset($server['HTTP_HOST']) ? $server['HTTP_HOST'] : '', $secure)) {
                $this->log('identity cookie not set: headers were already sent. Move the include earlier.');
            }
        }

        if ($this->config->emitContext) {
            $this->tokens->writeContextCookie($decision->decisionId(), $decision->nonce(), $secure);
        }
    }

    private function shouldSkip(string $uri): bool
    {
        foreach ($this->config->skipPaths as $pattern) {
            if (@preg_match($pattern, $uri) === 1) {
                return true;
            }
        }

        return false;
    }

    private function cacheKey(string $ip, string $uri, array $server, ?string $token, bool $passValid = false): string
    {
        return hash('sha256', implode('|', [
            // A pass changes the answer, so it has to change the key. Without
            // this, the allow earned by a challenge would be served to the
            // same address after the pass expired.
            $passValid ? 'pass' : 'nopass',
            $token ?: $ip,
            isset($server['HTTP_HOST']) ? $server['HTTP_HOST'] : '',
            $this->pathClass($uri),
            substr(hash('sha256', isset($server['HTTP_USER_AGENT']) ? $server['HTTP_USER_AGENT'] : ''), 0, 16),
        ]));
    }

    /** Query strings vary per visit; the path is what a decision is about. */
    private function pathClass(string $uri): string
    {
        return explode('?', $uri, 2)[0];
    }

    private function pickTransport(): Transport
    {
        if (CurlTransport::available()) {
            return new CurlTransport();
        }

        if (StreamTransport::available()) {
            return new StreamTransport();
        }

        // Neither available. Every request will fail open, which the log says.
        return new StreamTransport();
    }

    private function log(string $message): void
    {
        $path = $this->config->debugLog;

        if (empty($path)) {
            return;
        }

        if (@filesize($path) > 5242880) {
            @rename($path, $path . '.1');
        }

        @file_put_contents($path, gmdate('Y-m-d H:i:s') . ' ' . $message . PHP_EOL, FILE_APPEND | LOCK_EX);
    }
}
