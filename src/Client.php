<?php

namespace Moonito;

use Moonito\Cache\Store;
use Moonito\Challenge\Bridge;
use Moonito\Challenge\PassJar;
use Moonito\Check\CheckPage;
use Moonito\Context\IpResolver;
use Moonito\Enforcer\Enforcer;
use Moonito\Identity\TokenJar;
use Moonito\Sensor\Injector;
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
    const VERSION = '3.5.2';

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
        $server = $server === null ? $_SERVER : $server;
        $cookies = $cookies === null ? $_COOKIE : $cookies;

        // The browser check talks only to this same URL: timing requests and
        // the answers. Both are handled here, before any decision is asked for.
        if ($this->config->enabled && $this->config->isConfigured() && !headers_sent()) {
            if (CheckPage::isPing($server)) {
                http_response_code(204);
                header('Cache-Control: no-store, private');
                exit;
            }

            if (CheckPage::isAnswer($server)) {
                $this->respondToCheck($server, $cookies, (string) file_get_contents('php://input', false, null, 0, 32768));
                exit;
            }
        }

        $decision = $this->evaluate($server, $cookies);

        $this->applySideEffects($decision, $server);

        if ($decision->check() !== null) {
            $decision = $this->showCheck($decision, $server, $cookies);
        }

        if ($decision->isChallenge() && $decision->challengeUrl() !== null
            && in_array($this->config->challengeAction, [Decision::CHALLENGE, Decision::FOLLOW], true)) {
            (new Bridge())->render($decision->challengeUrl(), $server, $_POST);

            return $decision;
        }

        if ($decision->isBlock()) {
            $this->enforce($decision);
        }

        $this->startSensor($decision, $server);

        return $decision;
    }

    /**
     * Shows the check page and stops, unless the visitor failed a check a
     * moment ago (then the site's unwanted-visitor action applies) or Moonito
     * could not be reached to verify the last one (then they are let through,
     * as every other API failure lets them through).
     */
    private function showCheck(Decision $decision, array $server, array $cookies): Decision
    {
        $next = $this->checkStep($decision, $server, $cookies);

        if ($next !== 'show') {
            return $decision->withoutChallenge($next === 'block' ? Decision::BLOCK : Decision::ALLOW);
        }

        if (headers_sent()) {
            // The page is already half sent; a check cannot be shown cleanly.
            return $decision->withoutChallenge(Decision::ALLOW);
        }

        header('HTTP/1.1 200 OK');
        header('Content-Type: text/html; charset=utf-8');
        header('Cache-Control: no-store, private');
        header('X-Robots-Tag: noindex, nofollow');
        header('Referrer-Policy: no-referrer');

        echo CheckPage::html($decision->check(), $server, $_POST);
        exit;
    }

    /**
     * What to do with a decision that carries a check: 'show' it, 'block'
     * (the visitor failed one a moment ago, so the unwanted-visitor action
     * applies) or 'allow' (Moonito could not verify the last one, and like
     * every other API failure that lets the visitor through for a while).
     */
    public function checkStep(Decision $decision, array $server, array $cookies): string
    {
        if ($decision->check() === null) {
            return 'allow';
        }

        if (!empty($cookies[CheckPage::FAIL_COOKIE])) {
            return 'block';
        }

        $ip = $this->ipResolver->resolve($server)['ip'];

        return $ip !== '' && $this->store->get('check-open:' . $ip) ? 'allow' : 'show';
    }

    /**
     * The answers from the check page, forwarded to Moonito server to server.
     *
     * @return array{json: string, pass: ?string, ttl: int, failed: bool}
     */
    public function answerCheck(array $server, array $cookies, string $body): array
    {
        $answers = json_decode($body, true);
        $result = ['pass' => null, 'ttl' => 0, 'failed' => false];

        if (is_array($answers) && isset($answers['t']) && is_string($answers['t'])) {
            $outcome = $this->verifyCheck($server, $cookies, $answers);

            if (($outcome['outcome'] === 'pass' || $outcome['outcome'] === 'uncertain') && $outcome['pass'] !== null) {
                $result['pass'] = $outcome['pass'];
                $result['ttl'] = $outcome['ttl'];
            } elseif ($outcome['outcome'] === 'fail') {
                $result['failed'] = true;
            }
        }

        // The browser learns only where to go next, never why.
        $result['json'] = json_encode(['next' => CheckPage::returnUrl($server), 'passed' => $result['pass'] !== null]);

        return $result;
    }

    /** The drop-in path: answer, set the cookie, and stop. */
    private function respondToCheck(array $server, array $cookies, string $body): void
    {
        $result = $this->answerCheck($server, $cookies, $body);
        $secure = (!empty($server['HTTPS']) && $server['HTTPS'] !== 'off')
            || (isset($server['HTTP_X_FORWARDED_PROTO']) && $server['HTTP_X_FORWARDED_PROTO'] === 'https');

        header('Content-Type: application/json');
        header('Cache-Control: no-store, private');

        if ($result['pass'] !== null) {
            $this->passes->write($result['pass'], $secure, $result['ttl']);
        } elseif ($result['failed']) {
            $this->setFailCookie($secure);
        }

        echo $result['json'];
    }

    /** @return array{outcome: string, pass: ?string, ttl: int} */
    public function verifyCheck(array $server, array $cookies, array $answers): array
    {
        $resolved = $this->ipResolver->resolve($server);
        $token = $this->tokens->read($cookies);
        $ticket = (string) $answers['t'];
        unset($answers['t']);

        $payload = [
            't' => $ticket,
            'ip' => $resolved['ip'],
            'ua' => $this->bounded(isset($server['HTTP_USER_AGENT']) ? $server['HTTP_USER_AGENT'] : '', 2048),
            'answers' => $answers,
        ];

        if ($token !== null) {
            $payload['client_token'] = $token;
        }

        $response = $this->transport->post(
            rtrim($this->config->endpoint, '/') . '/api/v2/check/verify',
            $payload,
            [
                'User-Agent: Moonito-PHP/' . self::VERSION,
                'X-Public-Key: ' . $this->config->publicKey,
                'X-Secret-Key: ' . $this->config->secretKey,
            ],
            (float) $this->config->connectTimeout,
            (float) $this->config->timeout
        );

        $decoded = $response['ok'] && $response['status'] < 500 ? json_decode($response['body'], true) : null;
        $outcome = is_array($decoded) && isset($decoded['data']['outcome']) ? (string) $decoded['data']['outcome'] : null;

        if ($outcome === null) {
            // Moonito could not answer. Fail open for this visitor for a few
            // minutes, like any other API failure, instead of looping them.
            $this->log('check could not be verified, letting the visitor through');
            if ($resolved['ip'] !== '') {
                $this->store->put('check-open:' . $resolved['ip'], 1, 300);
            }

            return ['outcome' => 'unverified', 'pass' => null, 'ttl' => 0];
        }

        return [
            'outcome' => $outcome,
            'pass' => isset($decoded['data']['pass']) && is_string($decoded['data']['pass']) ? $decoded['data']['pass'] : null,
            'ttl' => isset($decoded['data']['pass_ttl']) ? (int) $decoded['data']['pass_ttl'] : 1800,
        ];
    }

    private function setFailCookie(bool $secure): void
    {
        if (headers_sent()) {
            return;
        }

        setcookie(CheckPage::FAIL_COOKIE, '1', [
            'expires' => time() + 300,
            'path' => '/',
            'secure' => $secure,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
    }

    /**
     * Add the browser sensor to this page on the way out. Never for a skipped
     * path, a switched-off or unconfigured install, or a blocked visitor.
     */
    private function startSensor(Decision $decision, array $server): void
    {
        if (!$this->config->injectSensor || !$this->config->enabled || !$this->config->isConfigured() || $decision->isBlock()) {
            return;
        }

        if ($this->shouldSkip(isset($server['REQUEST_URI']) ? (string) $server['REQUEST_URI'] : '/')) {
            return;
        }

        $injector = new Injector((string) $this->config->publicKey, (string) $this->config->endpoint, function () {
            // The page's CSP blocks the sensor. Say so on the next requests,
            // so Moonito does not read the missing beacons as a bot.
            $this->rememberSensorBlocked();
        });

        $injector->start($server, $this->config->emitContext ? $this->contextTag($decision) : '');
    }

    /** The site's CSP blocks the sensor: tell Moonito on the next requests. */
    public function rememberSensorBlocked(): void
    {
        $this->store->put('sensor-off', 1, 3600);
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

        return $this->bounded($uri, 512);
    }

    /** API limits count characters; never cut through a UTF-8 sequence. */
    private function bounded($value, int $limit): string
    {
        return is_string($value) && preg_match('/\A.{0,' . $limit . '}/us', $value, $match) ? $match[0] : '';
    }

    private function payload(array $resolved, string $uri, array $server, ?string $token, ?string $pass = null): array
    {
        $payload = [
            'domain' => isset($server['HTTP_HOST']) ? strtolower($server['HTTP_HOST']) : '',
            'ip' => $resolved['ip'],
            'ua' => $this->bounded(isset($server['HTTP_USER_AGENT']) ? $server['HTTP_USER_AGENT'] : '', 2048),
            'events' => $this->bounded($uri, 4096),
            'method' => $this->bounded(isset($server['REQUEST_METHOD']) ? $server['REQUEST_METHOD'] : 'GET', 16),
            'protocol' => isset($server['SERVER_PROTOCOL']) ? $this->bounded($server['SERVER_PROTOCOL'], 16) : null,
            'headers' => $this->headers($server),
            'sdk' => 'php/' . self::VERSION,
            // Can show the browser check on this site's own URL.
            // check2: also shows a check that comes with an allow ("Check every
            // new visitor" in the dashboard).
            'caps' => 'check1,check2',
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

        if ($this->store->get('sensor-off')) {
            $payload['sensor'] = 'off';
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

            $headers[$name] = $this->bounded($value, 2048);

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
