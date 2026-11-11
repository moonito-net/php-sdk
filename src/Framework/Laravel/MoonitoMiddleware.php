<?php

namespace Moonito\Framework\Laravel;

use Closure;
use Moonito\Client;
use Moonito\Check\CheckPage;
use Moonito\Challenge\PassJar;
use Moonito\Decision;
use Moonito\Sensor\Injector;

/**
 * Laravel middleware.
 *
 * Register it AFTER TrustProxies. Laravel has already resolved the client
 * address by then, so the SDK's own resolver sees a REMOTE_ADDR it can trust
 * rather than re-deriving it from headers a second time.
 */
class MoonitoMiddleware
{
    private $client;

    public function __construct(Client $client)
    {
        $this->client = $client;
    }

    public function handle($request, Closure $next)
    {
        $server = $request->server->all();
        $cookies = $request->cookies->all();

        // The browser check talks only to this same URL.
        if (config('moonito.enabled', true) && CheckPage::isPing($server)) {
            return response('', 204)->header('Cache-Control', 'no-store, private');
        }

        if (config('moonito.enabled', true) && CheckPage::isAnswer($server)) {
            return $this->answerCheck($request, $server, $cookies);
        }

        $decision = $this->client->evaluate($server, $cookies);

        if ($decision->check() !== null) {
            $step = $this->client->checkStep($decision, $server, $cookies);

            if ($step === 'show') {
                return response(CheckPage::html($decision->check(), $server, $request->request->all()), 200)
                    ->header('Content-Type', 'text/html; charset=utf-8')
                    ->header('Cache-Control', 'no-store, private')
                    ->header('X-Robots-Tag', 'noindex, nofollow')
                    ->header('Referrer-Policy', 'no-referrer');
            }

            $decision = $decision->withoutChallenge($step === 'block' ? Decision::BLOCK : Decision::ALLOW);
        }

        if ($decision->isBlock() && !$decision->isDegraded()) {
            return $this->block($request, $decision);
        }

        $response = $next($request);

        return $this->injectSensor($request, $this->attach($request, $response, $decision), $decision);
    }

    /**
     * The browser sensor, added to HTML pages so the site needs no separate
     * script tag. Streamed and file responses are never touched.
     */
    protected function injectSensor($request, $response, Decision $decision)
    {
        if (!config('moonito.inject_sensor', true)
            || !($response instanceof \Symfony\Component\HttpFoundation\Response)
            || $response instanceof \Symfony\Component\HttpFoundation\StreamedResponse
            || $response instanceof \Symfony\Component\HttpFoundation\BinaryFileResponse
            || !$this->wantsPage($request)) {
            return $response;
        }

        $content = $response->getContent();

        if (!is_string($content) || $content === '') {
            return $response;
        }

        $lines = [];
        foreach ($response->headers->all() as $name => $values) {
            foreach ((array) $values as $value) {
                $lines[] = $name . ': ' . $value;
            }
        }

        $client = $this->client;
        $injector = new Injector(
            (string) config('moonito.public_key', ''),
            (string) config('moonito.endpoint', 'https://moonito.net'),
            function () use ($client) {
                $client->rememberSensorBlocked();
            }
        );

        try {
            $result = $injector->process($content, $lines, $response->getStatusCode());
        } catch (\Throwable $e) {
            return $response;
        }

        if ($result['outcome'] === Injector::INJECTED) {
            $response->setContent($result['html']);
            $response->headers->remove('Content-Length');
        }

        return $response;
    }

    protected function answerCheck($request, array $server, array $cookies)
    {
        $result = $this->client->answerCheck($server, $cookies, (string) $request->getContent());
        $response = response($result['json'], 200)
            ->header('Content-Type', 'application/json')
            ->header('Cache-Control', 'no-store, private');

        if ($result['pass'] !== null) {
            $response->headers->setCookie(cookie(PassJar::COOKIE, $result['pass'], (int) ceil($result['ttl'] / 60), '/', null, $request->isSecure(), false, false, 'Lax'));
        } elseif ($result['failed']) {
            $response->headers->setCookie(cookie(CheckPage::FAIL_COOKIE, '1', 5, '/', null, $request->isSecure(), true, false, 'Lax'));
        }

        return $response;
    }

    /** A page request from a browser. Never true on the command line. */
    protected function wantsPage($request): bool
    {
        return Injector::wantsPage($request->server->all());
    }

    protected function block($request, Decision $decision)
    {
        $to = config('moonito.unwanted_visitor_to');

        if (is_numeric($to)) {
            abort((int) $to);
        }

        if (!empty($to)) {
            return redirect()->away($to, 302);
        }

        abort(403);
    }

    /**
     * Cookies are attached to the response rather than sent with setcookie(),
     * so they survive Laravel's own response handling and testing helpers.
     */
    protected function attach($request, $response, Decision $decision)
    {
        $cookie = $decision->clientTokenCookie();

        // headers is a property on a Symfony response, not a method, so the
        // method_exists() check this replaced never passed and the identity
        // cookie was never set.
        if ($cookie !== null && $response instanceof \Symfony\Component\HttpFoundation\Response) {
            $response->headers->setCookie(cookie(
                $cookie['name'],
                $cookie['value'],
                (int) ($cookie['max_age'] / 60),
                '/',
                null,
                $request->isSecure(),
                false,
                false,
                'Lax'
            ));
        }

        if ($decision->decisionId() !== null && $decision->nonce() !== null
            && $response instanceof \Symfony\Component\HttpFoundation\Response) {
            $response->headers->setCookie(cookie(
                '__mo_cx', $decision->decisionId() . ':' . $decision->nonce(),
                2, '/', null, $request->isSecure(), false, false, 'Lax'
            ));
        }

        return $response;
    }
}
