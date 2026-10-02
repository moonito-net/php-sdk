<?php

namespace Moonito\Framework\Laravel;

use Closure;
use Moonito\Client;
use Moonito\Decision;

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
        $decision = $this->client->evaluate($request->server->all(), $request->cookies->all());

        if ($decision->isBlock() && !$decision->isDegraded()) {
            return $this->block($request, $decision);
        }

        $response = $next($request);

        return $this->attach($request, $response, $decision);
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

        if ($decision->decisionId() !== null && $response instanceof \Symfony\Component\HttpFoundation\Response) {
            // Read by the browser sensor when the page head cannot be edited.
            $response->headers->set('X-Moonito-Ctx', $decision->decisionId() . ':' . $decision->nonce());
        }

        return $response;
    }
}
