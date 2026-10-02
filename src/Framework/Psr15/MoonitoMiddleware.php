<?php

namespace Moonito\Framework\Psr15;

use Moonito\Client;
use Moonito\Config;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * PSR-15 middleware, for Slim, Mezzio and anything else that speaks it.
 *
 * The block response is a callable so the framework decides what a refusal
 * looks like. Guessing on the framework's behalf produces responses that do
 * not match the rest of the application.
 */
final class MoonitoMiddleware implements MiddlewareInterface
{
    private $client;
    private $onBlock;
    private $skip;

    /**
     * @param Client|Config $client  a Config is accepted too, as the README shows
     * @param callable|null $onBlock returns the response for a blocked visitor;
     *                               null sends the configured unwanted-visitor
     *                               response directly, so a block always blocks
     */
    public function __construct($client, ?callable $onBlock = null, array $skip = [])
    {
        $this->client = $client instanceof Config ? new Client($client) : $client;
        $this->onBlock = $onBlock;
        $this->skip = $skip;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $path = $request->getUri()->getPath();

        foreach ($this->skip as $pattern) {
            if (@preg_match($pattern, $path) === 1) {
                return $handler->handle($request);
            }
        }

        $decision = $this->client->evaluate($request->getServerParams(), $request->getCookieParams());

        if ($decision->isBlock() && !$decision->isDegraded()) {
            if ($this->onBlock !== null) {
                return call_user_func($this->onBlock, $request, $decision);
            }

            // No handler given. Letting the visitor through here used to be
            // the silent default, which made the middleware look installed
            // while blocking nothing.
            $this->client->enforce($decision);
        }

        $response = $handler->handle($request->withAttribute('moonito', $decision));

        $cookie = $decision->clientTokenCookie();

        if ($cookie !== null) {
            $response = $response->withAddedHeader('Set-Cookie', sprintf(
                '%s=%s; Max-Age=%d; Path=/; SameSite=Lax',
                $cookie['name'],
                $cookie['value'],
                (int) $cookie['max_age']
            ));
        }

        return $response;
    }
}
