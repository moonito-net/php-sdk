<?php

namespace Moonito\Framework\Psr15;

use Moonito\Client;
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

    public function __construct(Client $client, ?callable $onBlock = null, array $skip = [])
    {
        $this->client = $client;
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

        if ($decision->isBlock() && !$decision->isDegraded() && $this->onBlock !== null) {
            return call_user_func($this->onBlock, $request, $decision);
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
