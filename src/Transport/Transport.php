<?php

namespace Moonito\Transport;

/**
 * @return array{ok: bool, status: int, body: string, error: string}
 */
interface Transport
{
    public function post(string $url, array $payload, array $headers, float $connectTimeout, float $timeout): array;
}
