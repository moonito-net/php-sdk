<?php

namespace Moonito;

use Moonito\Cache\Store;

/**
 * Stops a Moonito outage from adding two seconds to every page on the site.
 *
 *   CLOSED    --- 5 failures in 30 s --->  OPEN
 *   OPEN      --- backoff elapsed ------>  HALF_OPEN
 *   HALF_OPEN --- one success ---------->  CLOSED
 *   HALF_OPEN --- one failure ---------->  OPEN, backoff doubles, capped
 *
 * While open, no request is attempted at all, so the cost of the outage drops
 * from a timeout per page view to nothing.
 *
 * State lives in the shared cache so it is shared across php-fpm workers. A
 * per-process breaker on a host with fifty workers needs fifty times as many
 * failures to trip, which is the same as not having one.
 */
final class CircuitBreaker
{
    private const KEY = 'circuit';
    private const THRESHOLD = 5;
    private const WINDOW = 30;
    private const BASE_BACKOFF = 30;
    private const MAX_BACKOFF = 300;

    private $store;

    public function __construct(Store $store)
    {
        $this->store = $store;
    }

    public function allows(): bool
    {
        $state = $this->state();

        return $state['open_until'] <= time();
    }

    public function recordSuccess(): void
    {
        $this->store->forget(self::KEY);
    }

    public function recordFailure(): void
    {
        $state = $this->state();
        $now = time();

        // Failures older than the window do not count toward tripping.
        if ($now - $state['first_failure'] > self::WINDOW) {
            $state['failures'] = 0;
            $state['first_failure'] = $now;
        }

        $state['failures']++;

        if ($state['failures'] >= self::THRESHOLD) {
            $state['backoff'] = min(self::MAX_BACKOFF, max(self::BASE_BACKOFF, $state['backoff'] * 2));
            $state['open_until'] = $now + $state['backoff'];
            $state['failures'] = 0;
            $state['first_failure'] = $now;
        }

        $this->store->put(self::KEY, $state, self::MAX_BACKOFF + self::WINDOW);
    }

    /** Open the circuit immediately, for failures that retrying cannot fix. */
    public function openFor(int $seconds): void
    {
        $state = $this->state();
        $state['open_until'] = time() + $seconds;
        $this->store->put(self::KEY, $state, $seconds + self::WINDOW);
    }

    private function state(): array
    {
        $state = $this->store->get(self::KEY);

        if (!is_array($state)) {
            return ['failures' => 0, 'first_failure' => time(), 'open_until' => 0, 'backoff' => 0];
        }

        return $state + ['failures' => 0, 'first_failure' => time(), 'open_until' => 0, 'backoff' => 0];
    }
}
