# Changelog

## 3.4.2

- Bound request fields and headers to the decision API limits without splitting
  UTF-8 characters. Ignore malformed identity cookies so they cannot prevent
  the API check from running.
- Trust CF-Connecting-IP only when the directly connected peer is a Cloudflare
  edge. Resolve trusted proxy chains using X-Forwarded-For otherwise.
- Deliver browser sensor context through Laravel and PSR-15 response cookies.
  Keep Moonito protocol cookies readable through Laravel's encryption middleware.
- Add regression tests for proxy spoofing, malformed cookies, oversized input,
  and real HTTP requests using both cURL and stream transports.

Existing API keys and settings remain compatible. Replace only engine.php and
detector.php when upgrading the drop-in, preserving config.php.

## 3.4.1

- Isolate cached decisions and circuit breakers by API endpoint and credentials.
  A failed credential can no longer stop another client from checking visitors,
  and an allow decision cannot be reused across accounts.
- Keep APCu entries isolated when applications share a PHP worker pool.
- Fall back to the file cache when APCu is installed but disabled for the
  current process.
- Add regression coverage for credential, account, endpoint, and cache isolation.

Existing installations must update their Composer dependency or replace the
drop-in runtime files. Existing keys and protection settings remain compatible.
