# Changelog

## 3.6.0

- The browser sensor is served from your own site. Its script, its timing
  requests and its beacon go to the page's own URL with a query parameter
  unique to your site (derived from your public key), and the SDK forwards
  the beacon to Moonito from your server after the browser has its answer.
  Visitors' browsers never contact another host: ad blockers have nothing to
  match and visitors never see which service protects the site.
- The sensor's requests are answered before any decision is asked for, so
  they cost no API requests and no time: the script is cached for a year,
  the timing and beacon requests answer 204 immediately.
- A Content-Security-Policy now only needs 'self' for the sensor.
- The decision context meta tag is named site-ctx.

## 3.5.2

- The Laravel middleware no longer sends an `X-Moonito-Ctx` response header.
  Nothing read it (the browser sensor reads the `__mo_cx` cookie), and it
  named the service to every visitor who opened their browser's developer
  tools.

## 3.5.1

- Show the browser check when Moonito allows a visitor but the site owner
  turned on "Check every new visitor" in the dashboard. The SDK says it can do
  this with `caps=check1,check2`; older versions are never sent such a check.
- A check that comes with a challenge this site turned into an allow (for
  example `challenge_action` set to `allow`) is still ignored.

## 3.5.0

- The browser check runs on the site's own URL. A capable SDK sends
  `caps=check1` and shows the check page instead of sending the visitor to
  another domain. Answers are posted back to the same URL and forwarded to
  Moonito server to server.
- `challenge_action` defaults to `follow`: do what the dashboard says.
- The browser sensor is added to HTML pages automatically (`injectSensor`),
  so one install covers both. It turns itself off when the site's
  Content-Security-Policy would block it.

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
