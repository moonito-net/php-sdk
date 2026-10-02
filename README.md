# Moonito PHP SDK

> Stop bad bots before your page is built, not after. Server side protection for PHP, with one line to install and nothing that can take your site down.

[![Packagist](https://img.shields.io/badge/composer-moonito%2Fphp--sdk-orange.svg)](https://packagist.org/packages/moonito/php-sdk)
[![PHP](https://img.shields.io/badge/php-7.4%20to%208.4-blue.svg)](https://www.php.net/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Website](https://img.shields.io/badge/Website-moonito.net-blue)](https://moonito.net)

## Why server side

A browser snippet can only act after your page has been sent. That is fine for analytics and for moving unwanted visitors along, and Moonito has [a snippet](https://github.com/moonito-net/lib) for exactly that.

It is not fine when the thing you are protecting costs you money: a checkout, a signup form, a paid campaign landing page, an API. A scraper that ignores JavaScript never runs a snippet. This SDK makes the decision before a single byte of your page is generated, so the visitor you did not want never sees it.

**What you get:**

- A decision before your page renders, in about two milliseconds of your own code
- Rotating residential and mobile proxy detection, not just an IP blocklist
- An optional interactive challenge for the visitors you are unsure about
- Works on shared hosting with FTP and no Composer
- Fails open by design, so a problem on our side is never a problem on your site

## Install

### Composer

```bash
composer require moonito/php-sdk
```

### Shared hosting, no Composer

Download the release zip, upload the `lib` folder, and add one line to the top of the file you are protecting. No autoloader, no build step. That drop-in is generated from this same source, so it never drifts from the Composer version.

## Use it

```php
use Moonito\Client;

$moonito = Client::fromArray([
    'public_key' => getenv('MOONITO_PUBLIC_KEY'),
    'secret_key' => getenv('MOONITO_SECRET_KEY'),
]);

$moonito->protect();   // blocks and redirects if needed, otherwise returns
```

That is the whole integration. Put it above everything else in your entry point.

If you would rather decide for yourself:

```php
$decision = $moonito->evaluate();

if ($decision->isBlock()) {
    $moonito->enforce($decision);       // does not return
}

if ($decision->score() > 70) {
    $order->flagForReview($decision->reasons());
}
```

### Laravel

The service provider registers itself. Publish the config and add the middleware:

```bash
php artisan vendor:publish --provider="Moonito\Framework\Laravel\MoonitoServiceProvider"
```

```php
// app/Http/Kernel.php
protected $middlewareGroups = [
    'web' => [
        \Moonito\Framework\Laravel\MoonitoMiddleware::class,
        // ...
    ],
];
```

### Any PSR-15 framework

```php
$app->add(new Moonito\Framework\Psr15\MoonitoMiddleware($config));
```

## Settings

Every setting has a default that is safe, meaning it never makes your site slower, less available or less correct than not installing this at all. Anything that trades availability for protection is opt in.

| Setting | Default | What it does |
|---|---|---|
| `public_key`, `secret_key` | none | From your Moonito dashboard |
| `timeout` | `0` | Seconds to wait for a decision. `0` waits for as long as the API takes, so no visitor is let through unchecked |
| `connect_timeout` | `10.0` | Seconds to reach the server. Never cuts into the time the API spends deciding |
| `fail_mode` | `open` | `open` lets visitors through when the check cannot run. `closed` blocks them |
| `cache_ttl` | `60` | Seconds an allow may be reused. Blocks are never cached |
| `trusted_proxies` | `[]` | Proxies whose forwarded headers may be believed |
| `cloudflare` | `true` | Trust `CF-Connecting-IP` only from Cloudflare's published ranges, so it cannot be forged |
| `skip_paths` | assets | Requests that skip the check entirely |
| `challenge_action` | `allow` | `allow`, `block`, or `challenge`. See below |
| `unwanted_visitor_to` | `https://google.com` | Where blocked visitors go |
| `identity_cookie` | `true` | Keep a first party visitor identity |

## The challenge

Set `challenge_action` to `challenge` and visitors the engine is unsure about get an interactive check instead of a guess.

```php
$moonito = Client::fromArray([
    'public_key'       => getenv('MOONITO_PUBLIC_KEY'),
    'secret_key'       => getenv('MOONITO_SECRET_KEY'),
    'challenge_action' => 'challenge',
]);
```

Four things are worth knowing about how it works, because they are the parts people usually have to build themselves:

**Your form submission survives it.** If a visitor is challenged halfway through a POST, the body is held on your own domain, never sent to Moonito, and replayed automatically once they pass. Nobody loses a filled in checkout.

**The pass never reaches your logs.** It comes back in the URL fragment rather than the query string, so it stays out of your access logs, your analytics, and the Referer header on the next link your visitor clicks.

**It cannot loop.** A visitor holding a valid pass is never sent back to the check, on either side of the wire. That is the failure mode an interstitial has, and it is closed by construction rather than by care.

**The pass is verified locally.** Your secret key signs it, so the SDK checks it with one hash instead of another API call. No added latency, no extra request on your bill.

The default stays `allow` when you upgrade. Turning a scored challenge into something your visitors actually see is your decision, not a side effect of taking a release.

## Getting the client IP right

Cloudflare is recognised automatically: `CF-Connecting-IP` is read only when the request arrives from one of Cloudflare's published ranges. If your site is behind a load balancer or another reverse proxy on a public address, tell the SDK:

```php
'trusted_proxies' => ['203.0.113.10'],
```

Without this, the SDK uses the address that actually connected, which is your proxy. With it, forwarded headers are read only from proxies you named, walking the chain right to left. Believing a forwarded header from an untrusted source is how IP filtering gets bypassed, so it is off until you say otherwise.

## What happens when something goes wrong

Nothing, as far as your visitors are concerned. That is the design goal.

- **The API is slow.** The SDK waits for the answer, so a slow decision is still a decision. Set `timeout` if you would rather serve an unchecked page than a slow one.
- **The API is down.** A circuit breaker stops trying, so an outage costs nothing per page view instead of a timeout per page view.
- **Your keys are wrong.** The circuit opens for five minutes rather than hammering the API, and the reason goes to your debug log.
- **Anything unexpected.** `evaluate()` returns a decision with `isDegraded()` set. It does not throw into your code and it never prints a warning above your doctype.

## Requirements

PHP 7.4 or newer. cURL if you have it, streams if you do not. No other dependencies.

## Support

- Website: [moonito.net](https://moonito.net)
- Guides: [moonito.net/usage-guides](https://moonito.net/usage-guides)
- Issues: [github.com/moonito-net/php-sdk/issues](https://github.com/moonito-net/php-sdk/issues)

## License

MIT, (c) 2025 [Moonito](https://moonito.net)

---

**Moonito. Stop bad bots. Start accurate web analytics.**
