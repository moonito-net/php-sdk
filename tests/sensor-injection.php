<?php
/**
 * Sensor injection (docs/residential-proxy, M11 and AC11).
 * Run: php tests/sensor-injection.php
 */
require dirname(__DIR__) . '/vendor-less-autoload.php';

use Moonito\Sensor\Injector;

function expect(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

$blocked = 0;
$injector = function () use (&$blocked) {
    return new Injector('pub_123', 'https://moonito.net', function () use (&$blocked) { $blocked++; });
};

$page = "<!DOCTYPE html><html><head><title>Shop</title></head><body><h1>Hi</h1></body></html>";

// 1. A plain HTML page gets the tag once, right before </head>.
$r = $injector()->process($page, ['Content-Type: text/html; charset=UTF-8'], 200);
expect($r['outcome'] === Injector::INJECTED, 'plain page not injected');
expect(substr_count($r['html'], 'moonito-net/sensor@' . Injector::VERSION . '/t.js') === 1, 'tag not present exactly once');
expect(strpos($r['html'], Injector::MARKER . '></script></head>') !== false, 'tag not placed before </head>');
expect(strpos($r['html'], 'integrity="' . Injector::SRI . '"') !== false, 'SRI missing');
expect(strpos($r['html'], 'data-key="pub_123"') !== false, 'public key missing');
expect(strpos($r['html'], 'data-endpoint="https://moonito.net"') !== false, 'endpoint not passed to the sensor');

// 2. No Content-Type header but an HTML body (PHP's default) is still a page.
$r = $injector()->process($page, [], 200);
expect($r['outcome'] === Injector::INJECTED, 'page without Content-Type header not injected');

// 3. Things that are not a page pass through byte for byte.
$untouched = [
    'json' => ['{"a":1}', ['Content-Type: application/json'], 200],
    'download' => [$page, ['Content-Type: text/html', 'Content-Disposition: attachment; filename="a.html"'], 200],
    'gzip header' => [$page, ['Content-Type: text/html', 'Content-Encoding: gzip'], 200],
    'gzip bytes' => [gzencode($page), ['Content-Type: text/html'], 200],
    'redirect' => [$page, ['Content-Type: text/html', 'Location: /x'], 302],
    'not found' => [$page, ['Content-Type: text/html'], 404],
    'no content' => ['', [], 204],
    'fragment' => ['<div>partial</div>', [], 200],
    'already pasted' => [str_replace('</head>', '<script defer src="https://cdn.jsdelivr.net/gh/moonito-net/sensor@1.0.0/t.js" data-key="k"></script></head>', $page), ['Content-Type: text/html'], 200],
];
foreach ($untouched as $name => [$body, $headers, $status]) {
    $r = $injector()->process($body, $headers, $status);
    expect($r['html'] === $body, 'modified a response it must not touch: ' . $name);
}

// 4. No </head>: inserted right after <body>.
$r = $injector()->process('<html><body class="x"><p>a</p></body></html>', [], 200);
expect(strpos($r['html'], '<body class="x"><script') !== false, 'not inserted after <body>');

// 5. Content-Security-Policy.
$blocked = 0;
$r = $injector()->process($page, ['Content-Type: text/html', "Content-Security-Policy: default-src 'self'"], 200);
expect($r['outcome'] === Injector::BLOCKED && $r['html'] === $page && $blocked === 1, 'strict CSP was not respected');

$r = $injector()->process($page, ['Content-Type: text/html', "Content-Security-Policy: script-src 'self' https://cdn.jsdelivr.net; connect-src 'self' https://moonito.net"], 200);
expect($r['outcome'] === Injector::INJECTED, 'CSP that allows jsDelivr and Moonito was refused');

$r = $injector()->process($page, ['Content-Type: text/html', "Content-Security-Policy: script-src 'self' https://cdn.jsdelivr.net; connect-src 'self'"], 200);
expect($r['outcome'] === Injector::BLOCKED, 'CSP that blocks telemetry was ignored');

$r = $injector()->process($page, ['Content-Type: text/html', "Content-Security-Policy: script-src 'nonce-abc123' 'strict-dynamic'"], 200);
expect($r['outcome'] === Injector::INJECTED && strpos($r['html'], 'nonce="abc123"') !== false, 'nonce policy not honoured');

$r = $injector()->process(str_replace('<head>', '<head><meta http-equiv="Content-Security-Policy" content="script-src \'self\'">', $page), ['Content-Type: text/html'], 200);
expect($r['outcome'] === Injector::BLOCKED, 'meta CSP was not respected');

$r = $injector()->process($page, ['Content-Type: text/html', "Content-Security-Policy-Report-Only: default-src 'none'"], 200);
expect($r['outcome'] === Injector::INJECTED, 'report-only CSP must not block');

// 6. A custom endpoint is passed to the sensor.
$r = (new Injector('pub_123', 'https://api.example.test/'))->process($page, [], 200);
expect(strpos($r['html'], 'data-endpoint="https://api.example.test"') !== false, 'custom endpoint not passed');

// 7. Request side: only page requests from a browser.
expect(Injector::wantsPage(['REQUEST_METHOD' => 'GET', 'HTTP_ACCEPT' => 'text/html,application/xhtml+xml']) === (PHP_SAPI !== 'cli'), 'browser page request');
expect(!Injector::wantsPage(['REQUEST_METHOD' => 'HEAD']), 'HEAD must be skipped');
expect(!Injector::wantsPage(['REQUEST_METHOD' => 'GET', 'HTTP_X_REQUESTED_WITH' => 'XMLHttpRequest']), 'AJAX must be skipped');
expect(!Injector::wantsPage(['REQUEST_METHOD' => 'GET', 'HTTP_ACCEPT' => 'application/json']), 'JSON request must be skipped');
expect(!Injector::wantsPage(['REQUEST_METHOD' => 'GET', 'HTTP_SEC_FETCH_DEST' => 'image']), 'image request must be skipped');

echo "sensor-injection: all checks passed\n";
