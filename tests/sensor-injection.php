<?php
/**
 * Sensor injection (docs/residential-proxy, M11 and AC11).
 * Run: php tests/sensor-injection.php
 */
require dirname(__DIR__) . '/vendor-less-autoload.php';

use Moonito\Sensor\Injector;
use Moonito\Sensor\Relay;
use Moonito\Sensor\SensorScript;

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
$param = Relay::param('pub_123');
expect(substr_count($r['html'], 'src="?' . $param . '=s&amp;v=' . SensorScript::VERSION . '"') === 1, 'relay tag not present exactly once');
expect(strpos($r['html'], Injector::MARKER . '></script></head>') !== false, 'tag not placed before </head>');
expect(strpos($r['html'], 'data-key="pub_123"') !== false, 'public key missing');
expect(strpos($r['html'], 'data-p="' . $param . '"') !== false, 'relay parameter not passed to the sensor');
expect(stripos($r['html'], 'moonito') === false && strpos($r['html'], 'jsdelivr') === false, 'the page names an outside host or the service');

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
// The sensor is served from the site itself, so 'self' is all it needs.
$r = $injector()->process($page, ['Content-Type: text/html', "Content-Security-Policy: default-src 'self'"], 200);
expect($r['outcome'] === Injector::INJECTED, "a 'self' policy was refused");

$r = $injector()->process($page, ['Content-Type: text/html', "Content-Security-Policy: script-src https://cdn.example.com; connect-src 'self'"], 200);
expect($r['outcome'] === Injector::BLOCKED && $r['html'] === $page && $blocked === 1, "a policy without 'self' for scripts was not respected");

$r = $injector()->process($page, ['Content-Type: text/html', "Content-Security-Policy: script-src 'self'; connect-src 'none'"], 200);
expect($r['outcome'] === Injector::BLOCKED, 'a policy that blocks the beacon was ignored');

$r = $injector()->process($page, ['Content-Type: text/html', "Content-Security-Policy: script-src 'nonce-abc123' 'strict-dynamic'"], 200);
expect($r['outcome'] === Injector::INJECTED && strpos($r['html'], 'nonce="abc123"') !== false, 'nonce policy not honoured');

$r = $injector()->process(str_replace('<head>', '<head><meta http-equiv="Content-Security-Policy" content="script-src \'self\'">', $page), ['Content-Type: text/html'], 200);
expect($r['outcome'] === Injector::BLOCKED, 'meta CSP was not respected');

$r = $injector()->process($page, ['Content-Type: text/html', "Content-Security-Policy-Report-Only: default-src 'none'"], 200);
expect($r['outcome'] === Injector::INJECTED, 'report-only CSP must not block');

// 5b. The page's own path goes into the tag, so the sensor always comes back
// to a URL that reaches this SDK (a <base href> or an SPA route cannot move it).
$r = (new Injector('pub_123', 'https://moonito.net'))->forPath('/shop/item')->process($page, [], 200);
expect(strpos($r['html'], 'src="/shop/item?' . $param . '=s&amp;v=') !== false && strpos($r['html'], 'data-endpoint="/shop/item"') !== false, 'page path not written into the tag');
expect(Relay::pathOf('/shop/item?id=5') === '/shop/item' && Relay::pathOf('x"><script>') === '/' && Relay::pathOf('') === '/', 'unsafe paths not refused');

// 6. The relay: which requests are the sensor's, per site.
$get = function (string $query, string $method = 'GET') { return ['REQUEST_METHOD' => $method, 'QUERY_STRING' => $query]; };
expect(Relay::kind($get($param . '=s&v=1.2.0'), 'pub_123') === 's', 'script request not recognised');
expect(Relay::kind($get('a=1&' . $param . '=p'), 'pub_123') === 'p', 'ping request not recognised');
expect(Relay::kind($get($param . '=t', 'POST'), 'pub_123') === 't', 'beacon not recognised');
expect(Relay::kind($get($param . '=t'), 'pub_123') === null, 'a GET beacon must not be handled');
expect(Relay::kind($get($param . '=s', 'POST'), 'pub_123') === null, 'a POST script request must not be handled');
expect(Relay::kind($get('__vt=s'), 'pub_123') === null, 'a generic parameter must not be handled');
expect(Relay::kind($get($param . '=s'), 'another_key') === null, 'another site\'s parameter must not be handled');
expect(Relay::param('pub_123') !== Relay::param('pub_456'), 'two sites share a parameter');
expect(preg_match('/^_[0-9a-f]{7}$/', $param) === 1, 'parameter has an unexpected shape');
expect(stripos(SensorScript::SOURCE, 'moonito') === false, 'the served script names the service');

// 7. A beacon is forwarded server to server with the visitor's address.
$sent = [];
$transport = new class($sent) implements Moonito\Transport\Transport {
    private $sent;
    public function __construct(array &$sent) { $this->sent = &$sent; }
    public function post(string $url, array $payload, array $headers, float $connectTimeout, float $timeout): array
    {
        $this->sent[] = compact('url', 'payload', 'headers', 'timeout');
        return ['ok' => true, 'status' => 202, 'body' => ''];
    }
};
$client = new Moonito\Client(Moonito\Config::fromArray(['public_key' => 'pub_123', 'secret_key' => 'sec_456']), $transport);
$client->relayBeacon(['REMOTE_ADDR' => '203.0.113.9'], '{"k":"pub_123"}');
expect(count($sent) === 1 && substr($sent[0]['url'], -strlen('/api/v2/telemetry/relay')) === '/api/v2/telemetry/relay', 'beacon not forwarded to the relay endpoint');
expect($sent[0]['payload'] === ['ip' => '203.0.113.9', 'p' => '{"k":"pub_123"}'], 'beacon or visitor address altered');
expect(in_array('X-Secret-Key: sec_456', $sent[0]['headers'], true), 'relay not authenticated');
expect($sent[0]['timeout'] <= 2.0, 'relay may hold the worker too long');
$client->relayBeacon(['REMOTE_ADDR' => '203.0.113.9'], str_repeat('x', Relay::MAX_BEACON + 1));
$client->relayBeacon(['REMOTE_ADDR' => '203.0.113.9'], '');
expect(count($sent) === 1, 'an empty or oversized beacon was forwarded');

// 8. Request side: only page requests from a browser.
expect(Injector::wantsPage(['REQUEST_METHOD' => 'GET', 'HTTP_ACCEPT' => 'text/html,application/xhtml+xml']) === (PHP_SAPI !== 'cli'), 'browser page request');
expect(!Injector::wantsPage(['REQUEST_METHOD' => 'HEAD']), 'HEAD must be skipped');
expect(!Injector::wantsPage(['REQUEST_METHOD' => 'GET', 'HTTP_X_REQUESTED_WITH' => 'XMLHttpRequest']), 'AJAX must be skipped');
expect(!Injector::wantsPage(['REQUEST_METHOD' => 'GET', 'HTTP_ACCEPT' => 'application/json']), 'JSON request must be skipped');
expect(!Injector::wantsPage(['REQUEST_METHOD' => 'GET', 'HTTP_SEC_FETCH_DEST' => 'image']), 'image request must be skipped');

echo "sensor-injection: all checks passed\n";
