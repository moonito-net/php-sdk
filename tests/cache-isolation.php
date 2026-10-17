<?php

require dirname(__DIR__) . '/vendor-less-autoload.php';

use Moonito\Client;
use Moonito\Config;
use Moonito\Transport\Transport;

final class DiagnosticTransport implements Transport
{
    public $calls = 0;
    private $status;
    private $action;

    public function __construct(int $status, string $action = 'block')
    {
        $this->status = $status;
        $this->action = $action;
    }

    public function post(string $url, array $payload, array $headers, float $connectTimeout, float $timeout): array
    {
        $this->calls++;
        return ['ok' => true, 'status' => $this->status, 'error' => '', 'body' => json_encode([
            'data' => ['status' => ['need_to_block' => $this->action === 'block', 'risk' => ['decision' => $this->action]]],
        ])];
    }
}

function check(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

$root = sys_get_temp_dir() . '/moonito-cache-regression-' . bin2hex(random_bytes(8));
$server = ['HTTP_HOST' => 'example.com', 'REMOTE_ADDR' => '198.51.100.10',
    'HTTP_USER_AGENT' => 'test-browser', 'REQUEST_URI' => '/checkout', 'REQUEST_METHOD' => 'GET'];
$make = function (string $directory, string $public, string $secret, DiagnosticTransport $transport, string $endpoint = 'https://moonito.net') use ($root): Client {
    return new Client(Config::fromArray(['public_key' => $public, 'secret_key' => $secret,
        'cache_dir' => $root . '/' . $directory, 'endpoint' => $endpoint]), $transport);
};

try {
    $badTransport = new DiagnosticTransport(401);
    $validTransport = new DiagnosticTransport(200);
    $bad = $make('circuit', 'account-a', 'wrong-secret', $badTransport);
    $valid = $make('circuit', 'account-a', 'correct-secret', $validTransport);
    check($bad->evaluate($server, [])->isDegraded(), 'Invalid credentials must yield a degraded decision.');
    check($valid->evaluate($server, [])->isBlock() && $validTransport->calls === 1,
        'A failed credential prevented a valid credential from calling the API.');

    $allowTransport = new DiagnosticTransport(200, 'allow');
    $blockTransport = new DiagnosticTransport(200);
    $allow = $make('decisions', 'account-a', 'secret-a', $allowTransport);
    $block = $make('decisions', 'account-b', 'secret-b', $blockTransport);
    check($allow->evaluate($server, [])->isAllow(), 'Allow fixture failed.');
    check($allow->evaluate($server, [])->isAllow() && $allowTransport->calls === 1,
        'A credential should still reuse its own cached decision.');
    check($block->evaluate($server, [])->isBlock() && $blockTransport->calls === 1,
        'An allow from another account bypassed the API.');

    $firstTransport = new DiagnosticTransport(401);
    $secondTransport = new DiagnosticTransport(200);
    $first = $make('endpoints', 'same-key', 'same-secret', $firstTransport, 'https://first.example');
    $second = $make('endpoints', 'same-key', 'same-secret', $secondTransport, 'https://second.example');
    $first->evaluate($server, []);
    check($second->evaluate($server, [])->isBlock() && $secondTransport->calls === 1,
        'An error on another endpoint prevented a valid API call.');

    echo "PASS: credential, account, endpoint, and own-cache isolation\n";
} finally {
    if (is_dir($root)) {
        $entries = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($entries as $entry) {
            $entry->isDir() ? rmdir($entry->getPathname()) : unlink($entry->getPathname());
        }
        rmdir($root);
    }
}
