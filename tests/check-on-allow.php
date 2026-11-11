<?php
/**
 * A browser check that comes with an allow ("Check every new visitor",
 * docs/residential-proxy S1). Run: php tests/check-on-allow.php
 */
require dirname(__DIR__) . '/vendor-less-autoload.php';

use Moonito\Decision;

function expect(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

$check = ['ticket' => 'mck1.abc', 'seed' => 'a1b2c3d4e5f60718', 'bits' => 14, 'light' => true];
$response = function (string $decision, bool $withCheck = true) use ($check) {
    $data = ['status' => ['need_to_block' => $decision === 'block', 'risk' => ['decision' => $decision]]];
    if ($withCheck) {
        $data['check'] = $check;
    }
    return ['meta' => ['code' => 200], 'data' => $data];
};

// 1. The server allows and sends a check: shown, whatever the site's setting.
foreach ([Decision::FOLLOW, Decision::CHALLENGE, Decision::ALLOW, Decision::BLOCK] as $setting) {
    $d = Decision::fromResponse($response('allow'), $setting);
    expect($d->check() !== null, "allow + check ignored with challengeAction=$setting");
    expect(!$d->isBlock(), "allow + check became a block with challengeAction=$setting");
}

// 2. A challenge the site turned into an allow carries no check.
$d = Decision::fromResponse($response('challenge'), Decision::ALLOW);
expect($d->check() === null, 'a downgraded challenge kept its check');
expect(!$d->isBlock(), 'downgraded challenge blocked');

// 3. A challenge the site turned into a block is a block, no check.
$d = Decision::fromResponse($response('challenge'), Decision::BLOCK);
expect($d->check() === null && $d->isBlock(), 'challenge with block setting not a block');

// 4. A challenge followed as before.
$d = Decision::fromResponse($response('challenge'), Decision::FOLLOW);
expect($d->check() !== null && $d->isChallenge(), 'followed challenge lost its check');

// 5. A block never carries a check, and a plain allow has none.
expect(Decision::fromResponse($response('block'), Decision::FOLLOW)->check() === null, 'block kept a check');
expect(Decision::fromResponse($response('allow', false), Decision::FOLLOW)->check() === null, 'plain allow grew a check');

// 6. A v1 response (no risk block) with a check is not trusted as an allow.
$v1 = ['meta' => ['code' => 200], 'data' => ['status' => ['need_to_block' => false], 'check' => $check]];
expect(Decision::fromResponse($v1, Decision::FOLLOW)->check() === null, 'v1 response without a verdict showed a check');

echo "check-on-allow: ok\n";
