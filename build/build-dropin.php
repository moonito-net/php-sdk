<?php
/**
 * Generates the no-Composer drop-in from the Composer package.
 *
 * Two hand-maintained copies of the same library diverge within one release.
 * A build step does not. This strips namespaces, prefixes class names, orders
 * the files by dependency and concatenates them into one file that works on a
 * shared host with FTP and nothing else.
 *
 * Usage: php build/build-dropin.php [output-dir]
 */

$root = dirname(__DIR__);
$out = $argv[1] ?? dirname($root) . '/php-lib/lib';

// Dependency order. Classes must be declared before anything that extends or
// type-hints them at load time.
$order = [
    'src/Config.php',
    'src/Context/CloudflareRanges.php',
    'src/Context/IpResolver.php',
    'src/Cache/Store.php',
    'src/CircuitBreaker.php',
    'src/Decision.php',
    'src/Transport/Transport.php',
    'src/Transport/CurlTransport.php',
    'src/Transport/StreamTransport.php',
    'src/Identity/TokenJar.php',
    'src/Enforcer/Enforcer.php',
    'src/Client.php',
];

$classMap = [];

foreach ($order as $file) {
    $source = file_get_contents($root . '/' . $file);

    if (preg_match('/\b(?:final\s+)?(?:class|interface)\s+([A-Za-z0-9_]+)/', $source, $m)) {
        $classMap[$m[1]] = 'Moonito_' . $m[1];
    }
}

$body = '';

foreach ($order as $file) {
    $source = file_get_contents($root . '/' . $file);

    // Strip the opening tag, the namespace and every use statement.
    $source = preg_replace('/^<\?php\s*/', '', $source, 1);
    $source = preg_replace('/^namespace\s+[^;]+;\s*/m', '', $source);
    $source = preg_replace('/^use\s+[^;]+;\s*/m', '', $source);

    // Rename classes and drop the leading backslashes that qualified them.
    foreach ($classMap as $short => $prefixed) {
        $source = preg_replace('/\\\\?\bMoonito\\\\(?:[A-Za-z0-9_]+\\\\)*' . $short . '\b/', $prefixed, $source);
        $source = preg_replace('/(?<![A-Za-z0-9_\\\\$>])' . $short . '\b/', $prefixed, $source);
    }

    $body .= "\n" . trim($source) . "\n";
}

$header = <<<'HEAD'
<?php
/**
 * Moonito PHP Library 3.0.0, drop-in edition.
 *
 * GENERATED FILE. Do not edit.
 * Built from the moonito/php-sdk Composer package by build/build-dropin.php.
 * Edit the package and rebuild; changes made here are lost on the next build.
 *
 * Install: include_once(__DIR__ . '/lib/detector.php'); on the first line of
 * the file you are protecting, before anything is sent to the browser.
 */

HEAD;

if (!is_dir($out)) {
    mkdir($out, 0755, true);
}

file_put_contents($out . '/moonito.php', $header . $body);

$detector = <<<'DETECTOR'
<?php
/**
 * Moonito PHP Library 3.0.0
 *
 * Install: include_once(__DIR__ . '/lib/detector.php'); on the first line of
 * the file you are protecting, before anything is sent to the browser.
 *
 * Configuration lives in config.php. Every setting added since 2.0.1 is
 * optional with a safe default, so an older config.php keeps working.
 */

include_once __DIR__ . '/config.php';
include_once __DIR__ . '/moonito.php';

if (!function_exists('moonito_protect')) {
    function moonito_protect()
    {
        global $apiPublicKey, $apiSecretKey, $isProtected,
               $unwantedVisitorTo, $unwantedVisitorAction,
               $moonitoTimeout, $moonitoConnectTimeout, $moonitoFailMode,
               $moonitoTrustedProxies, $moonitoCloudflare, $moonitoSkipPaths,
               $moonitoCacheTtl, $moonitoCacheDir, $moonitoDebugLog,
               $moonitoChallengeAction, $moonitoIdentityCookie, $moonitoEndpoint;

        if (empty($isProtected)) {
            return null;
        }

        try {
            $config = Moonito_Config::fromArray(array(
                'public_key' => isset($apiPublicKey) ? $apiPublicKey : '',
                'secret_key' => isset($apiSecretKey) ? $apiSecretKey : '',
                'endpoint' => isset($moonitoEndpoint) ? $moonitoEndpoint : 'https://moonito.net',
                'unwanted_visitor_to' => isset($unwantedVisitorTo) ? $unwantedVisitorTo : '',
                'unwanted_visitor_action' => isset($unwantedVisitorAction) ? $unwantedVisitorAction : 1,
                'timeout' => isset($moonitoTimeout) ? $moonitoTimeout : 2.0,
                'connect_timeout' => isset($moonitoConnectTimeout) ? $moonitoConnectTimeout : 1.0,
                'fail_mode' => isset($moonitoFailMode) ? $moonitoFailMode : 'open',
                'trusted_proxies' => isset($moonitoTrustedProxies) ? $moonitoTrustedProxies : array(),
                'cloudflare' => isset($moonitoCloudflare) ? $moonitoCloudflare : false,
                'cache_ttl' => isset($moonitoCacheTtl) ? $moonitoCacheTtl : 60,
                'cache_dir' => isset($moonitoCacheDir) ? $moonitoCacheDir : null,
                'debug_log' => isset($moonitoDebugLog) ? $moonitoDebugLog : null,
                'challenge_action' => isset($moonitoChallengeAction) ? $moonitoChallengeAction : 'allow',
                'identity_cookie' => isset($moonitoIdentityCookie) ? $moonitoIdentityCookie : true,
            ));

            if (isset($moonitoSkipPaths) && is_array($moonitoSkipPaths)) {
                $config->skipPaths = $moonitoSkipPaths;
            }

            $client = new Moonito_Client($config);

            return $client->protect();
        } catch (\Throwable $e) {
            // Fail open. A protection outage must not become a site outage.
            return null;
        } catch (\Exception $e) {
            return null;
        }
    }
}

$moonitoDecision = moonito_protect();
DETECTOR;

file_put_contents($out . '/detector.php', $detector);

echo "Built:\n";
echo "  " . $out . "/moonito.php  (" . number_format(strlen($header . $body)) . " bytes)\n";
echo "  " . $out . "/detector.php\n";
