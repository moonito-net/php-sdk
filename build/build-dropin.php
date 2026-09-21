<?php
/**
 * Generates the no-Composer drop-in from the Composer package.
 *
 * Two hand-maintained copies of the same library diverge within one release.
 * A build step does not. This strips namespaces, prefixes class names, orders
 * the files by dependency and concatenates them into one file that works on a
 * shared host with FTP and nothing else.
 *
 * Nothing it emits names the vendor. A file called moonito.php full of
 * Moonito_ classes tells anyone who gets a directory listing exactly which
 * product is protecting the site and therefore exactly which bypasses to go
 * and read about. The names below are deliberately dull and are build
 * parameters, so a customer who wants different ones can have them.
 *
 * One thing cannot be hidden and should not be oversold: the API endpoint is
 * in the generated code, because the library has to know where to call and
 * burying that would make a support call impossible to answer.
 *
 * Usage: php build/build-dropin.php [output-dir] [--bundle=engine] [--prefix=Guard_]
 */

$root = dirname(__DIR__);
$args = array_values(array_filter(array_slice($argv, 1), fn ($a) => strpos($a, '--') !== 0));
$opts = [];

foreach (array_slice($argv, 1) as $arg) {
    if (preg_match('/^--([a-z]+)=(.+)$/', $arg, $m)) {
        $opts[$m[1]] = $m[2];
    }
}

$out = $args[0] ?? dirname($root) . '/php-lib/lib';
$bundle = preg_replace('/[^a-z0-9_]/', '', strtolower($opts['bundle'] ?? 'engine'));
$prefix = preg_replace('/[^A-Za-z0-9_]/', '', $opts['prefix'] ?? 'Guard_');

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
    'src/Challenge/PassJar.php',
    'src/Challenge/Bridge.php',
    'src/Enforcer/Enforcer.php',
    'src/Client.php',
];

$classMap = [];

foreach ($order as $file) {
    $source = file_get_contents($root . '/' . $file);

    if (preg_match('/\b(?:final\s+)?(?:class|interface)\s+([A-Za-z0-9_]+)/', $source, $m)) {
        $classMap[$m[1]] = $prefix . $m[1];
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

/**
 * Strip every comment from the bundle.
 *
 * Two reasons, and the second is the one that was asked for. The file is
 * generated and marked do-not-edit, so nobody reads it to understand the
 * code; the package is where the reasoning lives. And the comments are the
 * only place the vendor's name appears outside the handful of strings that
 * are protocol and cannot move.
 *
 * Done with the tokeniser rather than a regular expression, because "https://"
 * inside a string looks exactly like the start of a comment to a regex.
 */
$stripped = '';

foreach (token_get_all('<?php ' . $body) as $token) {
    if (is_array($token)) {
        if ($token[0] === T_COMMENT || $token[0] === T_DOC_COMMENT) {
            // Keep the newlines a block comment spanned, so line numbers in a
            // stack trace still point somewhere sensible.
            $stripped .= str_repeat("\n", substr_count($token[1], "\n"));

            continue;
        }

        $stripped .= $token[1];

        continue;
    }

    $stripped .= $token;
}

$body = preg_replace('/^<\?php /', '', $stripped, 1);
$body = preg_replace("/\n{3,}/", "\n\n", $body);

$header = <<<HEAD
<?php
/**
 * Traffic filtering runtime, version 3.1.0.
 *
 * GENERATED FILE. Do not edit.
 * Rebuilt from source; changes made here are lost on the next build.
 *
 * Install: include_once(__DIR__ . '/lib/detector.php'); on the first line of
 * the file you are protecting, before anything is sent to the browser.
 */

HEAD;

if (!is_dir($out)) {
    mkdir($out, 0755, true);
}

file_put_contents($out . '/' . $bundle . '.php', $header . $body);

$detector = <<<DETECTOR
<?php
/**
 * Traffic filtering, version 3.1.0.
 *
 * Install: include_once(__DIR__ . '/lib/detector.php'); on the first line of
 * the file you are protecting, before anything is sent to the browser.
 *
 * Settings live in config.php. Everything optional already has a safe
 * default, so a config.php from an older version keeps working untouched.
 */

include_once __DIR__ . '/config.php';
include_once __DIR__ . '/{$bundle}.php';

if (!function_exists('site_protect')) {
    function site_protect()
    {
        // The five names every existing config.php already uses, plus the
        // optional ones. All of them are neutral: nothing here says who wrote
        // the library or who it calls.
        global \$apiPublicKey, \$apiSecretKey, \$isProtected,
               \$unwantedVisitorTo, \$unwantedVisitorAction,
               \$guardTimeout, \$guardConnectTimeout, \$guardFailMode,
               \$guardTrustedProxies, \$guardCloudflare, \$guardSkipPaths,
               \$guardCacheTtl, \$guardCacheDir, \$guardDebugLog,
               \$guardChallengeAction, \$guardIdentityCookie, \$guardEndpoint;

        if (empty(\$isProtected)) {
            return null;
        }

        \$pick = function (\$value, \$fallback) {
            return isset(\$value) ? \$value : \$fallback;
        };

        try {
            \$config = {$prefix}Config::fromArray(array(
                'public_key' => isset(\$apiPublicKey) ? \$apiPublicKey : '',
                'secret_key' => isset(\$apiSecretKey) ? \$apiSecretKey : '',
                'endpoint' => \$pick(\$guardEndpoint, 'https://moonito.net'),
                'unwanted_visitor_to' => isset(\$unwantedVisitorTo) ? \$unwantedVisitorTo : '',
                'unwanted_visitor_action' => isset(\$unwantedVisitorAction) ? \$unwantedVisitorAction : 1,
                'timeout' => \$pick(\$guardTimeout, 2.0),
                'connect_timeout' => \$pick(\$guardConnectTimeout, 1.0),
                'fail_mode' => \$pick(\$guardFailMode, 'open'),
                'trusted_proxies' => \$pick(\$guardTrustedProxies, array()),
                'cloudflare' => \$pick(\$guardCloudflare, false),
                'cache_ttl' => \$pick(\$guardCacheTtl, 60),
                'cache_dir' => \$pick(\$guardCacheDir, null),
                'debug_log' => \$pick(\$guardDebugLog, null),
                'challenge_action' => \$pick(\$guardChallengeAction, 'allow'),
                'identity_cookie' => \$pick(\$guardIdentityCookie, true),
            ));

            \$skip = \$pick(\$guardSkipPaths, null);

            if (is_array(\$skip)) {
                \$config->skipPaths = \$skip;
            }

            \$client = new {$prefix}Client(\$config);

            return \$client->protect();
        } catch (\Throwable \$e) {
            // Fail open. A protection outage must not become a site outage.
            return null;
        } catch (\Exception \$e) {
            return null;
        }
    }
}

\$siteDecision = site_protect();
DETECTOR;

file_put_contents($out . '/detector.php', $detector);

echo "Built:\n";
echo "  " . $out . "/" . $bundle . ".php  (" . number_format(strlen($header . $body)) . " bytes)\n";
echo "  " . $out . "/detector.php\n";
