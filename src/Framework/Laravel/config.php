<?php

return [
    'public_key' => env('MOONITO_PUBLIC_KEY', ''),
    'secret_key' => env('MOONITO_SECRET_KEY', ''),
    'endpoint' => env('MOONITO_ENDPOINT', 'https://moonito.net'),
    'enabled' => env('MOONITO_ENABLED', true),

    'timeout' => env('MOONITO_TIMEOUT', 2.0),
    'connect_timeout' => env('MOONITO_CONNECT_TIMEOUT', 1.0),

    // Open means a Moonito outage never becomes a site outage.
    'fail_mode' => env('MOONITO_FAIL_MODE', 'open'),

    // Leave empty unless the app sits behind a proxy on a public address.
    // Laravel's own TrustProxies has usually already handled this.
    'trusted_proxies' => [],
    'cloudflare' => env('MOONITO_CLOUDFLARE', false),

    'cache_ttl' => env('MOONITO_CACHE_TTL', 60),
    'unwanted_visitor_to' => env('MOONITO_UNWANTED_TO', ''),
    'challenge_action' => env('MOONITO_CHALLENGE_ACTION', 'allow'),
    'debug_log' => env('MOONITO_DEBUG_LOG'),
];
