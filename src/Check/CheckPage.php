<?php

namespace Moonito\Check;

use Moonito\Challenge\PassJar;

/**
 * The browser check, shown on the site's own URL (docs/residential-proxy,
 * Phase 3).
 *
 * Everything the visitor's browser sees and talks to belongs to the site: the
 * page, the inlined script, the timing requests and the answer all go to this
 * same URL. Nothing names the vendor, because the page is the customer's.
 *
 * A POST interrupted by the check is kept in sessionStorage and sent again
 * once the visitor passes, the same way the challenge bridge does it.
 */
final class CheckPage
{
    /** Query flag for the timing requests, answered with an empty 204. */
    const PING = '__check_ping';

    /** Header the script sends with its answers. */
    const ANSWER_HEADER = 'HTTP_X_SITE_CHECK';

    /** Set for five minutes after a failed check. */
    const FAIL_COOKIE = '__check_fail';

    const MAX_FIELDS = 200;
    const MAX_VALUE = 8192;

    public static function isPing(array $server): bool
    {
        $method = strtoupper(isset($server['REQUEST_METHOD']) ? (string) $server['REQUEST_METHOD'] : 'GET');
        $query = isset($server['QUERY_STRING']) ? (string) $server['QUERY_STRING'] : '';

        return $method === 'GET' && preg_match('/(?:^|&)' . self::PING . '=1(?:&|$)/', $query) === 1;
    }

    public static function isAnswer(array $server): bool
    {
        $method = strtoupper(isset($server['REQUEST_METHOD']) ? (string) $server['REQUEST_METHOD'] : 'GET');

        return $method === 'POST' && isset($server[self::ANSWER_HEADER]) && (string) $server[self::ANSWER_HEADER] === '1';
    }

    /** The page's own URL with the check's query flags removed. */
    public static function returnUrl(array $server): string
    {
        $uri = isset($server['REQUEST_URI']) ? (string) $server['REQUEST_URI'] : '/';

        if ($uri === '' || $uri[0] !== '/' || (isset($uri[1]) && $uri[1] === '/')) {
            return '/';
        }

        $parts = explode('?', $uri, 2);

        if (!isset($parts[1])) {
            return $parts[0];
        }

        parse_str($parts[1], $query);
        unset($query[self::PING]);

        return $parts[0] . ($query ? '?' . http_build_query($query) : '');
    }

    /**
     * @param array $check the decision's check object: ticket, seed, bits
     */
    public static function html(array $check, array $server, array $post): string
    {
        $method = strtoupper(isset($server['REQUEST_METHOD']) ? (string) $server['REQUEST_METHOD'] : 'GET');
        $config = json_encode([
            't' => (string) ($check['ticket'] ?? ''),
            'z' => (string) ($check['seed'] ?? ''),
            'b' => (int) ($check['bits'] ?? 0),
        ], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);

        $resume = json_encode([
            'method' => $method,
            'action' => self::returnUrl($server),
            'fields' => $method === 'POST' ? self::flatten($post) : [],
            'upload' => $method === 'POST' && !empty($_FILES),
            'cookie' => PassJar::COOKIE,
        ], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);

        return '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
            . '<meta name="viewport" content="width=device-width,initial-scale=1">'
            . '<meta name="robots" content="noindex,nofollow"><title>Checking your browser</title>'
            . '<style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;'
            . 'font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;'
            . 'background:#f6f7f9;color:#16181d}@media(prefers-color-scheme:dark){body{background:#0f1115;color:#eceef2}}'
            . 'main{text-align:center;padding:24px;max-width:420px}</style></head>'
            . '<body><main><p id="site-check-status">Checking your browser, one moment.</p>'
            . '<noscript><p>JavaScript is required to continue. Please enable it and reload this page.</p></noscript>'
            . '</main><script>window.__siteCheck=' . $config . ';' . self::resumeScript($resume) . '</script>'
            . '<script>' . CheckScript::SOURCE . '</script></body></html>';
    }

    /** Keeps an interrupted form and sends it again after a pass. */
    private static function resumeScript(string $resume): string
    {
        return <<<JS
(function(){
  var R = {$resume}, KEY = 'site_check_resume';
  if (R.method === 'POST' && R.fields.length) {
    try { sessionStorage.setItem(KEY, JSON.stringify({a: R.action, f: R.fields, t: Date.now()})); } catch (e) {}
  }
  window.__siteCheckDone = function (res) {
    var saved = null;
    try { saved = JSON.parse(sessionStorage.getItem(KEY) || 'null'); sessionStorage.removeItem(KEY); } catch (e) {}
    if (!res.passed || !saved || !saved.t || (Date.now() - saved.t) > 600000) {
      if (res.passed && R.upload) {
        document.getElementById('site-check-status').textContent = 'Verified. Your file was not kept, so please choose it again.';
      }
      location.replace(res.next);
      return;
    }
    var form = document.createElement('form');
    form.method = 'POST';
    form.action = saved.a;
    form.style.display = 'none';
    for (var i = 0; i < saved.f.length; i++) {
      var input = document.createElement('input');
      input.type = 'hidden';
      input.name = saved.f[i].n;
      input.value = saved.f[i].v;
      form.appendChild(input);
    }
    document.body.appendChild(form);
    form.submit();
  };
})();
JS;
    }

    private static function flatten(array $post, string $prefix = ''): array
    {
        $out = [];

        foreach ($post as $key => $value) {
            if (count($out) >= self::MAX_FIELDS) {
                break;
            }

            $name = $prefix === '' ? (string) $key : $prefix . '[' . $key . ']';

            if (is_array($value)) {
                foreach (self::flatten($value, $name) as $nested) {
                    $out[] = $nested;
                }

                continue;
            }

            if (is_scalar($value) || $value === null) {
                $out[] = ['n' => $name, 'v' => substr((string) $value, 0, self::MAX_VALUE)];
            }
        }

        return $out;
    }
}
