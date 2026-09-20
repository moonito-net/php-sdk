<?php

namespace Moonito\Challenge;

/**
 * The page that stands between the customer's site and the interstitial.
 *
 * It is served from the customer's own origin, and that is the entire point.
 * The visitor's half-finished form submission stays on the site they were
 * submitting it to. Moonito never receives it, never stores it, and never has
 * to explain in a DPA why somebody else's checkout bodies passed through.
 *
 * One page handles both directions:
 *
 *   outbound  no pass in the URL. Stash the POST fields in sessionStorage,
 *             then send the visitor to the interstitial.
 *   return    the interstitial sent them back with the pass in the fragment.
 *             Write it as a cookie, drop the fragment, restore the stashed
 *             fields and resubmit.
 *
 * The pass rides in the fragment rather than the query string so it never
 * reaches the customer's access logs, their analytics, or a Referer header.
 * The cost is that only JavaScript can see it, which is acceptable here
 * because solving a CAPTCHA already required JavaScript.
 *
 * What this cannot preserve is a file upload. There is no way to put a file
 * back into a form from script, so an upload interrupted by a challenge has to
 * be chosen again. That is stated plainly to the visitor rather than silently
 * dropped.
 */
final class Bridge
{
    /** Guard against stuffing a megabyte of form data into sessionStorage. */
    const MAX_FIELDS = 200;
    const MAX_VALUE = 8192;

    /** Does not return. */
    public function render(string $challengeUrl, array $server, array $post): void
    {
        if (headers_sent()) {
            // Output has begun, so the page is half rendered and neither a
            // redirect nor a clean interstitial is possible. Letting the page
            // finish is better than printing a broken one on top of it.
            return;
        }

        header('HTTP/1.1 200 OK');
        header('Content-Type: text/html; charset=utf-8');
        header('Cache-Control: no-store, private');
        header('X-Robots-Tag: noindex, nofollow');
        header('Referrer-Policy: no-referrer');

        echo $this->html($challengeUrl, $server, $post);
        exit;
    }

    public function html(string $challengeUrl, array $server, array $post): string
    {
        $method = isset($server['REQUEST_METHOD']) ? strtoupper($server['REQUEST_METHOD']) : 'GET';
        $uri = isset($server['REQUEST_URI']) ? $server['REQUEST_URI'] : '/';

        $fields = $method === 'POST' ? $this->flatten($post) : [];
        $hasUpload = $method === 'POST' && !empty($_FILES);

        $data = json_encode([
            'challenge' => $challengeUrl,
            'method' => $method,
            'action' => $uri,
            'fields' => $fields,
            'cookie' => PassJar::COOKIE,
            'upload' => $hasUpload,
        ], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);

        return '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
            . '<meta name="viewport" content="width=device-width,initial-scale=1">'
            . '<meta name="robots" content="noindex,nofollow"><title>Checking your browser</title>'
            . '<style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;'
            . 'font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;'
            . 'background:#f6f7f9;color:#16181d}@media(prefers-color-scheme:dark){body{background:#0f1115;color:#eceef2}}'
            . 'main{text-align:center;padding:24px;max-width:420px}a{color:inherit}</style></head>'
            . '<body><main><p id="m">Checking your browser, one moment.</p>'
            . '<noscript><p>JavaScript is required to continue. Please enable it and reload this page.</p></noscript>'
            . '</main><script>' . $this->script($data) . '</script></body></html>';
    }

    /**
     * Only scalar fields survive. Nested arrays are flattened with the bracket
     * notation PHP itself uses, so name="a[b]" comes back as name="a[b]" and
     * the customer's own parsing is unchanged.
     */
    private function flatten(array $post, string $prefix = ''): array
    {
        $out = [];

        foreach ($post as $key => $value) {
            if (count($out) >= self::MAX_FIELDS) {
                break;
            }

            $name = $prefix === '' ? (string) $key : $prefix . '[' . $key . ']';

            if (is_array($value)) {
                foreach ($this->flatten($value, $name) as $nested) {
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

    private function script(string $data): string
    {
        return <<<JS
(function(){
  var D = {$data};
  var KEY = 'mo_resume';

  function stash(){
    if (D.method !== 'POST' || !D.fields.length) { return; }
    try { sessionStorage.setItem(KEY, JSON.stringify({a: D.action, f: D.fields, t: Date.now()})); } catch (e) {}
  }

  function stashed(){
    try {
      var raw = sessionStorage.getItem(KEY);
      if (!raw) { return null; }
      var v = JSON.parse(raw);
      // Anything older than ten minutes is somebody else's abandoned tab.
      return (v && v.t && (Date.now() - v.t) < 600000) ? v : null;
    } catch (e) { return null; }
  }

  function clear(){ try { sessionStorage.removeItem(KEY); } catch (e) {} }

  function passFromHash(){
    var m = /(?:^|[#&])__mo_pass=([^&]+)/.exec(window.location.hash || '');
    return m ? decodeURIComponent(m[1]) : null;
  }

  var pass = passFromHash();

  if (!pass) {
    stash();
    window.location.replace(D.challenge);
    return;
  }

  // Returning. The cookie is what the server will actually read; the fragment
  // is only how it got here, so it goes away immediately.
  document.cookie = D.cookie + '=' + encodeURIComponent(pass) +
    '; path=/; max-age=1800; samesite=lax' + (location.protocol === 'https:' ? '; secure' : '');

  try { history.replaceState(null, '', location.pathname + location.search); } catch (e) {}

  var resume = stashed();

  if (!resume) {
    if (D.upload) {
      document.getElementById('m').textContent =
        'Verified. Your file was not kept, so please choose it again on the next page.';
    }
    clear();
    window.location.replace(location.pathname + location.search);
    return;
  }

  clear();

  var form = document.createElement('form');
  form.method = 'POST';
  form.action = resume.a;
  form.style.display = 'none';

  for (var i = 0; i < resume.f.length; i++) {
    var input = document.createElement('input');
    input.type = 'hidden';
    input.name = resume.f[i].n;
    input.value = resume.f[i].v;
    form.appendChild(input);
  }

  document.body.appendChild(form);
  form.submit();
})();
JS;
    }
}
