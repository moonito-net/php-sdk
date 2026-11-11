<?php

namespace Moonito\Sensor;

/**
 * Adds the browser sensor to the site's HTML pages, so a customer installs one
 * thing instead of the SDK plus a separate script tag.
 *
 * The sensor version is pinned here, with its Subresource Integrity hash, so
 * updating the SDK is also how the sensor gets updated. jsDelivr serves the
 * tagged path as immutable; never point this at a branch path.
 *
 * It only ever touches a response that is plainly an HTML page for a browser:
 *
 *   - Content-Type text/html (or none set and the body looks like a document)
 *   - a 2xx status other than 204, and no Content-Disposition attachment
 *   - not compressed (no Content-Encoding, no gzip bytes)
 *   - not a HEAD, AJAX, JSON or sub-resource request
 *   - no sensor tag already on the page (customers who pasted the snippet)
 *   - a Content-Security-Policy, if any, that lets the script load from
 *     jsDelivr and talk to Moonito. When it does not, nothing is added and
 *     the SDK remembers it, so Moonito does not read the silence as a bot.
 *
 * Anything else passes through byte for byte.
 */
final class Injector
{
    const VERSION = '1.1.1';
    const SRI = 'sha384-/7UZbqrpJUAKrkuftEAXE/7FurwiJ7NUyeokkvYnYClNLTXAvBCAKqo9pKzC1Zkv';
    const SCRIPT_HOST = 'cdn.jsdelivr.net';
    // The published sensor's repository. The one place the drop-in has to
    // name it: the page loads it from there anyway.
    const SENSOR_PATH = '/gh/moonito-net/sensor@';
    // Marks the tag this library added, so it is never added twice.
    const MARKER = 'data-guard-sensor';
    const MAX_BYTES = 5242880;

    /** The page's CSP blocked the sensor; nothing was added. */
    const BLOCKED = 'blocked';
    const INJECTED = 'injected';
    const SKIPPED = 'skipped';

    private $publicKey;
    private $endpoint;

    /** @var callable|null fn(): void, called once when a CSP blocks the sensor */
    private $onBlocked;

    private $state = 'pending';
    private $contextTag = '';

    public function __construct(string $publicKey, string $endpoint, ?callable $onBlocked = null)
    {
        $this->publicKey = $publicKey;
        $this->endpoint = rtrim($endpoint, '/');
        $this->onBlocked = $onBlocked;
    }

    /** Whether the request itself is one a page could be served for. */
    public static function wantsPage(array $server): bool
    {
        if (PHP_SAPI === 'cli') {
            return false;
        }

        $method = strtoupper(isset($server['REQUEST_METHOD']) ? (string) $server['REQUEST_METHOD'] : 'GET');

        if ($method !== 'GET' && $method !== 'POST') {
            return false;
        }

        if (strtolower(isset($server['HTTP_X_REQUESTED_WITH']) ? (string) $server['HTTP_X_REQUESTED_WITH'] : '') === 'xmlhttprequest') {
            return false;
        }

        $accept = strtolower(isset($server['HTTP_ACCEPT']) ? (string) $server['HTTP_ACCEPT'] : '');

        if ($accept !== '' && strpos($accept, 'text/html') === false && strpos($accept, '*/*') === false) {
            return false;
        }

        $dest = strtolower(isset($server['HTTP_SEC_FETCH_DEST']) ? (string) $server['HTTP_SEC_FETCH_DEST'] : '');

        return $dest === '' || $dest === 'document' || $dest === 'iframe';
    }

    /**
     * The drop-in path: buffer this request's output and add the tag at the
     * end. Returns false when the request does not qualify or output has
     * already started (the page head is gone by then).
     */
    public function start(array $server, string $contextTag = ''): bool
    {
        if (!self::wantsPage($server) || headers_sent()) {
            return false;
        }

        $this->contextTag = $contextTag;

        return ob_start([$this, 'filter']);
    }

    /** Output buffer callback. Must never throw and never lose a byte. */
    public function filter($buffer, $phase = 0)
    {
        if (!is_string($buffer) || $this->state !== 'pending') {
            return $buffer;
        }

        try {
            $status = function_exists('http_response_code') ? (int) http_response_code() : 200;
            $result = $this->process($buffer, function_exists('headers_list') ? headers_list() : [], $status ?: 200);
        } catch (\Throwable $e) {
            $this->state = 'done';

            return $buffer;
        }

        if ($result['outcome'] === self::INJECTED || $result['outcome'] === self::BLOCKED || $result['final']) {
            $this->state = 'done';
        }

        return $result['html'];
    }

    /**
     * Decide and, if allowed, insert the tag.
     *
     * @param string[] $headers response header lines, "Name: value"
     * @return array{html: string, outcome: string, final: bool}
     */
    public function process(string $html, array $headers, int $status = 200): array
    {
        $pass = ['html' => $html, 'outcome' => self::SKIPPED, 'final' => true];

        if ($this->publicKey === '' || $html === '' || strlen($html) > self::MAX_BYTES) {
            return $pass;
        }

        if ($status < 200 || $status >= 300 || $status === 204) {
            return $pass;
        }

        $byName = [];
        foreach ($headers as $line) {
            $parts = explode(':', (string) $line, 2);
            if (count($parts) === 2) {
                $byName[strtolower(trim($parts[0]))][] = trim($parts[1]);
            }
        }

        if (isset($byName['content-encoding']) || substr($html, 0, 2) === "\x1f\x8b") {
            return $pass;
        }

        if (isset($byName['content-disposition']) && stripos(implode(';', $byName['content-disposition']), 'attachment') !== false) {
            return $pass;
        }

        $type = isset($byName['content-type']) ? strtolower(end($byName['content-type'])) : '';

        if ($type !== '' && strpos($type, 'text/html') === false) {
            return $pass;
        }

        if ($type === '' && !preg_match('/^\s*(<!doctype html|<html|<head)/i', $html)) {
            return $pass;
        }

        if (stripos($html, self::SENSOR_PATH) !== false || stripos($html, self::MARKER) !== false) {
            return $pass;
        }

        $at = stripos($html, '</head>');
        $insertAfter = false;

        if ($at === false) {
            if (!preg_match('/<body\b[^>]*>/i', $html, $m, PREG_OFFSET_CAPTURE)) {
                // Not the part of the page holding the head yet (a flushed
                // chunk), or not a full document. Try again on the next chunk.
                return ['html' => $html, 'outcome' => self::SKIPPED, 'final' => false];
            }

            $at = $m[0][1] + strlen($m[0][0]);
            $insertAfter = true;
        }

        $nonce = null;
        $policies = isset($byName['content-security-policy']) ? $byName['content-security-policy'] : [];

        // A policy set by a meta tag cannot be read reliably from here; stay out.
        if (preg_match('/<meta[^>]+http-equiv\s*=\s*["\']?content-security-policy/i', $html)) {
            $policies[] = "script-src 'none'";
        }

        foreach ($policies as $policy) {
            $allowed = $this->policyAllows($policy, $nonce);

            if (!$allowed) {
                if ($this->onBlocked !== null) {
                    try {
                        call_user_func($this->onBlocked);
                    } catch (\Throwable $e) {
                        // Remembering is a nicety; the page is what matters.
                    }
                }

                return ['html' => $html, 'outcome' => self::BLOCKED, 'final' => true];
            }
        }

        $tag = $this->tag($nonce);

        return [
            'html' => substr($html, 0, $at) . $tag . substr($html, $at),
            'outcome' => self::INJECTED,
            'final' => true,
        ];
    }

    private function tag(?string $nonce): string
    {
        $endpoint = $this->endpoint !== ''
            ? ' data-endpoint="' . htmlspecialchars($this->endpoint, ENT_QUOTES) . '"'
            : '';

        return $this->contextTag
            . '<script defer src="https://' . self::SCRIPT_HOST . self::SENSOR_PATH . self::VERSION . '/t.js"'
            . ' integrity="' . self::SRI . '" crossorigin="anonymous"'
            . ' data-key="' . htmlspecialchars($this->publicKey, ENT_QUOTES) . '"'
            . $endpoint
            . ($nonce !== null ? ' nonce="' . htmlspecialchars($nonce, ENT_QUOTES) . '"' : '')
            . ' ' . self::MARKER . '></script>';
    }

    /**
     * Whether one policy lets the sensor load and report. Sets $nonce when
     * the page's scripts are allowed by nonce and the tag must carry it.
     */
    private function policyAllows(string $policy, ?string &$nonce): bool
    {
        $directives = [];

        foreach (explode(';', $policy) as $part) {
            $tokens = preg_split('/\s+/', trim($part));

            if ($tokens === false || $tokens[0] === '') {
                continue;
            }

            $name = strtolower(array_shift($tokens));

            if (!isset($directives[$name])) {
                $directives[$name] = $tokens;
            }
        }

        $script = isset($directives['script-src-elem']) ? $directives['script-src-elem']
            : (isset($directives['script-src']) ? $directives['script-src']
            : (isset($directives['default-src']) ? $directives['default-src'] : null));

        if ($script !== null) {
            foreach ($script as $source) {
                if (preg_match("/^'nonce-([A-Za-z0-9+\/=_-]+)'$/", $source, $m)) {
                    $nonce = $m[1];
                }
            }

            $strictDynamic = in_array("'strict-dynamic'", array_map('strtolower', $script), true);

            if ($strictDynamic ? $nonce === null : (!$this->sourcesAllow($script, self::SCRIPT_HOST) && $nonce === null)) {
                return false;
            }
        }

        $connect = isset($directives['connect-src']) ? $directives['connect-src']
            : (isset($directives['default-src']) ? $directives['default-src'] : null);

        $apiHost = (string) parse_url($this->endpoint, PHP_URL_HOST);

        return $connect === null || $this->sourcesAllow($connect, $apiHost);
    }

    private function sourcesAllow(array $sources, string $host): bool
    {
        foreach ($sources as $source) {
            $source = strtolower(trim($source, '"'));

            if ($source === "'none'") {
                return false;
            }

            if ($source === '*' || $source === 'https:') {
                return true;
            }

            $sourceHost = preg_replace('#^https?://#', '', rtrim($source, '/'));
            $sourceHost = preg_replace('#[:/].*$#', '', $sourceHost);

            if ($sourceHost === $host) {
                return true;
            }

            if (strpos($sourceHost, '*.') === 0 && substr($host, -strlen(substr($sourceHost, 1))) === substr($sourceHost, 1)) {
                return true;
            }
        }

        return false;
    }
}
