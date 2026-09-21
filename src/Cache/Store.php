<?php

namespace Moonito\Cache;

/**
 * A tiny cache with no dependencies.
 *
 * APCu when the host has it, files otherwise. The target host is shared
 * hosting with FTP access and nothing else, so requiring Redis or Memcached
 * would exclude most of the people this SDK exists for.
 */
final class Store
{
    private $dir;
    private $apcu;

    public function __construct(string $dir)
    {
        $this->dir = rtrim($dir, '/');
        $this->apcu = function_exists('apcu_fetch') && ini_get('apc.enabled');
    }

    public function get(string $key)
    {
        if ($this->apcu) {
            $ok = false;
            $value = apcu_fetch($this->prefix($key), $ok);

            return $ok ? $value : null;
        }

        $path = $this->path($key);
        $raw = @file_get_contents($path);

        if ($raw === false) {
            return null;
        }

        $entry = @unserialize($raw);

        if (!is_array($entry) || !isset($entry['expires'], $entry['value'])) {
            return null;
        }

        if ($entry['expires'] < time()) {
            @unlink($path);

            return null;
        }

        return $entry['value'];
    }

    public function put(string $key, $value, int $ttl): void
    {
        if ($this->apcu) {
            apcu_store($this->prefix($key), $value, $ttl);

            return;
        }

        if (!is_dir($this->dir) && !@mkdir($this->dir, 0700, true) && !is_dir($this->dir)) {
            return;
        }

        $payload = serialize(['expires' => time() + $ttl, 'value' => $value]);

        // Written to a temporary name and moved, so a concurrent reader never
        // sees a half-written file.
        $tmp = $this->path($key) . '.' . getmypid() . '.tmp';

        if (@file_put_contents($tmp, $payload, LOCK_EX) !== false) {
            @rename($tmp, $this->path($key));
        }
    }

    public function forget(string $key): void
    {
        if ($this->apcu) {
            apcu_delete($this->prefix($key));

            return;
        }

        @unlink($this->path($key));
    }

    private function prefix(string $key): string
    {
        return 'c:' . $key;
    }

    private function path(string $key): string
    {
        return $this->dir . '/' . hash('sha256', $key) . '.cache';
    }
}
