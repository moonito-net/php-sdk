# Changelog

## 3.4.1

- Isolate cached decisions and circuit breakers by API endpoint and credentials.
  A failed credential can no longer stop another client from checking visitors,
  and an allow decision cannot be reused across accounts.
- Keep APCu entries isolated when applications share a PHP worker pool.
- Fall back to the file cache when APCu is installed but disabled for the
  current process.
- Add regression coverage for credential, account, endpoint, and cache isolation.

Existing installations must update their Composer dependency or replace the
drop-in runtime files. Existing keys and protection settings remain compatible.
