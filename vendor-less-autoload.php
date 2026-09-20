<?php
/** Minimal PSR-4 autoloader, so the package can be exercised without Composer. */
spl_autoload_register(function ($class) {
    if (strpos($class, 'Moonito\\') !== 0) {
        return;
    }
    $path = __DIR__ . '/src/' . str_replace('\\', '/', substr($class, 8)) . '.php';
    if (is_file($path)) {
        require $path;
    }
});
