<?php

namespace Moonito\Framework\Laravel;

use Illuminate\Support\ServiceProvider;
use Moonito\Client;
use Moonito\Config;

class MoonitoServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        // These values are signed by the decision service or read by the
        // browser sensor. Laravel encryption would make them unreadable there.
        $this->app->resolving(\Illuminate\Cookie\Middleware\EncryptCookies::class, function ($middleware) {
            $middleware->disableFor(['__mo_ct', '__mo_cx', '__mo_pass']);
        });
        $this->mergeConfigFrom(__DIR__ . '/config.php', 'moonito');

        $this->app->singleton(Client::class, function ($app) {
            return new Client(Config::fromArray($app['config']->get('moonito', [])));
        });
    }

    public function boot(): void
    {
        $this->publishes([__DIR__ . '/config.php' => config_path('moonito.php')], 'moonito-config');
    }
}
