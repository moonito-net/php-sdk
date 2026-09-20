<?php

namespace Moonito\Framework\Laravel;

use Illuminate\Support\ServiceProvider;
use Moonito\Client;
use Moonito\Config;

class MoonitoServiceProvider extends ServiceProvider
{
    public function register(): void
    {
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
