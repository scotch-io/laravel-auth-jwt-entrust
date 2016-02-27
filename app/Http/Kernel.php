<?php

namespace App\Http;

use Illuminate\Foundation\Http\Kernel as HttpKernel;

class Kernel extends HttpKernel
{
    /**
     * The application's global HTTP middleware stack.
     *
     * @var array
     */
    protected $middleware = [
        \Illuminate\Foundation\Http\Middleware\CheckForMaintenanceMode::class,
        \App\Http\Middleware\EncryptCookies::class,
        \Illuminate\Cookie\Middleware\AddQueuedCookiesToResponse::class,
        \Illuminate\Session\Middleware\StartSession::class,
        \Illuminate\View\Middleware\ShareErrorsFromSession::class,
//        \App\Http\Middleware\VerifyCsrfToken::class,
    ];

    /**
     * The application's route middleware.
     *
     * @var array
     */
    protected $routeMiddleware = [
        'auth' => \App\Http\Middleware\Authenticate::class,
        'auth.basic' => \Illuminate\Auth\Middleware\AuthenticateWithBasicAuth::class,
        'guest' => \App\Http\Middleware\RedirectIfAuthenticated::class,        
        'jwt.auth' => 'Tymon\JWTAuth\Middleware\GetUserFromToken',
        'jwt.refresh' => 'Tymon\JWTAuth\Middleware\RefreshToken',
        'role' => 'App\Http\Middleware\TokenEntrustRole',
        'permission' => 'App\Http\Middleware\TokenEntrustPermission',
        'ability' => 'App\Http\Middleware\TokenEntrustAbility'

        //Use this when not making use of tymon jwt
//        'role' => 'Zizaco\Entrust\Middleware\EntrustRole',
        // 'permission' => 'Zizaco\Entrust\Middleware\EntrustPermission::class',
        // 'ability' => 'Zizaco\Entrust\Middleware\EntrustAbility::class'
    ];
}
