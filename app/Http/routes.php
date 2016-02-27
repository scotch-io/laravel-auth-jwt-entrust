<?php

/*
|--------------------------------------------------------------------------
| Application Routes
|--------------------------------------------------------------------------
|
| Here is where you can register all of the routes for an application.
| It's a breeze. Simply tell Laravel the URIs it should respond to
| and give it the controller to call when that URI is requested.
|
*/

Route::get('/', function () {
    return view('welcome');
});

Route::post('role', 'JwtAuthenticateController@createRole');
Route::post('permission', 'JwtAuthenticateController@createPermission');
Route::post('assign-role', 'JwtAuthenticateController@assignRole');
Route::post('attach-permission', 'JwtAuthenticateController@attachPermission');
Route::post('check', 'JwtAuthenticateController@checkRoles');

Route::group(['prefix' => 'api', 'middleware' => ['ability:admin,create-users']], function()
{
        Route::get('users', 'JwtAuthenticateController@index');

});

Route::post('authenticate', 'JwtAuthenticateController@authenticate');