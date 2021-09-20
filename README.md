
# JetStream Multi authentication
This is the multi authentication system using Laravel 8 JetStream 
Package.

## Installation
 - [composer create-project laravel/laravel project_name](https://laravel.com/docs/8.x)
 - [composer require laravel/jetstream](https://jetstream.laravel.com/2.x/installation.html)
 - [php artisan jetstream:install livewire](https://jetstream.laravel.com/2.x/installation.html)
 - npm install && npm run dev

## After Installation
Create a Database & Connect With This Project
After Connectting The Database 

Run The Command `php artisan migrate`

## After Migration
Create A Controller 

`php artisan make:controller AdminController`

Make A Model & Migration For Admin

`php artisan make:model Admin -m`

Copy Users Table Column to Admin Table

    public function up()
    {
        Schema::create('admins', function (Blueprint $table) {
            $table->id();
            $table->string('name');
            $table->string('email')->unique();
            $table->timestamp('email_verified_at')->nullable();
            $table->string('password');
            $table->rememberToken();
            $table->foreignId('current_team_id')->nullable();
            $table->string('profile_photo_path', 2048)->nullable();
            $table->timestamps();
        });
    }

### Copy Paste In Admin Model

    namespace App\Models;

    use Illuminate\Contracts\Auth\MustVerifyEmail;
    use Illuminate\Database\Eloquent\Factories\HasFactory;
    use Illuminate\Foundation\Auth\User as Authenticatable;
    use Illuminate\Notifications\Notifiable;
    use Laravel\Fortify\TwoFactorAuthenticatable;
    use Laravel\Jetstream\HasProfilePhoto;
    use Laravel\Sanctum\HasApiTokens;

    class Admin extends Authenticatable
    {
    use HasApiTokens;
    use HasFactory;
    use HasProfilePhoto;
    use Notifiable;
    use TwoFactorAuthenticatable;

    /**
     * The attributes that are mass assignable.
     *
     * @var string[]
     */
    protected $fillable = [
        'name',
        'email',
        'password',
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var array
     */
    protected $hidden = [
        'password',
        'remember_token',
        'two_factor_recovery_codes',
        'two_factor_secret',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array
     */
    protected $casts = [
        'email_verified_at' => 'datetime',
    ];

    /**
     * The accessors to append to the model's array form.
     *
     * @var array
     */
    protected $appends = [
        'profile_photo_url',
    ];
    }


#### After That 

Run The Command `php artisan migrate`

Create A Factory `php artisan make:factory AdminFactory`

Copy Paste In AdminFactory 
#
    use Illuminate\Support\Str;

    public function definition()
    {
        return [
            'name' => 'Admin',
            'email' => 'admin@gmail.com',
            'email_verified_at' => now(),
            'password' => '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', // password
            'remember_token' => Str::random(10),
        ];
    }

Copy Paste In `Seeders\DatabaseSeeder.php`

    public function run()

    {
         \App\Models\Admin::factory()->create();
    }
    
#### After That 

Run The Command `php artisan migrate --seed`

Copy Paste In `App\Config\auth.php`


    'guards' => [

        'web' => [
            'driver' => 'session',
            'provider' => 'users',
        ],
        'admin' => [
            'driver' => 'session',
            'provider' => 'admins',
        ],
    ],



    providers' => [

        'users' => [
            'driver' => 'eloquent',
            'model' => App\Models\User::class,
        ],

        'admins' => [
            'driver' => 'eloquent',
            'model' => App\Models\Admin::class,
        ],
    ],


    'passwords' => [

        'users' => [
            'provider' => 'users',
            'table' => 'password_resets',
            'expire' => 60,
            'throttle' => 60,
        ],
        'admins' => [
            'provider' => 'admins',
            'table' => 'password_resets',
            'expire' => 60,
            'throttle' => 60,
        ],
    ],



Copy Paste In 
`app\providers\FortifyServiceProvider.php`

    use Illuminate\Contracts\Auth\StatefulGuard;
    use App\Actions\Fortify\AttemptToAuthenticate;
    use App\Actions\Fortify\RedirectIfTwoFactorAuthenticatable;
    use App\Http\Controllers\AdminController;

    public function register()
    {
       $this->app->when([AdminController::class, AttemptToAuthenticate::class, RedirectIfTwoFactorAuthenticatable::class ])
            ->needs(StatefulGuard::class)
            ->give(function(){
                return Auth::guard('admin');
            });
    }

 After That Create A folder in `app` folder name `Guards `

In `Guards` Folder Create A File `AdminStatefulGuard.php`
In `AdminStatefulGuard.php` Paste As It Is 

## 

    namespace App\Guards;

    interface AdminStatefulGuard extends Guard
    {
    public function attempt(array $credentials = [], $remember = false);

    /**
     * Log a user into the application without sessions or cookies.
     *
     * @param  array  $credentials
     * @return bool
     */
    public function once(array $credentials = []);

    /**
     * Log a user into the application.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  bool  $remember
     * @return void
     */
    public function login(Authenticatable $user, $remember = false);

    /**
     * Log the given user ID into the application.
     *
     * @param  mixed  $id
     * @param  bool  $remember
     * @return \Illuminate\Contracts\Auth\Authenticatable|bool
     */
    public function loginUsingId($id, $remember = false);

    /**
     * Log the given user ID into the application without sessions or cookies.
     *
     * @param  mixed  $id
     * @return \Illuminate\Contracts\Auth\Authenticatable|bool
     */
    public function onceUsingId($id);

    /**
     * Determine if the user was authenticated via "remember me" cookie.
     *
     * @return bool
     */
    public function viaRemember();

    /**
     * Log the user out of the application.
     *
     * @return void
     */
    public function logout();
    }

## After That Go To
`vendor\laravel\fortify\src\Http\controllers\AuthenticatedSessionController.php`

and Copy From `AuthenticatedSessionController.php` and Paste in

`app\Http\Controllers\AdminController.php`
###

    namespace App\Http\Controllers;

    use Illuminate\Contracts\Auth\StatefulGuard;
    use Illuminate\Http\Request;
    use Illuminate\Routing\Controller;
    use Illuminate\Routing\Pipeline;
    use App\Actions\Fortify\AttemptToAuthenticate;
    use Laravel\Fortify\Actions\EnsureLoginIsNotThrottled;
    use Laravel\Fortify\Actions\PrepareAuthenticatedSession;
    use App\Actions\Fortify\RedirectIfTwoFactorAuthenticatable;
    use App\Http\Responses\LoginResponse;
    use Laravel\Fortify\Contracts\LoginViewResponse;
    use Laravel\Fortify\Contracts\LogoutResponse;
    use Laravel\Fortify\Features;
    use Laravel\Fortify\Fortify;
    use Laravel\Fortify\Http\Requests\LoginRequest;

    class AdminController extends Controller
    {
    /**
     * The guard implementation.
     *
     * @var \Illuminate\Contracts\Auth\StatefulGuard
     */
    protected $guard;

    /**
     * Create a new controller instance.
     *
     * @param  \Illuminate\Contracts\Auth\StatefulGuard  $guard
     * @return void
     */
    public function __construct(StatefulGuard $guard)
    {
        $this->guard = $guard;
    }

    public function loginForm()
    {
        return view('auth.login', ['guard' => 'admin']);
    }

    /**
     * Show the login view.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Laravel\Fortify\Contracts\LoginViewResponse
     */
    public function create(Request $request): LoginViewResponse
    {
        return app(LoginViewResponse::class);
    }

    /**
     * Attempt to authenticate a new session.
     *
     * @param  \Laravel\Fortify\Http\Requests\LoginRequest  $request
     * @return mixed
     */
    public function store(LoginRequest $request)
    {
        return $this->loginPipeline($request)->then(function ($request) {
            return app(LoginResponse::class);
        });
    }

    /**
     * Get the authentication pipeline instance.
     *
     * @param  \Laravel\Fortify\Http\Requests\LoginRequest  $request
     * @return \Illuminate\Pipeline\Pipeline
     */
    protected function loginPipeline(LoginRequest $request)
    {
        if (Fortify::$authenticateThroughCallback) {
            return (new Pipeline(app()))->send($request)->through(array_filter(
                call_user_func(Fortify::$authenticateThroughCallback, $request)
            ));
        }

        if (is_array(config('fortify.pipelines.login'))) {
            return (new Pipeline(app()))->send($request)->through(array_filter(
                config('fortify.pipelines.login')
            ));
        }

        return (new Pipeline(app()))->send($request)->through(array_filter([
            config('fortify.limiters.login') ? null : EnsureLoginIsNotThrottled::class,
            Features::enabled(Features::twoFactorAuthentication()) ? RedirectIfTwoFactorAuthenticatable::class : null,
            AttemptToAuthenticate::class,
            PrepareAuthenticatedSession::class,
        ]));
    }

    /**
     * Destroy an authenticated session.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Laravel\Fortify\Contracts\LogoutResponse
     */
    public function destroy(Request $request): LogoutResponse
    {
        $this->guard->logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();
        return app(LogoutResponse::class);
    }
    }

### Then Change in `routes\web.php`

`use App\Http\Controllers\AdminController;`

`Route::group(['prefix'=>'admin', 'middleware'=>['admin:admin']], function(){
    Route::get('/login', [AdminController::class, 'loginForm']);
    Route::post('/login', [AdminController::class, 'store'])->name('admin.login');
});`

`Route::middleware(['auth:sanctum,admin', 'verified'])->get('/admin/dashboard', function () {
    return view('dashboard');
})->name('dashboard');`

`Route::middleware(['auth:sanctum,web', 'verified'])->get('/dashboard', function () {
    return view('dashboard');
})->name('dashboard');`


### After that Change In `resources\views\auth\login.blade.php`

`<form method="POST" action="{{ isset($guard) ? url($guard.'/login') : route('login') }}">`

### Now go to 
`vendor\laravel\fortify\src\Actions` Folder and copy 2 fies 

`AttemptToAuthenticate.php` & `RedirectIfTwoFactorAuthenticatable.php` 

and paste them in `app\Actions\Fortify` Folder
and Change Their namespace 

    `namespace App\Actions\Fortify;`

### Then go to `app\providers`
Open `RouteServiceProvider.php' & Paste it 

    public const HOME = '/dashboard';

    public static function redirectTo($guard)
    {
        return $guard.'/dashboard';
    }


### Now go to `Middleware\RedirectIfAuthenticated.php` and Paste it

    foreach ($guards as $guard) {
            if (Auth::guard($guard)->check()) {
                return redirect($guard.'/dashboard');
        }
    }

Create A Middleware `php artisan make:middleware AdminRedirectIfAuthenticated`

Then Copy all From 
`RedirectIfAuthenticated.php` and paste in `AdminRedirectIfAuthenticated.php`

    namespace App\Http\Middleware;
    use App\Providers\RouteServiceProvider;
    use Closure;
    use Illuminate\Http\Request;
    use Illuminate\Support\Facades\Auth;

    class AdminRedirectIfAuthenticated
    {
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @param  string|null  ...$guards
     * @return mixed
     */
    public function handle(Request $request, Closure $next, ...$guards)
    {
        $guards = empty($guards) ? [null] : $guards;

        foreach ($guards as $guard) {
            if (Auth::guard($guard)->check()) {
                return redirect($guard.'/dashboard');
            }
        }

        return $next($request);
    }
    }

Register The Middleware in `Kernel.php` 

    protected $routeMiddleware = [
        'admin' => \App\Http\Middleware\AdminRedirectIfAuthenticated::class,
    ];


### Create A Folder in `app\Http` and name `Responses`
in `app\Http\Responses` create a file named `LoginResponse.php`
Then go To `vendor\laravel\fortify\src\Http\Responses\LoginResponse.php`

Copy All From `vendor\laravel\fortify\src\Http\Responses\LoginResponse.php` 
and Paste it `app\Http\Responses\LoginResponse.php`


    namespace Laravel\Fortify\Http\Responses;

    use Laravel\Fortify\Contracts\LoginResponse as LoginResponseContract;
    use Laravel\Fortify\Fortify;

    class LoginResponse implements LoginResponseContract
    {
    /**
     * Create an HTTP response that represents the object.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function toResponse($request)
    {
        return $request->wantsJson()
                    ? response()->json(['two_factor' => false])
                    : redirect()->intended('admin/dashboard');
    }
    }


# Login Details

    http://127.0.0.1:8000/login
    User Name : towhidhasang1@gmail.com
    Password: 12345678

    http://127.0.0.1:8000/admin/login
    User Name : admin@gmail.com
    Password: password