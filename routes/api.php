<?php

use App\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/



 
Route::post('/sanctum/token', function (Request $request) {
    $request->validate([
        'email' => 'required|email',
        'password' => 'required',
    ]);
 
    $user = User::where('email', $request->email)->first();
 
    if (! $user || ! Hash::check($request->password, $user->password)) {
        throw ValidationException::withMessages([
            'email' => ['The provided credentials are incorrect.'],
        ]);
    }
 
    $token_can_all    = $user->createToken('can_all')->plainTextToken;
    $token_can_update = $user->createToken('can_update', ['system:update'])->plainTextToken;
    $token_can_create = $user->createToken('post_create', ['system:create'])->plainTextToken;

    $abilities = [$token_can_all,$token_can_update,$token_can_create];

    return $abilities;
});

/*Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});*/

Route::group(['middleware' => ['auth:sanctum']], function(){
    Route::get('user', function(Request $request){
        return $request->user();
    });

    Route::get('list_tokens', function(Request $request){
        return $request->user()->tokens;
    });

    Route::get('list_abilities', function(Request $request){
        $abilities = [];
        

        if ($request->user()->tokenCan('system:update')) {
            array_push($abilities, 'posso atualizar');
        }

        if ($request->user()->tokenCan('system:create')) {
            array_push($abilities, 'posso criar');
        }

        if ($request->user()->tokenCan('system:delete')) {
            array_push($abilities, 'posso deletar');
        }
        
        return $abilities;
    });

     // Revoke all tokens...
    Route::delete('revoke_all', function(Request $request){
        $request->user()->tokens()->delete();
        return response()->json([],204);
    });

    // Revoke the token that was used to authenticate the current request...
    Route::delete('revoke_authenticated', function(Request $request){
        $request->user()->currentAccessToken()->delete();
        return response()->json([],204);
    });

    // Revoke a specific token by id...
    Route::delete('revoke_by_id/{tokenId}', function(Request $request, $tokenId){
        $request->user()->tokens()->where('id', $tokenId)->delete();
        return response()->json([],204);
    });
   

 


});
