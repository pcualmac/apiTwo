<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Config;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;
use Illuminate\Support\Facades\Auth;

class AuthUser extends Controller
{
    public function loginUser(Request $request)
    {

        $credentials = $request->only('email', 'password');
        try {
            $token = auth()->guard('api')->attempt($credentials);
            if (!$token) {
                return response()->json(['success' => false, 'error' => 'Some Error Message'], 401);
            }
        } catch (JWTException $e) {
            return response()->json(['success' => false, 'error' => 'Failed to login, please try again.'], 500);
        }
        $user = Auth::guard('api')->user();
        $customClaims = $user->getJWTCustomClaims();
        $response =[
            'token' => $token,
            'customClaims' => $customClaims,
            'claims' => JWTAuth::claims($customClaims)->fromUser($user)
        ]; 
        return $this->finalResponse($response);
    }


    public function registerUser(Request $request)
    {
        $credentials = $request->only('email', 'password');
        $request->merge(['password' => Hash::make($request->password)]);
        $username = explode('@', $request->email)[0];
        $user = User::create([
            'name' => $username,
            'username' => $username,
            'email' => $request->email,
            'password' => $request->password,
        ]);
        return response()->json('success' . ' ' . $user->name . '  ' . $user->email . ' ');
    }

    public function verifyToken(Request $request)
    {
        try {
            $token = $request->bearerToken() ?: $request->query('token');
            JWTAuth::setToken($token);
            $user = Auth::guard('api')->user();
            $customClaims = $user->getJWTCustomClaims();
            $response =[
                'user' => $user,
                'customClaims' => $customClaims,
                'claims' => JWTAuth::claims($customClaims)->fromUser($user),
            ]; 
            return response()->json(['response' => $response], 200);
        } catch (\Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
            // Token has expired
            return response()->json(['error' => 'Token expired'], 401);
        } catch (\Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {
            // Token is invalid
            return response()->json(['error' => 'Token invalid'], 401);
        } catch (\Tymon\JWTAuth\Exceptions\JWTException $e) {
            // Token is absent from the request
            return response()->json(['error' => 'Token absent'], 401);
        }
    }
}