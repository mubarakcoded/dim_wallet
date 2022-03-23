<?php

use App\Models\UserModel;
use Config\Services;
use Firebase\JWT\JWT;
Use Firebase\JWT\Key;

function getJWTFromRequest($authenticationHeader): string
{
    if (is_null($authenticationHeader)) { //JWT is absent
        throw new Exception('Missing or invalid JWT in request');
    }
    //JWT is sent from client in the format Bearer XXXXXXXXX
    return explode(' ', $authenticationHeader)[1];
}

function validateJWTFromRequest(string $encodedToken)
{
    $key = Services::getSecretKey();
    $decodedToken = JWT::decode($encodedToken, $key, ['HS256']);
    $userModel = new UserModel();
    $userModel->findUserByEmailAddress($decodedToken->email);
}

function validateJWTFromRequestOtp(string $encodedToken)
{
    $key = Services::getSecretKey();
    //$decodedToken = JWT::decode($encodedToken, $key, ['HS256']);
    $decodedToken = JWT::decode($encodedToken, new Key($key, 'HS256'));
    // print_r($decodedToken->email);
    // die();
}



function getSignedJWTForUser(string $email)
{
    $issuedAtTime = time();
    $tokenTimeToLive = getenv('JWT_TIME_TO_LIVE');
    $tokenExpiration = $issuedAtTime + $tokenTimeToLive;
    $payload = [
        'email' => $email,
        'iat' => $issuedAtTime,
        'exp' => $tokenExpiration,
    ];

    $jwt = JWT::encode($payload, Services::getSecretKey(), 'HS256');
    //$jwt = JWT::encode($payload, Services::getSecretKey());
    return $jwt;
}

function getSignedJWTForUserWithOtp(string $email, string $otp)
{
    $issuedAtTime = time();
    $tokenTimeToLive = getenv('JWT_TIME_TO_LIVE');
    $tokenExpiration = $issuedAtTime + $tokenTimeToLive;
    $payload = [
        'email' => $email,
        'otp' => $otp,
        'iat' => $issuedAtTime,
        'exp' => $tokenExpiration,
    ];

    $jwt = JWT::encode($payload, Services::getSecretKey(), 'HS256');
    //$jwt = JWT::encode($payload, Services::getSecretKey());
    return $jwt;
}
