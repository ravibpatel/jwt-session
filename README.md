# JWT-SESSION

Easily replace your existing session based authentication with JWT token-based authentication.

# Installation

Use composer to manage your dependencies and download JWT-SESSION:

```bash
composer require ravibpatel/jwt-session
```

## How to use

Just create the "session.php" file with the following content.

```php
require_once __DIR__ . "/vendor/autoload.php";

$JWTSession = new ravibpatel\JWTSession\JWTSession(20, "Your Secret Key");
$JWTSession->setSessionHandler();
```

Now just include "session.php" file instead of using session_start() as shown below. 

~~session_start();~~

```php
require_once __DIR__ . "/session.php";
```

## Parameters accepted by JWTSession constructor


### 1. Timeout : int

Session timeout in minutes.

### 2. Secret Key : string

This will be used to sign your session cookie.

### 3. Expire on Browser Close : boolean

Set it to true if you want the session to expire when the user closes the browser otherwise set it to false. By default, it is set to false.

### 4. Cookie name : string

If you are running multiple websites using this library on same domain then it is a good idea to set this to something else to avoid session collision. By default, it is set to "AUTH_BEARER".

### 5. Domain : string

By default it will be set to $_SERVER["HTTP_HOST"]. You can set it manually to point to your domain. The session cookie will only work for Domain you set here.

## Note

The JWT Token can't be tampered with, but it is readable. This library stores the JWT token into a cookie so it is recommended that you don't save sensitive data like passwords in it. Also, the cookie can store only 4093 bytes of data so you should not store lots of information in your session.

## Motivation

* [JSON Web Tokens (JWT) vs Sessions](https://float-middle.com/json-web-tokens-jwt-vs-sessions/)
* [byjg/jwt-session](https://github.com/byjg/jwt-session)