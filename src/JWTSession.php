<?php

namespace ravibpatel\JWTSession;

use Exception;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use SessionHandlerInterface;

class JWTSession implements SessionHandlerInterface
{
    const ALGORITHM = 'HS512';

    private $timeout;

    private $secretKey;

    private $name;

    private $expireOnClose;

    private $domain;

    private $samesite;

    private $secure;

    /**
     * JWTSession constructor.
     * @param int $timeout
     * @param string $secretKey
     * @param bool $expireOnClose
     * @param string $name
     * @param string|null $domain
     * @param string $samesite
     * @param bool $secure
     */
    public function __construct(
        int    $timeout,
        string $secretKey,
        bool   $expireOnClose = false,
        string $name = 'AUTH_BEARER',
        string $domain = '',
        string $samesite = 'Lax',
        bool   $secure = false
    )
    {
        $this->secretKey = $secretKey;
        $this->timeout = $timeout;
        $this->name = $name;
        $this->expireOnClose = $expireOnClose;
        $this->samesite = $samesite;
        $this->secure = $secure;
        $this->domain = $domain;
    }

    /**
     * Set this object as the session save handler.
     * @link http://php.net/manual/en/function.session-set-save-handler.php
     * @param bool $startSession
     * @throws Exception
     */
    public function setSessionHandler(bool $startSession = true)
    {
        if (session_status() != PHP_SESSION_NONE) {
            throw new Exception('Session already started!');
        }

        session_set_save_handler($this, true);

        if ($startSession) {
            ob_start();
            session_start();
        }
    }

    /**
     * Close the session
     * @link https://php.net/manual/en/sessionhandlerinterface.close.php
     * @return bool <p>
     * The return value (usually TRUE on success, FALSE on failure).
     * Note this value is returned internally to PHP for processing.
     * </p>
     * @since 5.4
     */
    public function close(): bool
    {
        return true;
    }

    /**
     * Destroy a session
     * @link https://php.net/manual/en/sessionhandlerinterface.destroy.php
     * @param string $id The session ID being destroyed.
     * @return bool <p>
     * The return value (usually TRUE on success, FALSE on failure).
     * Note this value is returned internally to PHP for processing.
     * </p>
     * @since 5.4
     */
    public function destroy($id): bool
    {
        return setcookie($this->name, "", time() - 3600, '/', $this->domain);
    }

    /**
     * Cleanup old sessions
     * @link https://php.net/manual/en/sessionhandlerinterface.gc.php
     * @param int $max_lifetime <p>
     * Sessions that have not updated for
     * the last maxlifetime seconds will be removed.
     * </p>
     * @return int|false <p>
     * Returns the number of deleted sessions on success, or false on failure. Prior to PHP version 7.1, the function returned true on success.
     * Note this value is returned internally to PHP for processing.
     * </p>
     * @since 5.4
     */
    public function gc($max_lifetime): int
    {
        return 0;
    }

    /**
     * Initialize session
     * @link https://php.net/manual/en/sessionhandlerinterface.open.php
     * @param string $path The path where to store/retrieve the session.
     * @param string $name The session name.
     * @return bool <p>
     * The return value (usually TRUE on success, FALSE on failure).
     * Note this value is returned internally to PHP for processing.
     * </p>
     * @since 5.4
     */
    public function open($path, $name): bool
    {
        return true;
    }

    /**
     * Read session data
     * @link https://php.net/manual/en/sessionhandlerinterface.read.php
     * @param string $id The session id to read data for.
     * @return string|false <p>
     * Returns an encoded string of the read data.
     * If nothing was read, it must return false.
     * Note this value is returned internally to PHP for processing.
     * </p>
     * @since 5.4
     */
    public function read($id): string
    {
        if (isset($_COOKIE[$this->name])) {
            try {
                $token = (array)JWT::decode($_COOKIE[$this->name], new Key($this->secretKey, self::ALGORITHM));
                return $token["data"];
            } catch (Exception $exception) {
                return '';
            }
        }
        return '';
    }

    /**
     * Write session data
     * @link https://php.net/manual/en/sessionhandlerinterface.write.php
     * @param string $id The session id.
     * @param string $data <p>
     * The encoded session data. This data is the
     * result of the PHP internally encoding
     * the $_SESSION superglobal to a serialized
     * string and passing it as this parameter.
     * Please note sessions use an alternative serialization method.
     * </p>
     * @return bool <p>
     * The return value (usually TRUE on success, FALSE on failure).
     * Note this value is returned internally to PHP for processing.
     * </p>
     * @since 5.4
     */
    public function write($id, $data): bool
    {
        $tokenId = $id;
        $issuedAt = time();
        $notBefore = $issuedAt;
        $expire = $notBefore + $this->timeout * 60;
        $serverName = $this->domain;
        $token = [
            'iat'  => $issuedAt,       // Issued At: Time at which the JWT was issued
            'jti'  => $tokenId,        // JWT ID: A unique identifier for the JWT
            'iss'  => $serverName,     // Issuer: Server that issued the JWT
            'nbf'  => $notBefore,      // Not Before: The time before which the JWT MUST NOT be accepted for processing
            'exp'  => $expire,         // Expiration Time: The expiration time on or after which the JWT MUST NOT be accepted for processing
            'data' => $data            // Session data
        ];
        $jwt = JWT::encode($token, $this->secretKey, self::ALGORITHM);
        $time = strtotime('+2 years');
        if ($this->expireOnClose) {
            $time = 0;
        }
        if (PHP_VERSION_ID < 70300) {
            return setcookie($this->name, $jwt, $time, "/; SameSite=$this->samesite", $this->domain, $this->secure);
        } else {
            return setcookie($this->name, $jwt, [
                'expires' => $time,
                'path' => '/',
                'domain' => $this->domain,
                'samesite' => $this->samesite,
                'secure' => $this->secure
            ]);
        }
    }
}