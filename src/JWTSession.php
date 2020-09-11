<?php

namespace ravibpatel\JWTSession;

use Exception;
use \Firebase\JWT\JWT;
use SessionHandlerInterface;

class JWTSession implements SessionHandlerInterface
{
    const ALGORITHM = 'HS512';

    private $timeout;

    private $secret_key;

    private $name;

    private $expireOnClose;

    private $domain;

    /**
     * JWTSession constructor.
     * @param int $timeout
     * @param string $secret_key
     * @param bool $expireOnClose
     * @param string $name
     * @param string $domain
     */
    public function __construct($timeout, $secret_key, $expireOnClose = false, $name = 'AUTH_BEARER', $domain = null)
    {
        $this->secret_key = $secret_key;
        $this->timeout = $timeout;
        $this->name = $name;
        $this->expireOnClose = $expireOnClose;
        if (empty($domain)) {
            $this->domain = $_SERVER["HTTP_HOST"];
        } else {
            $this->domain = $domain;
        }
    }

    /**
     * Set this object as the session save handler.
     * @link http://php.net/manual/en/function.session-set-save-handler.php
     * @param bool $startSession
     * @throws Exception
     */
    public function setSessionHandler($startSession = true)
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
     * @link http://php.net/manual/en/sessionhandlerinterface.close.php
     * @return bool <p>
     * The return value (usually TRUE on success, FALSE on failure).
     * Note this value is returned internally to PHP for processing.
     * </p>
     * @since 5.4.0
     */
    public function close()
    {
        return true;
    }

    /**
     * Destroy a session
     * @link http://php.net/manual/en/sessionhandlerinterface.destroy.php
     * @param string $session_id The session ID being destroyed.
     * @return bool <p>
     * The return value (usually TRUE on success, FALSE on failure).
     * Note this value is returned internally to PHP for processing.
     * </p>
     * @since 5.4.0
     */
    public function destroy($session_id)
    {
        return setcookie($this->name, "", time() - 3600, '/', $this->domain);
    }

    /**
     * Cleanup old sessions
     * @link http://php.net/manual/en/sessionhandlerinterface.gc.php
     * @param int $maxlifetime <p>
     * Sessions that have not updated for
     * the last maxlifetime seconds will be removed.
     * </p>
     * @return bool <p>
     * The return value (usually TRUE on success, FALSE on failure).
     * Note this value is returned internally to PHP for processing.
     * </p>
     * @since 5.4.0
     */
    public function gc($maxlifetime)
    {
        return true;
    }

    /**
     * Initialize session
     * @link http://php.net/manual/en/sessionhandlerinterface.open.php
     * @param string $save_path The path where to store/retrieve the session.
     * @param string $name The session name.
     * @return bool <p>
     * The return value (usually TRUE on success, FALSE on failure).
     * Note this value is returned internally to PHP for processing.
     * </p>
     * @since 5.4.0
     */
    public function open($save_path, $name)
    {
        return true;
    }

    /**
     * Read session data
     * @link http://php.net/manual/en/sessionhandlerinterface.read.php
     * @param string $session_id The session id to read data for.
     * @return string <p>
     * Returns an encoded string of the read data.
     * If nothing was read, it must return an empty string.
     * Note this value is returned internally to PHP for processing.
     * </p>
     * @since 5.4.0
     */
    public function read($session_id)
    {
        if (isset($_COOKIE[$this->name])) {
            try {
                $token = (array)JWT::decode($_COOKIE[$this->name], $this->secret_key, [self::ALGORITHM]);
                return $token["data"];
            } catch (Exception $exception) {
                return '';
            }
        }
        return '';
    }

    /**
     * Write session data
     * @link http://php.net/manual/en/sessionhandlerinterface.write.php
     * @link https://tools.ietf.org/html/rfc7519#section-4.1
     * @param string $session_id The session id.
     * @param string $session_data <p>
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
     * @since 5.4.0
     */
    public function write($session_id, $session_data)
    {
        $tokenId = $session_id;
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
            'data' => $session_data    // Session data
        ];
        $jwt = JWT::encode($token, $this->secret_key, self::ALGORITHM);
        $time = strtotime('+2 years');
        if ($this->expireOnClose) {
            $time = 0;
        }
        if (PHP_VERSION_ID < 70300) {
            return setcookie($this->name, $jwt, $time, '/; SameSite=Strict', $this->domain);
        } else {
            return setcookie($this->name, $jwt, [
                'expires' => $time,
                'path' => '/',
                'domain' => $this->domain,
                'samesite' => 'Strict'
            ]);
        }
    }
}