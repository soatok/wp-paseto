<?php

class WP_Paseto
{
    /** @var PasetoKeyManager $handler */
    private $handler;

    /** @var array<string, string> */
    private $expectedClaims = array();

    /** @var ?DateInterval $lifetime */
    private $lifetime;

    /**
     * @param array<string, scalar> $keySet
     */
    public function __construct(array $keySet = array(), DateInterval $lifetime = null)
    {
        $this->handler = new PasetoKeyManager($keySet);
        $this->lifetime = $lifetime;
    }

    /**
     * @param string $audience
     * @return self
     */
    public function setAudience($audience)
    {
        $this->expectedClaims['aud'] = $audience;
        return $this;
    }

    /**
     * @param string $id
     * @return self
     */
    public function setIdentifier($id)
    {
        $this->expectedClaims['jti'] = $id;
        return $this;
    }

    /**
     * @param string $issuer
     * @return self
     */
    public function setIssuer($issuer)
    {
        $this->expectedClaims['iss'] = $issuer;
        return $this;
    }

    /**
     * @param string $subject
     * @return self
     */
    public function setSubject($subject)
    {
        $this->expectedClaims['sub'] = $subject;
        return $this;
    }

    /**
     * @param array<string, scalar> $claims
     * @param ?string $key_id
     * @param string $implicit
     * @return string
     * @throws PasetoException
     */
    public function encode(array $claims, $key_id = null, $implicit = '')
    {
        $now = (new DateTime('NOW'))->format(DATE_ATOM);

        // Only add these if we have a lifetime
        if (!is_null($this->lifetime)) {
            if (empty($claims['nbf'])) {
                $claims['nbf'] = $now;
            }
            if (empty($claims['iat'])) {
                $claims['iat'] = $now;
            }
            if (empty($claims['exp'])) {
                $claims['exp'] = (new DateTime('NOW'))
                    ->add($this->lifetime)
                    ->format(DATE_ATOM);
            }
        }
        foreach ($this->expectedClaims as $key => $value) {
            $claims[$key] = $value;
        }

        if (is_null($key_id)) {
            $keys = $this->handler->getKeyIDs();
            $key_id = array_pop($keys);
        }
        return $this->handler->encrypt(json_encode($claims), $key_id, $implicit);
    }

    /**
     * @param string $token
     * @param string $implicit
     * @param bool $skip_validation
     * @return array<string, scalar>
     * @throws PasetoException
     */
    public function decode($token, $implicit = '', $skip_validation = false)
    {
        $jsonString = $this->handler->decrypt($token, $implicit);
        $claims = json_decode($jsonString, true);
        if ($skip_validation) {
            return $claims;
        }
        return $this->validate($claims);
    }

    /**
     * @param array<string, string> $claims
     * @return array<string, string>
     *
     * @throws PasetoException
     * @throws SodiumException
     */
    public function validate(array $claims)
    {
        $now = new DateTime('NOW');

        // If we have expiration:
        if (!is_null($this->lifetime)) {
            if (isset($claims['exp'])) {
                $exp = new DateTime($claims['exp']);
                if ($now > $exp) {
                    throw new PasetoException('This token has expired');
                }
            }
            if (isset($claims['nbf'])) {
                $nbf = new DateTime($claims['nbf']);
                if ($now < $nbf) {
                    throw new PasetoException('This token has expired');
                }
            }
        }

        // Handle any literal claims:
        foreach ($this->expectedClaims as $key => $value) {
            if (!array_key_exists($key, $claims)) {
                throw new PasetoException('Expected claim "' .$key . '" not found!');
            }
            if (!ParagonIE_Sodium_Core_Util::hashEquals($value, $claims[$key])) {
                throw new PasetoException('Expected claim "' .$key . '" has unexpected value');
            }
        }

        return $claims;
    }
}
