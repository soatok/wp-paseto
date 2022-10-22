<?php

/**
 * @ref https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md
 */
class PasetoV4Local
{
    const HEADER = 'v4.local.';

    /** @var string $secretKey */
    private $secretKey;

    /**
     * @param string $secretKey
     */
    public function __construct(
        #[\SensitiveParameter]
        $secretKey
    ) {
        if (ParagonIE_Sodium_Core_Util::strlen($secretKey) !== 32) {
            throw new PasetoException('Secret key must be 32 bytes (256 bits)');
        }
        $this->secretKey = $secretKey;
    }

    /**
     * @param string $token
     * @param string $expectedFooter
     * @return void
     * @throws PasetoException
     * @throws SodiumException
     */
    public function assertFooter($token, $expectedFooter)
    {
        $footer = PasetoUtil::extractFooter($token);
        if (!ParagonIE_Sodium_Core_Util::hashEquals($footer, $expectedFooter)) {
            throw new PasetoException("Footer assertion failed.");
        }
    }

    /**
     * @param string $message
     * @param string $footer
     * @param string $implicit
     * @return string
     * @throws SodiumException
     */
    public function encrypt(
        $message,
        $footer = '',
        $implicit = ''
    ) {
        /// Step 2
        $h = self::HEADER;

        /// Step 3
        $n = random_bytes(32);

        /// Step 4
        list($Ek, $n2, $Ak) = $this->splitKeys($n);

        /// Step 5
        $c = sodium_crypto_stream_xchacha20_xor(
            $message,
            $n2,
            $Ek
        );

        /// Step 6
        $preAuth = $this->preAuthEncode($h, $n, $c, $footer, $implicit);

        /// Step 7
        $t = sodium_crypto_generichash($preAuth, $Ak);

        // Wipe memory if we can
        try {
            sodium_memzero($Ek);
            sodium_memzero($Ak);
            sodium_memzero($n2);
        } catch (SodiumException $ex) {
            $Ek ^= $Ek;
            $Ak ^= $Ak;
            $n2 ^= $n2;
        }

        if (empty($footer)) {
            return $h . PasetoUtil::b64u_encode($n . $c . $t);
        }
        return $h . PasetoUtil::b64u_encode($n . $c . $t) . '.' . PasetoUtil::b64u_encode($footer);
    }

    /**
     * @param string $token
     * @param string $implicit
     * @param ?string $expectedFooter
     * @return string
     * @throws PasetoException
     * @throws SodiumException
     */
    public function decrypt($token, $implicit = '', $expectedFooter = null)
    {
        /// Step 3
        $header = ParagonIE_Sodium_Core_Util::substr($token, 0, 9);
        if (!ParagonIE_Sodium_Core_Util::hashEquals($header, self::HEADER)) {
            throw new PasetoException('Incorrect protocol version');
        }
        $pieces = explode('.', $token);
        if (count($pieces) === 4) {
            $footer = PasetoUtil::b64u_decode($pieces[3]);
        } elseif (count($pieces) === 3) {
            $footer = '';
        } else {
            throw new PasetoException('Token has incorrect number of separators');
        }
        if (!is_null($expectedFooter)) {
            $this->assertFooter($footer, $expectedFooter);
        }

        /// Step 4
        $payload = PasetoUtil::b64u_decode($pieces[2]);
        $n = ParagonIE_Sodium_Core_Util::substr($payload, 0, 32);
        $t = ParagonIE_Sodium_Core_Util::substr($payload, -32, 32);
        $c = ParagonIE_Sodium_Core_Util::substr($payload, 32, -32);

        /// Step 5
        list($Ek, $n2, $Ak) = $this->splitKeys($n);

        /// Step 6
        $preAuth = $this->preAuthEncode($header, $n, $c, $footer, $implicit);

        /// Step 7
        $t2 = sodium_crypto_generichash($preAuth, $Ak);

        try {
            /// Step 8
            if (!ParagonIE_Sodium_Core_Util::hashEquals($t2, $t)) {
                throw new PasetoException('Token has been tampered with');
            }

            /// Step 9
            return sodium_crypto_stream_xchacha20_xor($c, $n2, $Ek);
        } finally {
            try {
                sodium_memzero($Ek);
                sodium_memzero($Ak);
                sodium_memzero($n2);
            } catch (SodiumException $ex) {
                $Ek ^= $Ek;
                $Ak ^= $Ak;
                $n2 ^= $n2;
            }
        }
    }

    /**
     * @param string $n
     * @return array<int, string>
     *
     * @throws \SodiumException
     */
    protected function splitKeys($n)
    {
        $tmp = sodium_crypto_generichash(
            'paseto-encryption-key' . $n,
            $this->secretKey,
            56
        );
        $Ek = ParagonIE_Sodium_Core_Util::substr($tmp, 0, 32);
        $n2 = ParagonIE_Sodium_Core_Util::substr($tmp, 32);
        $Ak = sodium_crypto_generichash(
            'paseto-auth-key-for-aead' . $n,
            $this->secretKey,
            32
        );
        return array($Ek, $n2, $Ak);
    }

    /**
     * @param ...string $params
     * @return string
     */
    protected function preAuthEncode()
    {
        $params = func_get_args();
        $num = func_num_args();
        $accumulator =  pack('P', $num);
        for ($i = 0; $i < $num; ++$i) {
            $length = ParagonIE_Sodium_Core_Util::strlen($params[$i]);
            $accumulator .= pack('P', $length);
            $accumulator .= $params[$i];
        }
        return $accumulator;
    }
}
