<?php

class PasetoKeyManager
{
    /** @var array<string, PasetoV4Local> $keySet */
    private $keySet = array();

    public function __construct($keys)
    {
        foreach ($keys as $key_id => $raw_key) {
            $this->addKey($key_id, $raw_key);
        }
    }

    /**
     * @return string[]
     */
    public function getKeyIDs()
    {
        return array_keys($this->keySet);
    }

    /**
     * @param string $message
     * @param string $key_id
     * @param string $implicit
     * @return string
     * @throws PasetoException
     * @throws SodiumException
     */
    public function encrypt($message, $key_id = '', $implicit = '')
    {
        if (empty($this->keySet)) {
            throw new PasetoException("No KeySet provided");
        }
        if (!array_key_exists($key_id, $this->keySet)) {
            throw new PasetoException("Key ID {$key_id} is not defined");
        }
        /** @var PasetoV4Local $encryptor */
        $encryptor = $this->keySet[$key_id];
        return $encryptor->encrypt($message, $key_id, $implicit);
    }

    /**
     * @param string $token
     * @param string $implicit
     * @return string
     * @throws PasetoException
     * @throws SodiumException
     */
    public function decrypt($token, $implicit = '')
    {
        if (empty($this->keySet)) {
            throw new PasetoException("No KeySet provided");
        }

        $key_id = PasetoUtil::extractFooter($token);
        if (empty($key_id)) {
            throw new PasetoException("Invalid number of components");
        }
        if (!array_key_exists($key_id, $this->keySet)) {
            throw new PasetoException("Key ID {$key_id} is not defined");
        }
        /** @var PasetoV4Local $encryptor */
        $decryptor = $this->keySet[$key_id];
        return $decryptor->decrypt($token, $implicit);
    }

    /**
     * @param string $key_id
     * @param string $raw_key
     * @return self
     * @throws PasetoException
     */
    public function addKey(
        $key_id,
        #[\SensitiveParameter]
        $raw_key
    ) {
        if (array_key_exists($key_id, $this->keySet)) {
            throw new PasetoException("Key ID {$key_id} is already defined");
        }
        $this->keySet[$key_id] = new PasetoV4Local($raw_key);
        return $this;
    }
}
