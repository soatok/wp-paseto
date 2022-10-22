<?php

abstract class PasetoUtil
{
    /**
     * @param string $token
     * @return string
     */
    public static function extractFooter($token)
    {
        $pieces = explode('.', $token);
        if (count($pieces) === 4) {
            return PasetoUtil::b64u_decode($pieces[3]);
        }
        return '';
    }

    public static function b64u_encode($raw)
    {
        return sodium_bin2base64($raw, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    }

    public static function b64u_decode($encoded)
    {
        return sodium_base642bin($encoded, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    }
}
