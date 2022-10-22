# PASETO for WordPress

[![Build Status](https://github.com/soatok/wp-paseto/actions/workflows/ci.yml/badge.svg)](https://github.com/soatok/wp-paseto/actions)
[![Static Analysis](https://github.com/soatok/wp-paseto/actions/workflows/psalm.yml/badge.svg)](https://github.com/soatok/wp-paseto/actions)
[![Latest Stable Version](https://poser.pugx.org/soatok/wp-paseto/v/stable)](https://packagist.org/packages/soatok/wp-paseto)
[![Latest Unstable Version](https://poser.pugx.org/soatok/wp-paseto/v/unstable)](https://packagist.org/packages/soatok/wp-paseto)
[![License](https://poser.pugx.org/soatok/wp-paseto/license)](https://packagist.org/packages/soatok/wp-paseto)
[![Downloads](https://img.shields.io/packagist/dt/soatok/wp-paseto.svg)](https://packagist.org/packages/soatok/wp-paseto)

Requirements:

* PHP 5.6 or newer

Recommended:

* PHP 7.2 or newer
* Sodium extension

Supports key rotation. Implements `v4.local.` only!

## Installing

```terminal
composer require soatok/wp-paseto
```

## Usage

Provide an array of `key id strings` mapped to hex-encoded keys to the constructor.
Then you can `encode()` and `decode()` arrays containing arbitrary claims.

```php
<?php
// Define your keys
$encoder = new WP_Paseto((
    'key-id-1' => 'hex-encoded 256-bit (32 byte) random key goes here',
    'key-id-2' => 'hex-encoded 256-bit (32 byte) random key goes here',
    // ...
    'key-id-N' =>L 'hex-encoded 256-bit (32 byte) random key goes here'
));

// Encode a secret
$token = $encoder->encode(array('secret' => 'value goes here'));

var_dump($token);
/* v4.local.fHvh8jwJauiNMdC0yRZ9xvbCE5cdrNwP4... */

// Decode
$claims = $encoder->decode($token);
```
