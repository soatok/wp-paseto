<?php
require_once __DIR__ . '/vendor/autoload.php';

spl_autoload_register(function ($name) {
    switch ($name) {
        case 'PasetoV4LocalTest':
        case 'WP_PasetoTest':
            require_once __DIR__ . '/test/' . $name . '.php';
            break;
        default:
    }
});
