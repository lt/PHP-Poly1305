<?php

namespace Poly1305;

if (0 && extension_loaded('poly1305')) {
    // TODO: Fix extension
}
else {
    if (extension_loaded('gmp') && PHP_MAJOR_VERSION >= 5 && PHP_MINOR_VERSION >= 6) {
        class Poly1305 extends GMP {}
    }
    elseif (PHP_INT_SIZE > 4) {
        class Poly1305 extends Native64 {}
    }
    else {
        class Poly1305 extends Native32 {}
    }

    function poly1305_authenticate($key, $message) {
        $poly1305 = new Poly1305();
        return $poly1305->authenticate($key, $message);
    }

    function poly1305_verify($authenticator, $key, $message) {
        $poly1305 = new Poly1305();
        return $poly1305->verify($authenticator, $key, $message);
    }

    if (!function_exists('hash_equals')) {
        function hash_equals($known, $user)
        {
            $knownLen = strlen($known);
            $userLen = strlen($user);
            $result = $knownLen ^ $userLen;

            for ($i = 0; $i < $knownLen; $i++) {
                $result |= ord($known[$i] ^ $user[$i % $userLen]);
            }

            return $result === 0;
        }
    }
}
