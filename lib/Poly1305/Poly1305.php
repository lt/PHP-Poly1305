<?php

namespace Poly1305;

if (extension_loaded('poly1305')) {
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
}
