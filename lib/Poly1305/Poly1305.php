<?php

if (extension_loaded('poly1305')) {
    // TODO: Fix extension
}
else {
    if (extension_loaded('gmp') && PHP_MAJOR_VERSION >= 5 && PHP_MINOR_VERSION >= 6) {
        require 'Poly1305GMP.php';
        class Poly1305 extends Poly1305\GMP {}
        class Poly1305Context extends Poly1305\ContextGMP {}
    }
    elseif (PHP_INT_SIZE > 4 && PHP_MAJOR_VERSION >= 5 && PHP_MINOR_VERSION >= 6) {
        require 'Poly1305Native.php';
        class Poly1305 extends Poly1305\Native {}
        class Poly1305Context extends Poly1305\ContextNative {}
    }
    else {
        require 'Poly1305Legacy.php';
        class Poly1305 extends Poly1305\Legacy {}
        class Poly1305Context extends Poly1305\ContextLegacy {}
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
