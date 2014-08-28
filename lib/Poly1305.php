<?php

if (extension_loaded('poly1305')) {
    class Poly1305 {
        function authenticate($key, $message)
        {
            return poly1305_authenticate($key, $message);
        }

        function verify($authenticator, $key, $message)
        {
            return poly1305_verify($authenticator, $key, $message);
        }
    }
}
else {
    if (PHP_MAJOR_VERSION >= 5 && PHP_MINOR_VERSION >= 6) {
        if (extension_loaded('gmp')) {
            require 'Poly1305GMP.php';
            class Poly1305 extends Poly1305GMP {}
        }
        elseif (extension_loaded('bcmath')) {
            require 'Poly1305BCMath.php';
            class Poly1305 extends Poly1305BCMath {}
        }
        else {
            require 'Poly1305Native.php';
            class Poly1305 extends Poly1305BCMath {}
        }
    }
    else {
        require 'Poly1305Legacy.php';
        class Poly1305 extends Poly1305Legacy {}
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
