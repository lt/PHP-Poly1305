<?php

namespace Poly1305 {
    if (!extension_loaded('poly1305')) {
        if (extension_loaded('gmp')) {
            if (version_compare(PHP_VERSION, '5.6.1') >= 0) {
                class Authenticator extends GMP {}
            }
            else {
                class Authenticator extends GMPLegacy {}
            }
        }
        else {
            class Authenticator extends Native {}
        }

        function auth($key, $message)
        {
            $p = new Authenticator();
            $c = new Context();
            $p->init($c, $key);
            $p->update($c, $message);
            return $p->finish($c);
        }

        function verify($mac, $key, $message)
        {
            if (!is_string($mac) || strlen($mac) !== 16) {
                throw new \InvalidArgumentException('MAC must be a 16 bytes');
            }

            return hash_equals($mac, auth($key, $message));
        }
    }
}

namespace {
    if (!function_exists('hash_equals')) {
        function hash_equals($known_string, $user_string)
        {
            $knownLen = strlen($known_string);
            $userLen = strlen($user_string);
            $result = $knownLen ^ $userLen;

            for ($i = 0; $i < $knownLen; $i++) {
                $result |= ord($known_string[$i] ^ $user_string[$i % $userLen]);
            }

            return $result === 0;
        }
    }
}
