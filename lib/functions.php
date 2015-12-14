<?php

namespace Poly1305 {
    if (!extension_loaded('poly1305')) {
        function authenticate($key, $message)
        {
            $authenticator = new Authenticator();
            $context = $authenticator->init($key);
            $authenticator->update($context, $message);
            return $authenticator->finish($context);
        }

        function verify($mac, $key, $message)
        {
            if (!is_string($mac) || strlen($mac) !== 16) {
                throw new \InvalidArgumentException('MAC must be a 128-bit string.');
            }

            return hash_equals($mac, authenticate($key, $message));
        }
    }
}

namespace {
    if (!function_exists('hash_equals')) {
        function hash_equals($knownString, $userString)
        {
            $knownLen = strlen($knownString);
            $userLen = strlen($userString);
            $result = $knownLen ^ $userLen;

            for ($i = 0; $i < $knownLen; $i++) {
                $result |= ord($knownString[$i] ^ $userString[$i % $userLen]);
            }

            return $result === 0;
        }
    }
}
