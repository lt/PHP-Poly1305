<?php declare(strict_types = 1);

namespace Poly1305;

if (!extension_loaded('poly1305')) {
    function authenticate(string $key, string $message): string
    {
        $authenticator = new Authenticator();
        $context = $authenticator->init($key);
        $authenticator->update($context, $message);
        return $authenticator->finish($context);
    }

    function verify(string $mac, string $key, string $message): string
    {
        if (strlen($mac) !== 16) {
            throw new \InvalidArgumentException('MAC must be a 128-bit string.');
        }

        return hash_equals($mac, authenticate($key, $message));
    }
}