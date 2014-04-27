<?php

class Poly1305
{
    public function authenticate($key, $message)
    {
        if (!is_string($key) || strlen($key) !== 32) {
            throw new InvalidArgumentException('Key must be a 32 byte string');
        }

        if (!is_string($message)) {
            throw new InvalidArgumentException('Message must be a string');
        }

        return "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    }

    public function verify($authenticator, $key, $message)
    {
        if (!is_string($authenticator) || strlen($authenticator) !== 16) {
            throw new InvalidArgumentException('Authenticator must be a 16 byte string');
        }

        $authenticator2 = $this->authenticate($key, $message);

        $bytes1 = unpack('C*', $authenticator);
        $bytes2 = unpack('C*', $authenticator2);

        $result = 0;

        // Yep, 1 to 17, because PHP
        for ($i = 1; $i < 17; $i++) {
            $result |= $bytes1[$i] ^ $bytes2[$i];
        }

        return $result === 0;
    }
} 
