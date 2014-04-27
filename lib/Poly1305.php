<?php

class Poly1305
{
    private $h;

    public function authenticate($key, $message)
    {
        if (!is_string($key) || strlen($key) !== 32) {
            throw new InvalidArgumentException('Key must be a 32 byte string');
        }

        if (!is_string($message)) {
            throw new InvalidArgumentException('Message must be a string');
        }

        $this->h = [-1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];

        $r = unpack('C16', $key);
        $s = unpack('@16/C16', $key);

        // Clamp
        $r[4] &= 0x0f;
        $r[5] &= 0xfc;
        $r[8] &= 0x0f;
        $r[9] &= 0xfc;
        $r[12] &= 0x0f;
        $r[13] &= 0xfc;
        $r[16] &= 0x0f;

        $r[17] = 0;
        $s[17] = 0;

        $bytesLeft = strlen($message);
        $offset = 0;
        while ($bytesLeft > 0) {
            $hr = [];

            /* h += m */
            if ($bytesLeft >= 16) {
                $c = unpack("@$offset/C16", $message);
                $c[17] = 1;
            }
            else {
                $c = unpack("C17", substr($message, $offset, 16) . "\1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
            }

            $this->add($c);

            /* h *= r */
            for ($i = 1; $i < 18; $i++) {
                $u = 0;
                for ($j = 1; $j <= $i; $j++) {
                    $u += $this->h[$j] * $r[$i + 1 - $j];
                }
                for ($j = $i + 1; $j < 18; $j++) {
                    $u += $this->h[$j] * $r[$i + 18 - $j] * 320;
                }
                $hr[$i] = $u;
            }

            /* (partial) h %= p */
            for ($u = 0, $i = 1; $i < 17; $i++, $u >>= 8) {
                $u += $hr[$i];
                $this->h[$i] = $u & 0xff;
            }
            $u += $hr[17];
            $this->h[17] = $u & 0x03;
            $u >>= 2;
            $u += ($u << 2); /* u *= 5; */
            for ($i = 1; $i < 17; $i++) {
                $u += $this->h[$i];
                $this->h[$i] = $u & 0xff;
                $u >>= 8;
            }
            $this->h[17] += $u;

            $offset += 16;
            $bytesLeft -= 16;
        }

        $horig = $this->h;
        /* compute h + -p */
        $this->add([-1,5,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0xfc]);
        /* select h if h < p, or h + -p if h >= p */
        $negative = -($this->h[17] >> 7);
        for ($i = 1; $i < 18; $i++) {
            $this->h[$i] ^= $negative & ($horig[$i] ^ $this->h[$i]);
        }
        /* h = (h + pad) % (1 << 128) */
        $this->add($s);

        $authenticator = '';
        for ($i = 1; $i < 17; $i++) {
            $authenticator .= chr($this->h[$i]);
        }

        return $authenticator;
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

    public function add(array $c)
    {
        for ($u = 0, $i = 1; $i < 18; $i++, $u >>= 8) {
            $u += $this->h[$i] + $c[$i];
            $this->h[$i] = $u & 0xff;
        }
    }
}

if (!function_exists('poly1305_authenticate')) {
    function poly1305_authenticate($key, $message) {
        return (new Poly1305)->authenticate($key, $message);
    }

    function poly1305_verify($authenticator, $key, $message) {
        return (new Poly1305)->verify($authenticator, $key, $message);
    }
}