<?php

class Poly1305
{
    private $h;
    private $final = 0;

    public function authenticate($key, $message)
    {
        if (!is_string($key) || strlen($key) !== 32) {
            throw new InvalidArgumentException('Key must be a 32 byte string');
        }

        if (!is_string($message)) {
            throw new InvalidArgumentException('Message must be a string');
        }

        $this->h = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];

        $keyBytes = array_values(unpack('C*', $key));
        $this->r = array_slice($keyBytes, 0, 16);
        $s = array_slice($keyBytes, 16);

        // Clamp
        $this->r[3] &= 0x0f;
        $this->r[4] &= 0xfc;
        $this->r[7] &= 0x0f;
        $this->r[8] &= 0xfc;
        $this->r[11] &= 0x0f;
        $this->r[12] &= 0xfc;
        $this->r[15] &= 0x0f;

        $this->r[16] = 0;
        $s[16] = 0;

        $bytes = strlen($message);
        $want = 0;
        $this->final = 0;

        if ($bytes >= 16) {
            $want = ($bytes & ~15);
            $this->blocks($message, $want);
            $bytes -= $want;
        }

        /* store leftover */
        if ($bytes) {
            $buffer = substr($message, $want, $bytes) . "\1" . str_repeat("\0", 16 - $bytes - 1);

            $this->final = 1;
            $this->blocks($buffer, 16);
        }

        $horig = $this->h;
        /* compute h + -p */
        $this->add([5,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0xfc]);
        /* select h if h < p, or h + -p if h >= p */
        $negative = -($this->h[16] >> 7);
        for ($i = 0; $i < 17; $i++) {
            $this->h[$i] ^= $negative & ($horig[$i] ^ $this->h[$i]);
        }
        /* h = (h + pad) % (1 << 128) */
        $this->add($s);

        $authenticator = '';
        for ($i = 0; $i < 16; $i++) {
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

    public function blocks($m, $bytes)
    {
        $hibit = $this->final ^ 1; /* 1 << 128 */
        $offset = 0;
        while ($bytes >= 16) {
            $hr = [];
            $c = [];

            /* h += m */
            for ($i = 0; $i < 16; $i++)
                $c[$i] = ord($m[$offset + $i]);
            $c[16] = $hibit;
            $this->add($c);

            /* h *= r */
            for ($i = 0; $i < 17; $i++) {
                $u = 0;
                for ($j = 0; $j <= $i; $j++) {
                    $u += $this->h[$j] * $this->r[$i - $j];
                }
                for ($j = $i + 1; $j < 17; $j++) {
                    $u += $this->h[$j] * $this->r[$i + 17 - $j] * 320;
                }
                $hr[$i] = $u;
            }

            /* (partial) h %= p */
            for ($u = 0, $i = 0; $i < 16; $i++, $u >>= 8) {
                $u += $hr[$i];
                $this->h[$i] = $u & 0xff;
            }
            $u += $hr[16];
            $this->h[16] = $u & 0x03;
            $u >>= 2;
            $u += ($u << 2); /* u *= 5; */
            for ($i = 0; $i < 16; $i++) {
                $u += $this->h[$i];
                $this->h[$i] = $u & 0xff;
                $u >>= 8;
            }
            $this->h[16] += $u;

            $offset += 16;
            $bytes -= 16;
        }
    }

    public function add(array $c)
    {
        for ($u = 0, $i = 0; $i < 17; $i++, $u >>= 8) {
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