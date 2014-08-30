<?php

namespace Poly1305;

class Native32
{
    private $h;

    public function authenticate($key, $message)
    {
        if (!is_string($key) || strlen($key) !== 32) {
            throw new \InvalidArgumentException('Key must be a 32 byte string');
        }

        if (!is_string($message)) {
            throw new \InvalidArgumentException('Message must be a string');
        }

        $this->h = array('C16',0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);

        // Clamp
        $r = unpack('C17', $key & "\xff\xff\xff\x0f\xfc\xff\xff\x0f\xfc\xff\xff\x0f\xfc\xff\xff\x0f\0");
        $s = unpack('@16/C16', $key);

        $s[17] = 0;

        $bytesLeft = strlen($message);
        $offset = 0;
        while ($bytesLeft > 0) {
            $hr = array();

            /* h += m */
            if ($bytesLeft >= 16) {
                $c = unpack("@$offset/C16", $message);
                $c[17] = 1;
            }
            else {
                $c = unpack("@$offset/C*", $message) +
                    array($bytesLeft + 1 => 1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);
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
            $this->add(array(1 => $u + ($u << 2),0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0));

            $offset += 16;
            $bytesLeft -= 16;
        }

        $horig = $this->h;
        /* compute h + -p */
        $this->add(array(1 => 5,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0xfc));
        /* select h if h < p, or h + -p if h >= p */
        $negative = -($this->h[17] >> 7);
        for ($i = 1; $i < 18; $i++) {
            $this->h[$i] ^= $negative & ($horig[$i] ^ $this->h[$i]);
        }
        /* h = (h + pad) % (1 << 128) */
        $this->add($s);

        unset($this->h[17]);
        return call_user_func_array('pack', $this->h);
    }

    public function verify($authenticator, $key, $message)
    {
        if (!is_string($authenticator) || strlen($authenticator) !== 16) {
            throw new \InvalidArgumentException('Authenticator must be a 16 byte string');
        }

        $authenticator2 = $this->authenticate($key, $message);

        $bytes1 = unpack('C16', $authenticator);
        $bytes2 = unpack('C16', $authenticator2);

        $result = 0;

        // Yep, 1 to 17, because PHP
        for ($i = 1; $i < 17; $i++) {
            $result |= $bytes1[$i] ^ $bytes2[$i];
        }

        return $result === 0;
    }

    private function add(array $c)
    {
        for ($u = 0, $i = 1; $i < 18; $i++, $u >>= 8) {
            $u += $this->h[$i] + $c[$i];
            $this->h[$i] = $u & 0xff;
        }
    }
}
