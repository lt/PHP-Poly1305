<?php

class Poly1305GMP
{
    public function authenticate($key, $message)
    {
        if (!is_string($key) || strlen($key) !== 32) {
            throw new InvalidArgumentException('Key must be a 32 byte string');
        }

        if (!is_string($message)) {
            throw new InvalidArgumentException('Message must be a string');
        }

        $r = $this->import($key & "\xff\xff\xff\x0f\xfc\xff\xff\x0f\xfc\xff\xff\x0f\xfc\xff\xff\x0f");
        $s = $this->import(substr($key, 16));

        $h = gmp_init('0');
        $p = gmp_init('3fffffffffffffffffffffffffffffffb', 16);

        $l = strlen($message);
        $offset = 0;

        while ($l) {
            if ($l < 16) {
                $j = $l;
            }
            else {
                $j = 16;
            }

            $c = $this->import(substr($message, $offset, $j));
            $h = gmp_div_r(($c + $h + (gmp_init('1') << ($j << 3))) * $r, $p);

            $offset += $j;
            $l -= $j;
        }

        $h += $s;

        $out = [];
        for ($j = 0; $j < 16; $j++) {
            list($h, $out[$j]) = gmp_div_qr($h, 256);
        }

        return pack('C16', ...$out);
    }

    public function verify($authenticator, $key, $message)
    {
        if (!is_string($authenticator) || strlen($authenticator) !== 16) {
            throw new InvalidArgumentException('Authenticator must be a 16 byte string');
        }

        return hash_equals($authenticator, $this->authenticate($key, $message));
    }

    private function import($bin)
    {
        $c = unpack('C*', $bin);

        $i = count($c);
        $ret = gmp_init($c[$i--]);
        while ($i) {
            $ret = ($ret << 8) | $c[$i--];
        }

        return $ret;
    }
}
