<?php

class Poly1305BCMath
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

        $h = '0';
        $p = '1361129467683753853853498429727072845819';

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
            $h = $this->div_r(
                bcmul(bcadd(bcadd($c, $h), bcpow('2', $j  << 3)), $r), $p
            );

            $offset += $j;
            $l -= $j;
        }

        $h = bcadd($h, $s);

        $out = [];
        for ($j = 0; $j < 16; $j++) {
            $out[$j] = $this->div_r($h, 256);
            $h = bcdiv($h, 256);
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

    private function div_r($l, $r)
    {
        return bcsub($l, bcmul(bcdiv($l, $r), $r));
    }

    private function import($bin)
    {
        $c = unpack('C*', $bin);

        $i = count($c);
        $ret = $c[$i--];
        while ($i) {
            $ret = bcadd(bcmul($ret, 256), $c[$i--]);
        }

        return $ret;
    }
}
