<?php

namespace Poly1305;

if (PHP_INT_SIZE > 4) {
    function poly1305_gmp_import($bin)
    {
        // r, s and all except one message block (maybe) will be 16 bytes
        if (strlen($bin) < 16) {
            $bin = str_pad($bin, 16, "\0", STR_PAD_RIGHT);
        }

        $w = unpack('V4', $bin);

        // looks a littlemad but it propagates the GMP object downwards
        return (((((
            gmp_init($w[4]) << 32) |
                     $w[3]) << 32) |
                     $w[2]) << 32) |
                     $w[1];
    }
}
else {
    function poly1305_gmp_import($bin)
    {
        $binLen = strlen($bin);

        // r, s and all except one message block (maybe) will be 16 bytes
        if ($binLen === 16) {
            $w = unpack('v8', $bin);
            // looks mad but it propagates the GMP object downwards
            return (((((((((((((
                gmp_init($w[8]) << 16) |
                         $w[7]) << 16) |
                         $w[6]) << 16) |
                         $w[5]) << 16) |
                         $w[4]) << 16) |
                         $w[3]) << 16) |
                         $w[2]) << 16) |
                         $w[1];
        }

        $words = $binLen >> 1;
        $w = unpack("v$words", $bin);

        if ($binLen & 1) {
            $ret = gmp_init(ord($bin[$binLen ^ 1]));
        }
        else {
            $ret = gmp_init($w[$words--]);
        }

        while ($words) {
            $ret = ($ret << 16) | $w[$words--];
        }

        return $ret;
    }
}

class ContextGMP
{
    public $r;
    public $s;
    public $h;
    public $buffer;
}

class GMP
{
    private $p;
    private $one;

    function __construct()
    {
        $this->one = gmp_init('1');
        $this->p = gmp_init('3fffffffffffffffffffffffffffffffb', 16);
    }

    function init(ContextGMP $ctx, $key)
    {
        if (!is_string($key) || strlen($key) !== 32) {
            throw new \InvalidArgumentException('Key must be a 32 byte string');
        }

        $ctx->r = poly1305_gmp_import($key & "\xff\xff\xff\x0f\xfc\xff\xff\x0f\xfc\xff\xff\x0f\xfc\xff\xff\x0f");
        $ctx->s = poly1305_gmp_import(substr($key, 16));
        $ctx->h = gmp_init('0');
        $ctx->buffer = '';
    }

    function blocks(ContextGMP $ctx, $message)
    {
        if (!($ctx->h instanceof \GMP)) {
            throw new \InvalidArgumentException('Context not initialised');
        }

        if (!is_string($message)) {
            throw new \InvalidArgumentException('Message must be a string');
        }

        $msgLen = strlen($message);

        if ($ctx->buffer) {
            $bufferLen = strlen($ctx->buffer);
            $offset = 16 - $bufferLen;
            if ($msgLen + $bufferLen >= 16) {
                $c = poly1305_gmp_import($ctx->buffer . substr($message, 0, $offset));
                $ctx->h = gmp_div_r(($c + $ctx->h + ($this->one << 128)) * $ctx->r, $this->p);
                $ctx->buffer = '';
            }
            else {
                $ctx->buffer .= $message;
                return;
            }
        }
        else {
            $offset = 0;
        }

        $blocks = ($msgLen - $offset) >> 4;

        while ($blocks--) {
            $c = poly1305_gmp_import(substr($message, $offset, 16));
            $ctx->h = gmp_div_r(($c + $ctx->h + ($this->one << 128)) * $ctx->r, $this->p);
            $offset += 16;
        }

        if ($offset < $msgLen) {
            $ctx->buffer = substr($message, $offset);
        }
    }

    function finish(ContextGMP $ctx)
    {
        if (!($ctx->h instanceof \GMP)) {
            throw new \InvalidArgumentException('Context not initialised');
        }

        if ($ctx->buffer) {
            $c = poly1305_gmp_import($ctx->buffer);
            $ctx->h = gmp_div_r(($c + $ctx->h + ($this->one << (strlen($ctx->buffer) << 3))) * $ctx->r, $this->p);
        }

        $ctx->h += $ctx->s;

        $out = [];
        for ($j = 0; $j < 16; $j++) {
            list($ctx->h, $out[$j]) = gmp_div_qr($ctx->h, 256);
        }

        $ctx = new ContextGMP();

        return pack('C16', ...$out);
    }

    public function authenticate($key, $message)
    {
        $ctx = new ContextGMP();
        $this->init($ctx, $key);
        $this->blocks($ctx, $message);
        return $this->finish($ctx);
    }

    public function verify($authenticator, $key, $message)
    {
        if (!is_string($authenticator) || strlen($authenticator) !== 16) {
            throw new \InvalidArgumentException('Authenticator must be a 16 byte string');
        }

        return hash_equals($authenticator, $this->authenticate($key, $message));
    }
}
