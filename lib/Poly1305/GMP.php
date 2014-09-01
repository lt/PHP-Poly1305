<?php

namespace Poly1305;

class GMP
{
    private $p;
    private $one;

    function __construct()
    {
        $this->one = gmp_init('1');
        $this->p = gmp_init('3fffffffffffffffffffffffffffffffb', 16);
    }

    function init(Context $ctx, $key)
    {
        if (!is_string($key) || strlen($key) !== 32) {
            throw new \InvalidArgumentException('Key must be a 32 bytes');
        }

        $ctx->r = gmp_init(bin2hex(strrev($key & "\xff\xff\xff\x0f\xfc\xff\xff\x0f\xfc\xff\xff\x0f\xfc\xff\xff\x0f")), 16);
        $ctx->s = gmp_init(bin2hex(strrev(substr($key, 16))), 16);
        $ctx->h = gmp_init('0');
        $ctx->buffer = '';
        $ctx->type = __CLASS__;
    }

    function update(Context $ctx, $message)
    {
        if (!property_exists($ctx, 'type') || $ctx->type !== __CLASS__) {
            throw new \InvalidArgumentException('Invalid Context');
        }

        if (!is_string($message)) {
            throw new \InvalidArgumentException('Message must be a string');
        }

        $msgLen = strlen($message);

        if ($ctx->buffer) {
            $bufferLen = strlen($ctx->buffer);
            $offset = 16 - $bufferLen;
            if ($msgLen + $bufferLen >= 16) {
                $c = gmp_init(bin2hex(strrev($ctx->buffer . substr($message, 0, $offset))), 16);
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
            $c = gmp_init(bin2hex(strrev(substr($message, $offset, 16))), 16);
            $ctx->h = gmp_div_r(($c + $ctx->h + ($this->one << 128)) * $ctx->r, $this->p);
            $offset += 16;
        }

        if ($offset < $msgLen) {
            $ctx->buffer = substr($message, $offset);
        }
    }

    function finish(Context $ctx)
    {
        if (!property_exists($ctx, 'type') || $ctx->type !== __CLASS__) {
            throw new \InvalidArgumentException('Invalid Context');
        }

        if ($ctx->buffer) {
            $c = gmp_init(bin2hex(strrev($ctx->buffer)), 16);
            $ctx->h = gmp_div_r(($c + $ctx->h + ($this->one << (strlen($ctx->buffer) << 3))) * $ctx->r, $this->p);
        }

        $ctx->h += $ctx->s;

        $out = [];
        list($max, $div, $format) = [4 => [8, 0x10000, 'v8'], 8 => [4, 0x100000000, 'V4']][PHP_INT_SIZE];
        for ($j = 0; $j < $max; $j++) {
            list($ctx->h, $out[$j]) = gmp_div_qr($ctx->h, $div);
        }

        $ctx = new Context();

        return pack($format, ...$out);
    }
}
