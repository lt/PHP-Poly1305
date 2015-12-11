<?php

namespace Poly1305;

class GMP implements Streamable
{
    private $p;
    private $hibit;

    function __construct()
    {
        $this->hibit = gmp_init('100000000000000000000000000000000', 16);
        $this->p = gmp_init('3fffffffffffffffffffffffffffffffb', 16);
    }

    function init(Context $ctx, $key)
    {
        if (!is_string($key) || strlen($key) !== 32) {
            throw new \InvalidArgumentException('Key must be a 32 bytes');
        }

        $ctx->r = gmp_import($key & "\xff\xff\xff\x0f\xfc\xff\xff\x0f\xfc\xff\xff\x0f\xfc\xff\xff\x0f", 1, GMP_LSW_FIRST | GMP_LITTLE_ENDIAN);
        $ctx->s = gmp_import(substr($key, 16), 1, GMP_LSW_FIRST | GMP_LITTLE_ENDIAN);
        $ctx->h = gmp_init('0');
        $ctx->buffer = '';
        $ctx->init = true;
    }

    function update(Context $ctx, $message)
    {
        if (!$ctx->init) {
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
                $c = gmp_import($ctx->buffer . substr($message, 0, $offset), 1, GMP_LSW_FIRST | GMP_LITTLE_ENDIAN);
                $ctx->h = gmp_div_r(($c + $ctx->h + $this->hibit) * $ctx->r, $this->p);
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
            $c = gmp_import(substr($message, $offset, 16), 1, GMP_LSW_FIRST | GMP_LITTLE_ENDIAN);
            $ctx->h = gmp_div_r(($c + $ctx->h + $this->hibit) * $ctx->r, $this->p);
            $offset += 16;
        }

        if ($offset < $msgLen) {
            $ctx->buffer = substr($message, $offset);
        }
    }

    function finish(Context $ctx)
    {
        if (!$ctx->init) {
            throw new \InvalidArgumentException('Context not initialised');
        }

        if ($ctx->buffer) {
            $c = gmp_import($ctx->buffer, 1, GMP_LSW_FIRST | GMP_LITTLE_ENDIAN);
            $ctx->h = gmp_div_r(($c + $ctx->h + gmp_pow('2', strlen($ctx->buffer) << 3)) * $ctx->r, $this->p);
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
