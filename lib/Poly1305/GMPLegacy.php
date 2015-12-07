<?php

namespace Poly1305;

class GMPLegacy implements Base
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

        $ctx->r = gmp_init(bin2hex(strrev($key & "\xff\xff\xff\x0f\xfc\xff\xff\x0f\xfc\xff\xff\x0f\xfc\xff\xff\x0f")), 16);
        $ctx->s = gmp_init(bin2hex(strrev(substr($key, 16))), 16);
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
                $c = gmp_init(bin2hex(strrev($ctx->buffer . substr($message, 0, $offset))), 16);
                $ctx->h = gmp_div_r(gmp_mul(gmp_add($c, gmp_add($ctx->h, $this->hibit)), $ctx->r), $this->p);
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
            $ctx->h = gmp_div_r(gmp_mul(gmp_add($c, gmp_add($ctx->h, $this->hibit)), $ctx->r), $this->p);
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
            $c = gmp_init(bin2hex(strrev($ctx->buffer)), 16);
            $ctx->h = gmp_div_r(gmp_mul(gmp_add(gmp_add($c, $ctx->h), gmp_pow('2', strlen($ctx->buffer) << 3)), $ctx->r), $this->p);
        }

        $ctx->h = gmp_add($ctx->h, $ctx->s);

        if (PHP_INT_SIZE === 8) {
            $max = 4;
            $div = 0x100000000;
            $out = ['V4'];
        }
        else {
            $max = 8;
            $div = 0x10000;
            $out = ['v8'];
        }

        for ($j = 1; $j <= $max; $j++) {
            $tmp = gmp_div_qr($ctx->h, $div);
            $ctx->h = $tmp[0];
            $out[$j] = gmp_strval($tmp[1]);
        }

        $ctx = new Context();

        return call_user_func_array('pack', $out);
    }
}
