<?php

namespace Poly1305;

class Native64
{
    function init(Context $ctx, $key)
    {
        if (!is_string($key) || strlen($key) !== 32) {
            throw new \InvalidArgumentException('Key must be a 32 byte string');
        }

        $words = unpack('v8', $key);
        $ctx->r = [
            ( $words[1]        | ($words[2] << 16))                     & 0x3ffffff,
            (($words[2] >> 10) | ($words[3] <<  6) | ($words[4] << 22)) & 0x3ffff03,
            (($words[4] >>  4) | ($words[5] << 12))                     & 0x3ffc0ff,
            (($words[5] >> 14) | ($words[6] <<  2) | ($words[7] << 18)) & 0x3f03fff,
            (($words[7] >>  8) | ($words[8] <<  8))                     & 0x00fffff,
        ];

        $words = unpack('@16/v8', $key);
        $ctx->s = [
            ( $words[1]        | ($words[2] << 16))                     & 0x3ffffff,
            (($words[2] >> 10) | ($words[3] <<  6) | ($words[4] << 22)) & 0x3ffffff,
            (($words[4] >>  4) | ($words[5] << 12))                     & 0x3ffffff,
            (($words[5] >> 14) | ($words[6] <<  2) | ($words[7] << 18)) & 0x3ffffff,
            (($words[7] >>  8) | ($words[8] <<  8))                     & 0x0ffffff,
        ];

        $ctx->h = [0, 0, 0, 0, 0];
        $ctx->buffer = '';
        $ctx->type = __CLASS__;
    }

    function blocks(Context $ctx, $message, $hibit = 1)
    {
        if ($ctx->type !== __CLASS__) {
            throw new \InvalidArgumentException('Context not initialised');
        }

        if (!is_string($message)) {
            throw new \InvalidArgumentException('Message must be a string');
        }

        if ($ctx->buffer) {
            $message = $ctx->buffer . $message;
            $ctx->buffer = '';
        }

        $offset = 0;

        $hibit <<= 24;

        list($r0, $r1, $r2, $r3, $r4) = $ctx->r;

        $s1 = 5 * $r1;
        $s2 = 5 * $r2;
        $s3 = 5 * $r3;
        $s4 = 5 * $r4;

        list($h0, $h1, $h2, $h3, $h4) = $ctx->h;

        $msgLen = strlen($message);
        $blocks = $msgLen >> 4;

        while ($blocks--) {
            $words = unpack("@$offset/v8", $message);
            $h0 += ( $words[1]        | ($words[2] << 16))                     & 0x3ffffff;
            $h1 += (($words[2] >> 10) | ($words[3] <<  6) | ($words[4] << 22)) & 0x3ffffff;
            $h2 += (($words[4] >>  4) | ($words[5] << 12))                     & 0x3ffffff;
            $h3 += (($words[5] >> 14) | ($words[6] <<  2) | ($words[7] << 18)) & 0x3ffffff;
            $h4 += (($words[7] >>  8) | ($words[8] <<  8))                     | $hibit;

            $hr0 = ($h0 * $r0) + ($h1 * $s4) + ($h2 * $s3) + ($h3 * $s2) + ($h4 * $s1);
            $hr1 = ($h0 * $r1) + ($h1 * $r0) + ($h2 * $s4) + ($h3 * $s3) + ($h4 * $s2);
            $hr2 = ($h0 * $r2) + ($h1 * $r1) + ($h2 * $r0) + ($h3 * $s4) + ($h4 * $s3);
            $hr3 = ($h0 * $r3) + ($h1 * $r2) + ($h2 * $r1) + ($h3 * $r0) + ($h4 * $s4);
            $hr4 = ($h0 * $r4) + ($h1 * $r3) + ($h2 * $r2) + ($h3 * $r1) + ($h4 * $r0);

                        $c = $hr0 >> 26; $h0 = $hr0 & 0x3ffffff;
            $hr1 += $c; $c = $hr1 >> 26; $h1 = $hr1 & 0x3ffffff;
            $hr2 += $c; $c = $hr2 >> 26; $h2 = $hr2 & 0x3ffffff;
            $hr3 += $c; $c = $hr3 >> 26; $h3 = $hr3 & 0x3ffffff;
            $hr4 += $c; $c = $hr4 >> 26; $h4 = $hr4 & 0x3ffffff;
            $h0 += 5 * $c; $c = $h0 >> 26; $h0 &= 0x3ffffff;
            $h1 += $c;

            $offset += 16;
        }

        $ctx->h = [$h0, $h1, $h2, $h3, $h4];

        if ($offset < $msgLen) {
            $ctx->buffer = substr($message, $offset);
        }
    }

    function finish(Context $ctx)
    {
        if ($ctx->type !== __CLASS__) {
            throw new \InvalidArgumentException('Context not initialised');
        }

        if ($ctx->buffer) {
            $this->blocks($ctx, "\1" . str_repeat("\0", 15 - strlen($ctx->buffer)), 0);
        }

        list($h0, $h1, $h2, $h3, $h4) = $ctx->h;

                   $c = $h1 >> 26; $h1 &= 0x3ffffff;
        $h2 += $c; $c = $h2 >> 26; $h2 &= 0x3ffffff;
        $h3 += $c; $c = $h3 >> 26; $h3 &= 0x3ffffff;
        $h4 += $c; $c = $h4 >> 26; $h4 &= 0x3ffffff;
        $h0 += 5 * $c; $c = $h0 >> 26; $h0 &= 0x3ffffff;
        $h1 += $c;

        $g0 = $h0  + 5; $c = $g0 >> 26; $g0 &= 0x3ffffff;
        $g1 = $h1 + $c; $c = $g1 >> 26; $g1 &= 0x3ffffff;
        $g2 = $h2 + $c; $c = $g2 >> 26; $g2 &= 0x3ffffff;
        $g3 = $h3 + $c; $c = $g3 >> 26; $g3 &= 0x3ffffff;
        $g4 = ($h4 + $c - (1 << 26)) & 0xffffffff;

        $mask = ($g4 >> 31) - 1;
        $g0 &= $mask;
        $g1 &= $mask;
        $g2 &= $mask;
        $g3 &= $mask;
        $g4 &= $mask;
        $mask = ~$mask & 0xffffffff;
        $h0 = ($h0 & $mask) | $g0;
        $h1 = ($h1 & $mask) | $g1;
        $h2 = ($h2 & $mask) | $g2;
        $h3 = ($h3 & $mask) | $g3;
        $h4 = ($h4 & $mask) | $g4;

        list($s0, $s1, $s2, $s3, $s4) = $ctx->s;

        $c = $h0 + $s0;              $h0 = $c & 0x3ffffff;
        $c = $h1 + $s1 + ($c >> 26); $h1 = $c & 0x3ffffff;
        $c = $h2 + $s2 + ($c >> 26); $h2 = $c & 0x3ffffff;
        $c = $h3 + $s3 + ($c >> 26); $h3 = $c & 0x3ffffff;
        $c = $h4 + $s4 + ($c >> 26); $h4 = $c & 0x0ffffff;

        $mac = pack('v8',
            $h0,
            (($h0 >> 16) | ($h1 << 10)),
            ($h1 >> 6),
            (($h1 >> 22) | ($h2 <<  4)),
            (($h2 >> 12) | ($h3 << 14)),
            ($h3 >> 2),
            (($h3 >> 18) | ($h4 <<  8)),
            ( $h4 >>  8)
        );

        $ctx = new Context();

        return $mac;
    }

    public function authenticate($key, $message)
    {
        $ctx = new Context();
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
