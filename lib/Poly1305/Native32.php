<?php

namespace Poly1305;

class Native32
{
    function init(Context $ctx, $key)
    {
        if (!is_string($key) || strlen($key) !== 32) {
            throw new \InvalidArgumentException('Key must be a 32 byte string');
        }

        $words = unpack('v8', $key);
        $ctx->r = [
            $words[1] & 0x1fff,
            (($words[1] >> 13) | ($words[2] << 3)) & 0x1fff,
            (($words[2] >> 10) | ($words[3] << 6)) & 0x1f03,
            (($words[3] >> 7) | ($words[4] << 9)) & 0x1fff,
            (($words[4] >> 4) | ($words[5] << 12)) & 0x00ff,
            ($words[5] >> 1) & 0x1ffe,
            (($words[5] >> 14) | ($words[6] << 2)) & 0x1fff,
            (($words[6] >> 11) | ($words[7] << 5)) & 0x1f81,
            (($words[7] >> 8) | ($words[8] << 8)) & 0x1fff,
            ($words[8] >> 5) & 0x007f
        ];

        $words = unpack('@16/v8', $key);
        $ctx->s = [
            $words[1] & 0x1fff,
            (($words[1] >> 13) | ($words[2] << 3)) & 0x1fff,
            (($words[2] >> 10) | ($words[3] << 6)) & 0x1fff,
            (($words[3] >> 7) | ($words[4] << 9)) & 0x1fff,
            (($words[4] >> 4) | ($words[5] << 12)) & 0x1fff,
            ($words[5] >> 1) & 0x1fff,
            (($words[5] >> 14) | ($words[6] << 2)) & 0x1fff,
            (($words[6] >> 11) | ($words[7] << 5)) & 0x1fff,
            (($words[7] >> 8) | ($words[8] << 8)) & 0x1fff,
            ($words[8] >> 5) & 0x07ff
        ];

        $ctx->h = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
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

        $hibit <<= 11;

        $msgLen = strlen($message);
        $blocks = $msgLen >> 4;
        $hr = [];
        $h = $ctx->h;
        $r = $ctx->r;

        while ($blocks--) {
            $words = unpack("@$offset/v8", $message);
            $h[0] += $words[1] & 0x1fff;
            $h[1] += (($words[1] >> 13) | ($words[2] << 3)) & 0x1fff;
            $h[2] += (($words[2] >> 10) | ($words[3] << 6)) & 0x1fff;
            $h[3] += (($words[3] >> 7) | ($words[4] << 9)) & 0x1fff;
            $h[4] += (($words[4] >> 4) | ($words[5] << 12)) & 0x1fff;
            $h[5] += ($words[5] >> 1) & 0x1fff;
            $h[6] += (($words[5] >> 14) | ($words[6] << 2)) & 0x1fff;
            $h[7] += (($words[6] >> 11) | ($words[7] << 5)) & 0x1fff;
            $h[8] += (($words[7] >> 8) | ($words[8] << 8)) & 0x1fff;
            $h[9] += ($words[8] >> 5) | $hibit;

            for ($i = 0, $c = 0; $i < 10; $i++) {
                $u = $c;
                for ($j = 0; $j <= $i && $j < 5; $j++) {
                    $u += $h[$j] * $r[$i - $j];
                }
                for (; $j < 5; $j++) {
                    $u += $h[$j] * (5 * $r[$i + 10 - $j]);
                }
                $c = ($u >> 13);
                $u &= 0x1fff;
                for (; $j <= $i; $j++) {
                    $u += $h[$j] * $r[$i - $j];
                }
                for (; $j < 10; $j++) {
                    $u += $h[$j] * (5 * $r[$i + 10 - $j]);
                }
                $c += $u >> 13;
                $hr[$i] = $u & 0x1fff;
            }
            $c *= 5;
            $c += $hr[0];
            $hr[0] = $c & 0x1fff;
            $c = $c >> 13;
            $hr[1] += $c;

            $h = $hr;
            $offset += 16;
        }

        $ctx->h = $h;
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

        $h = $ctx->h;

        $c = $h[1] >> 13;
        $h[1] &= 0x1fff;
        for ($i = 2; $i < 10; $i++) {
            $h[$i] += $c;
            $c = $h[$i] >> 13;
            $h[$i] &= 0x1fff;
        }
        $h[0] += 5 * $c;
        $c = $h[0] >> 13;
        $h[0] &= 0x1fff;
        $h[1] += $c;
        $c = $h[1] >> 13;
        $h[1] &= 0x1fff;
        $h[2] += $c;

        $g = [];
        $g[0] = $h[0] + 5;

        $c = $g[0] >> 13;
        $g[0] &= 0x1fff;
        for ($i = 1; $i < 10; $i++) {
            $g[$i] = $h[$i] + $c;
            $c = $g[$i] >> 13;
            $g[$i];
        }
        $g[9] -= (1 << 13);
        $g[9] &= 0xffff;

        $mask = ($g[9] >> 15) - 1;

        for ($i = 0; $i < 10; $i++) {
            $g[$i] &= $mask;
        }
        $mask = ~$mask & 0xffff;
        for ($i = 0; $i < 10; $i++) {
            $h[$i] = ($h[$i] & $mask) | ($g[$i] & 0x1fff);
        }

        $c = $h[0] + $ctx->s[0];
        $h[0] = $c & 0x1fff;
        $c = $h[1] + $ctx->s[1] + ($c >> 13);
        $h[1] = $c & 0x1fff;
        $c = $h[2] + $ctx->s[2] + ($c >> 13);
        $h[2] = $c & 0x1fff;
        $c = $h[3] + $ctx->s[3] + ($c >> 13);
        $h[3] = $c & 0x1fff;
        $c = $h[4] + $ctx->s[4] + ($c >> 13);
        $h[4] = $c & 0x1fff;
        $c = $h[5] + $ctx->s[5] + ($c >> 13);
        $h[5] = $c & 0x1fff;
        $c = $h[6] + $ctx->s[6] + ($c >> 13);
        $h[6] = $c & 0x1fff;
        $c = $h[7] + $ctx->s[7] + ($c >> 13);
        $h[7] = $c & 0x1fff;
        $c = $h[8] + $ctx->s[8] + ($c >> 13);
        $h[8] = $c & 0x1fff;
        $c = $h[9] + $ctx->s[9] + ($c >> 13);
        $h[9] = $c & 0x1fff;

        $mac = pack('v8',
            $h[0] | ($h[1] << 13),
            ($h[1] >> 3) | ($h[2] << 10),
            ($h[2] >> 6) | ($h[3] << 7),
            ($h[3] >> 9) | ($h[4] << 4),
            ($h[4] >> 12) | ($h[5] << 1) | ($h[6] << 14),
            ($h[6] >> 2) | ($h[7] << 11),
            ($h[7] >> 5) | ($h[8] << 8),
            ($h[8] >> 8) | ($h[9] << 5)
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
