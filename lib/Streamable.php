<?php declare(strict_types = 1);

namespace Poly1305;

interface Streamable
{
    function init(string $key): Context;
    function update(Context $ctx, string $message);
    function finish(Context $ctx): string;
}
