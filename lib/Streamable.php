<?php

namespace Poly1305;

interface Streamable
{
    function init(Context $ctx, $key);
    function update(Context $ctx, $message);
    function finish(Context $ctx);
}
