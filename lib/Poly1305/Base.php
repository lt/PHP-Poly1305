<?php

namespace Poly1305;

interface Base
{
    function init(Context $ctx, $key);
    function update(Context $ctx, $message);
    function finish(Context $ctx);
} 
