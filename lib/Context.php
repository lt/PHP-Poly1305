<?php

namespace Poly1305;

class Context
{
    public $r;
    public $s;
    public $h;
    public $buffer;
    public $init;
    // Native implementation only
    public $hibit;
}
