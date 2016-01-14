<?php declare(strict_types = 1);

namespace Poly1305;

if (extension_loaded('gmp')) {
    class Authenticator extends GMP {}
}
else {
    class Authenticator extends Native {}
}
