<?php

namespace Poly1305;

if (extension_loaded('gmp')) {
    if (version_compare(PHP_VERSION, '5.6.1') >= 0) {
        class Authenticator extends GMP {}
    }
    else {
        class Authenticator extends GMPLegacy {}
    }
}
else {
    class Authenticator extends Native {}
}
