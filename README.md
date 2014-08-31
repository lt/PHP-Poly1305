Poly1305 in PHP
===============

This library contains pure PHP implementations of the Poly1305 algorithm.

 - The GMP based implementation requires the GMP extension and PHP 5.6 or above.
 - The Native64 implementation requires PHP 5.4 or above, and 8 byte integers.
 - The Native32 implementation requires PHP 5.4 or above

The above implementations are listed in order of performance.

For those who require even better performance, I have a C-based [Poly1305 PHP extension](https://github.com/lt/php-poly1305).
