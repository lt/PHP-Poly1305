Poly1305 in PHP
===============

This library contains both a compilable extension and pure PHP implementations of the Poly1305 algorithm.

 - The C-based implementation requires that you can compile and install the extension.
 - The GMP based implementation requires the GMP extension and PHP 5.6 or above.
 - The Native64 implementation requires PHP 5.4 or above, and 64 bit integers.
 - The Native32 implementation requires PHP 5.4 or above

The above implementations are listed in order of performance.

For those who only want the C-based extension, it lives in it's own repository: [Poly1305 PHP extension](https://github.com/lt/php-poly1305).

### Usage:

You can generate and verify MACs with the one-shot functions `auth` and `verify` available in the `Poly1305` namespace.

Generate an mac using a 32 byte unique key

```
$mac = Poly1305\auth($key, $message);
```

Verify the authenticity using the MAC for that key / message combination

```
$valid = Poly1305\verify($mac, $key, $message);
```

Remember that *a key must not be used more than once*

You can also use the `Poly1305` class and `Context` class also available in the `Poly1305` namespace. This is more useful if you are streaming messages and want to generate the MAC as you go to conserve memory.

```
$poly1305 = new Poly1305\Poly1305;
$ctx = new Poly1305\Context;

$poly1305->init($ctx, $key);

$poly1305->update($ctx, $message);
$poly1305->update($ctx, $message);
$poly1305->update($ctx, $message);

$mac = $poly1305->finish($ctx);
```

# Poly1305-AES

This extension can be used to compute Poly1305-AES MACs and includes optimised AES functions specifically for this purpose.

If you have the OpenSSL or MCrypt extensions installed, you can use these instead, however while OpenSSL appears to be around 10x faster than the bundled AES implementation, MCrypt is around 2x slower and is disabled by default.

To use Poly1305-AES you need 3x 16 byte strings, instead of the usual 32 byte key.

```
$k = '0123456789012345'; // AES key
$r = '0123456789012345'; // "static" portion of Poly1305 key
$n = '0123456789012345'; // Nonce
```

The key is now formed by calculating `aes($k, $n) . $r`, allowing `$k` and `$r` to remain unchanged as long as a unique `$n` is used for each message.

There are two ways to generate `aes($k, $n)` optimised for different secnarios.

If you're only going to perform one AES operation in the lifetime of your script (i.e. during a web request) then the optimised solution is to use the one-shot `kn(k, n)` method.

```
$aes = new Poly1305\AES();
$key = $aes->kn($k, $n) . $r;
$mac = Poly1305\auth($key, $message);
```

If you have a long running script that will perform many AES operations with incremental or random nonces, then the optimised solution is to use the separate `k()` and `n()` methods. Calling `k()` caches the processed key so that it can be used again.

```
$aes = new Poly1305\AES();
$aes->k($k);

$key = $aes->n($n) . $r;
$mac = Poly1305\auth($key, $message);

// change nonce

$key = $aes->n($n) . $r;
$mac = Poly1305\auth($key, $message);
```

### How to install the compiled extension:

```
cd ext/php-poly1305
phpize
./configure
make
sudo make install
```
Finally add `extension=poly1305.so` to your /etc/php.ini
