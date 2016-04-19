Poly1305 in PHP
===============

This library contains a pure PHP implementations of the Poly1305 algorithm.

 - The GMP based implementation requires the GMP extension and PHP 5.6 or above.
 - The GMPLegacy based implementation requires the GMP extension and PHP 5.4 or above.
 - The Native implementation requires PHP 5.4 or above with 64 bit integers.

The above implementations are listed in order of performance.

For those who want a C-based extension, it lives in it's own repository: [Poly1305 PHP extension](https://github.com/lt/php-poly1305).

### Usage:

You can generate and verify MACs with the one-shot functions `authenticate` and `verify` available in the `Poly1305` namespace.

Generate a MAC using a 256-bit unique key

```php
$mac = Poly1305\authenticate($key, $message);
```

Verify the authenticity using the MAC for that key / message combination

```php
$valid = Poly1305\verify($mac, $key, $message);
```

Remember that *a key must not be used more than once*

You can also use the `Authenticator` class directly. This is more useful if you are streaming messages and want to generate the MAC as you go.

```php
$auth = new Poly1305\Authenticator;

// Context preserves state between updates
$ctx = $auth->init($key);

while($messageChunk = getChunk()) {
    $auth->update($ctx, $messageChunk);
}

$mac = $poly1305->finish($ctx);
```

# Poly1305-AES

This extension can be used to compute Poly1305-AES MACs and includes optimised AES functions specifically for this purpose.

If you have the OpenSSL extension installed this will be used instead. MCrypt is around 2x slower than the bundled native implementation, as well as being unmaintained, and is not supported here.

To use Poly1305-AES you need three 128-bit strings, instead of the usual 256-bit key.

```php
$r = '0123456789012345'; // "static" portion of Poly1305 key
$k = '0123456789012345'; // AES key
$n = '0123456789012345'; // Nonce
```

The key is now formed by calculating `$r . aes($k, $n)`, allowing `$k` and `$r` to remain unchanged as long as a unique `$n` is used for each message.

The native implementation has two ways to generate `aes($k, $n)` optimised for different secnarios. The OpenSSL version provides the same methods, but is not optimised (it is still faster than native though).

If you're only going to perform one AES operation in the lifetime of your script (i.e. during a web request) then the optimised solution is to use the one-shot `kn(k, n)` method.

```php
$aes = new Poly1305\AES();
$key = $r . $aes->kn($k, $n);
$mac = Poly1305\auth($key, $message);
```

If you have a long running script that will perform many AES operations with incremental or random nonces, then the optimised solution is to use the separate `k()` and `n()` methods. Calling `k()` caches the processed key so that it can be used again.

```php
$aes = new Poly1305\AES();
$aes->k($k);

$key = $r . $aes->n($n);
$mac = Poly1305\auth($key, $message);

// change nonce

$key = $r . $aes->n($n);
$mac = Poly1305\auth($key, $message);
```
