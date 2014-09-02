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

### How to install:

```
git clone git://github.com/lt/php-poly1305.git
cd php-poly1305
phpize
./configure
make
sudo make install
```
Finally add `extension=poly1305.so` to your /etc/php.ini


# Poly1305-AES

This extension can be used to compute Poly1305-AES MACs. You will need a way of performing AES encryption to do this. Most people have the OpenSSL or MCrypt extensions that can do this.

### OpenSSL

`$k$r` is 32 byte random key, and `$n` is unique nonce for each message.

```
$k = '0123456789012345';
$r = '0123456789012345';
$n = '0123456789012345';

$aeskn = openssl_encrypt($n, 'aes-128-ecb', $k,
    OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);

$mac = Poly1305\auth($r . $aeskn, $message);
```

### MCrypt

`$k$r` is 32 byte random key, and `$n` is unique nonce for each message.

```
$k = '0123456789012345';
$r = '0123456789012345';
$n = '0123456789012345';

$aeskn = mcrypt_encrypt('rijndael-128', $k, $n, 'ecb');

$mac = Poly1305\auth($r . $aeskn, $message);
```