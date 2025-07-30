# Node openssl

This was created so that we could verify the modulus of a public and private key
match. At the moment it has two functions RSAPrivateKey and X509PublicKey. The
first reads an rsa private key and the second reads from an x509 cert.

### The output of RSAPrivateKey is as follows:
```
{
        n: (hex string)             // public modulus
        e: (hex string)             // public exponent
        d: (hex string)             // private exponent
        p: (hex string)             // secret prime factor
        q: (hex string)             // secret prime factor
        dmp1: (hex string)          // d mod (p-1)
        dmq1: (hex string)          // d mod (q-1)
        iqmp: (hex string)          // q^-1 mod p
}
```

### The output of X509PublicKey is as follows:
```
{
        n: (hex string)             // public modulus
        e: (hex string)             // public exponent
}
```

## Licence

This is licenced under the GNU Lesser General Public License version 2. See
lgpl-2.1.txt for more details.
