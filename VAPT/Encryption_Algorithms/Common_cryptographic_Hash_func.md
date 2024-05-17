https://en.wikipedia.org/wiki/Cryptographic_hash_function

# MD5
https://en.wikipedia.org/wiki/MD5

The MD5 message-digest algorithm is a widely used hash function producing a 128-bit hash value. MD5 was designed by Ronald Rivest in 1991 to replace an earlier hash function MD4,[3] and was specified in 1992 as RFC 1321.

**`**Security Issue`**

- `Computationally infeasible` (not `collsion restistant`)

In cryptography, collision resistance is a property of cryptographic hash functions: a hash function H is collision-resistant if it is hard to find two inputs that hash to the same output.

MD5 fails this requirement catastrophically

In 2004 it was shown that MD5 is not collision-resistant. As such, MD5 is not suitable for applications like SSL certificates or digital signatures that rely on this property for digital security.

On 31 December 2008, the CMU Software Engineering Institute concluded that MD5 was essentially "cryptographically broken and unsuitable for further use"

As of 2019, one quarter of widely used content management systems were reported to still use MD5 for password hashing.

Cryptographers began recommending the use of other algorithms, such as `SHA-1`, which found to be vulnerable as well

# SHA-1
https://en.wikipedia.org/wiki/SHA-1

# SHA-2

# SHA-3

# BLAKE2

# BLAKE3