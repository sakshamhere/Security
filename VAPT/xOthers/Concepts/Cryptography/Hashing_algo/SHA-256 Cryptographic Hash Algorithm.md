# SHA-256 Cryptographic Hash Algorithm

Its an algorithm which is used to create a Message Digest / Signature

`SHA-256` is one of the successor hash functions to `SHA-1` (collectively referred to as `SHA-2`), and is one of the `strongest` hash functions available

NOTE
A hash is not ‘encryption’ – it cannot be decrypted back to the original text (it is a ‘one-way’ cryptographic function, and is a fixed size for any size of source text). This makes it suitable when it is appropriate to compare ‘hashed’ versions of texts, as opposed to decrypting the text to obtain the original version.

It would be virtually impossible to convert the 256-bit hash mentioned above back to its original 512-bit form.

It converts any length of data either very large or very small to 256 bit, which is very efficient when sending with request/response.

# Use

- Used in creating HMAC

- Major use in password verification, Used in hashing passwords when performing authentication

- SHA-256 is used in some of the most popular authentication and encryption protocols, including `SSL, TLS, IPsec, SSH, and PGP`. 

- In Unix and Linux, SHA-256 is used for secure password hashing. 


# How secure it is.

-  It is almost impossible to reconstruct the initial data from the hash value. A brute-force attack would need to make `2^256 (2 to the power 256) ` attempts to generate the initial data. 

- Second, having two messages with the same hash value (called a collision) is extremely unlikely. With `2^256 (2 to the power 256) ` possible hash values (`more than the number of atoms in the known universe`), the likelihood of two being the same is infinitesimally, unimaginably small.