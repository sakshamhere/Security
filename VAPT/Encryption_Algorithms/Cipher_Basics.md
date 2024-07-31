https://tryhackme.com/room/cryptographyintro?ref=blog.tryhackme.com


`Symmetric encryption, such as AES`

`Asymmetric encryption, such as RSA`

`Diffie-Hellman Key Exchange`

`Hashing`

`PKI`

Some terminology:

`Cryptographic Algorithm or Cipher:` This algorithm defines the encryption and decryption processes.

`Key`: The cryptographic algorithm needs a key to convert the plaintext into ciphertext and vice versa.

`plaintext` is the original message that we want to encrypt

`ciphertext` is the message in its encrypted form

`block cipher` - A block cipher algorithm converts the input (plaintext) into blocks and encrypts each block.


******************************************************************************

# Symmetric Encryption

A symmetric encryption algorithm uses the same key for encryption and decryption. 

Consequently, the communicating parties need to agree on a secret key before being able to exchange any messages.


(NIST) published the `Data Encryption Standard (DES)` in 1977 which is a symmetric encryption algorithm that uses a key size of 56 bits

In 1998, a DES key was broken in 56 hours using brute-force. These cases indicated that DES could no longer be considered secure.

NIST published the `Advanced Encryption Standard (AES)` in 2001. Like DES, it is also a symmetric encryption algorithm; however, it uses a key size of 128, 192, or 256 bits, and it is still considered secure and in use today.

In addition to AES, AES192, and AES256, many other symmetric encryption algorithms are considered secure.

- `BLOWFISH`
- `TWOFISH`


All the algorithms mentioned above are **`block cipher symmetric encryption algorithms.`**