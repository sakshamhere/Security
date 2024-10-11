
The key exchange method specifies how one-time session keys are generated for encryption and for authentication, and how the server authentication is done.

The `Diffie-Hellman` Key Exchange is a method for exchanging secret keys over a non-secure medium without exposing the keys.

The Diffie-Hellman (DH) key agreement method `is an alternative to the traditional way of negotiating encryption keys during the SSL handshaking process that uses RSA`.

best -  https://www.youtube.com/watch?v=NmM9HA2MQGI

https://wiki.openssl.org/index.php/Diffie_Hellman
https://www.comparitech.com/blog/information-security/diffie-hellman-key-exchange/
****************************************************************************************************************************************

# The Problem

` How can you securely exchange information with someone if you haven’t had the opportunity to share the key ahead of time?`

The Diffie-Hellman key exchange was the first publicly-used mechanism for solving this problem. The algorithm allows those who have never met before to safely create a shared key, even over an insecure channel that adversaries may be monitoring.

# Where is the Diffie-Hellman key exchange used?

The main purpose of the Diffie-Hellman key exchange is to securely develop shared secrets that can be used to derive keys. 

`These keys can then be used with symmetric-key algorithms to transmit information in a protected manner`

Frequently implemented in security protocols such as `TLS, IPsec, SSH, PGP, and many others`

As part of these protocols, the Diffie-Hellman key exchange is often used to help `secure your connection to a website, to remotely access another computer, and for sending encrypted emails`

# How does it work
best explained - https://www.youtube.com/watch?v=NmM9HA2MQGI

https://www.youtube.com/watch?v=KXq065YrpiU
https://www.comparitech.com/blog/information-security/diffie-hellman-key-exchange/

The critical part of the Diffie-Hellman key exchange is that both parties end up with the same result, without ever needing to send the entirety of the common secret across the communication channel.

It allows the two parties to communicate over a potentially dangerous connection and still come up with a shared secret that they can use to make encryption keys for their future communications.

# Authentication & the Diffie-Hellman key exchange

In the real world, the Diffie-Hellman key exchange is `rarely used by itself`. The `main reason behind this is that it provides no authentication, which leaves users vulnerable to man-in-the-middle attacks`.

` Instead the Diffie-Hellman key exchange is generally implemented alongside some means of authentication. This often involves using digital certificates and a public-key algorithm, such as RSA, to verify the identity of each party.`


# Types of Diffie-Hellman used in SSL/TLS

There are three versions of Diffie-Hellman used in SSL/TLS.

- `Anonymous Diffie-Hellman`

- `Fixed Diffie-Hellman`

- `Ephemeral Diffie-Hellman`

- `Elliptic-curve Diffie-Hellman`

# Anonymous Diffie-Hellman

Anonymous Diffie-Hellman uses Diffie-Hellman, but without authentication. Because the keys used in the exchange are not authenticated, the protocol is susceptible to `Man-in-the-Middle attacks`.


# Fixed Diffie-Hellman

Fixed Diffie-Hellman embeds the server's public parameter in the certificate, and the CA then signs the certificate. That is, the certificate contains the Diffie-Hellman public-key parameters, and those parameters never change. 


# Ephemeral Diffie-Hellman 

Ephemeral Diffie-Hellman uses temporary, public keys. Each instance or run of the protocol uses a different public key. The authenticity of the server's temporary key can be verified by checking the signature on the key. 

Because the public keys are temporary, a compromise of the server's long term signing key does not jeopardize the privacy of past sessions. This is known as `Perfect Forward Secrecy (PFS).`


# Elliptic-curve Diffie-Hellman

Elliptic-curve Diffie-Hellman takes advantage of the algebraic structure of elliptic curves to allow its implementations to achieve a similar level of security with a smaller key size. A 224-bit elliptic-curve key provides the same level of security as a 2048-bit RSA key. This can make exchanges more efficient and reduce the storage requirements.

Apart from the smaller key length and the fact that it relies on the properties of elliptic curves, elliptic-curve Diffie-Hellman operates in a similar manner to the standard Diffie-Hellman key exchange.


* RECOMMEDED

For the key exchange, public sites can typically `choose between the classic ephemeral Diffie-Hellman key exchange (DHE) and its elliptic curve variant`, ECDHE. There are other key exchange algorithms, but they're generally insecure in one way or another. The RSA key exchange is still very popular, but it doesn't provide forward secrecy.



