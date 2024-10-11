https://en.wikipedia.org/wiki/Crypt_(C)#Traditional_DES-based_scheme

# DES Based Scheme (Data Encryption Standard )

Long back The traditional DES-based crypt algorithm was originally chosen because DES was resistant to key recovery even in the face of "known plaintext" attacks, and because it was computationally expensive

The algorithm `incorporated a 12-bit salt` in order to ensure that an attacker would be forced to crack each password independently in database as opposed to being able to target the entire password database simultaneously.

What was done?
- `incorporated a 12-bit salt`

Example - `Kyq4bCxAXJkbg`

Actually at that time unix machine was not so good in computation and so making attacker crack each password seperatly was also big achievement, DES was reasonably resistant to dictionary attacks in that era.

At that time password hashes were commonly stored in an account file (`/etc/passwd`) which was readable to anyone on the system.

In the three decades since that time, computers have become vastly more powerful, which made DES vulnerable to brute force attack since computers are now way more faster in cmputing things like hash. then it was decided to keep passwords in seperate file `/etc/shadow` which should be only accessible by root user or similar privilege.

So Then came the `BSDi extended DES-based scheme`

# BSDi extended DES-based schem (Berkeley Software Design, Inc Corporation)

BSDI corporation introduced a slight modification of the classic DES-based scheme

What was done?

`BSDi extended the salt to 24 bits and made the number of rounds variable (up to 224-1).`

These hashes are identified by starting with an underscore (_), which is followed by 4 characters representing the number of rounds then 4 characters for the salt.

Example - `_EQ0.jzhSVeUyoSqLupI`

# MD5-based scheme

Poul-Henning Kamp designed a baroque and (at the time) computationally expensive algorithm based on the MD5 message digest algorithm

(The MD5 message-digest algorithm is a widely used hash function producing a 128-bit hash value. MD5 was designed by Ronald Rivest in 1991 to replace an earlier hash function MD4)

This scheme allows users to have any length password (since many other implementations limit the password length), and they can use any characters supported by their platform (not just 7-bit ASCII). The salt used was also an arbitrary string.

what was done?
- `First the passphrase and salt are hashed together, yielding an MD5 message digest. Then a new digest is constructed, hashing together the passphrase, the salt, and the first digest, all in a rather complex form. Then this digest is passed through a thousand iterations of a function which rehashes it together with the passphrase and salt in a manner that varies between rounds. The output of the last of these rounds is the resulting passphrase hash.`

Example  - `$1$etNnh7FA$OlM7eljE/B7F1J4XYNnk81`

In June 2012, Poul-Henning Kamp declared the algorithm insecure and encouraged users to migrate to stronger password scramblers

# (Bcrypt) Blowfish-based scheme

Niels Provos and David Mazières designed a crypt() scheme called bcrypt based on Blowfish in 1999.

Blowfish is notable among block ciphers for its expensive key setup phase. 

The printable form of these hashes starts with `$2$, $2a$, $2b$, $2x$ or $2y$ depending on which variant of the algorithm `is used.

What was done?

`It starts off with subkeys in a standard state, then uses this state to perform a block encryption using part of the key, and uses the result of that encryption (really, a hashing) to replace some of the subkeys. Then it uses this modified state to encrypt another part of the key, and uses the result to replace more of the subkeys. It proceeds in this fashion, using a progressively modified state to hash the key and replace bits of state, until all subkeys have been set`

Example - `$2a$10$VIhIOofSMqgdGlL4wzE//e.77dAQGqntF/1dT7bqCrVtquInWy2qi`


# NT Hash based scheme

FreeBSD (a linux distro) implemented support for the NT LAN Manager hash algorithm to provide easier compatibility with NT accounts via MS-CHAP (MS-CHAP is the Microsoft version of the Challenge-Handshake Authentication Protocol, (CHAP).)

The NT-Hash algorithm is known to be weak, as it uses the deprecated `md4 hash` algorithm without any salting.

FreeBSD used the $3$ prefix for this. Its use is not recommended, as it is easily broken.

# SHA-2 based scheme

Although the Blowfish-based system has the option of adding rounds and thus remain a challenging password algorithm, but it does not use a NIST-approved algorithm.

Considering this Ulrich Drepper of Red Hat led an effort to create a scheme based on the `SHA-2 (SHA-256 and SHA-512)` hash functions

The printable form of these hashes starts with` $5$ (for SHA-256) or $6$ (for SHA-512) depending on which SHA variant` is used.

The specification and sample code have been released into the public domain; it is often referred to as `"SHAcrypt"`

- SHA-256 - `$5$9ks3nNEqv31FX.F$gdEoLFsCRsn/WRN3wxUnzfeZLoooVlzeF4WjLomTRFD`
- SHA-512 - `$6$qoE2letU$wWPRl.PVczjzeMVgjiA8LLy2nOyZbf7Amj3qLIL978o18gbMySdKZ7uepq9tmMQXxyTIrS12Pln.2Q/6Xscao0`

# Scrypt

In cryptography, scrypt (pronounced "ess crypt"[1]) is a password-based key derivation function created by Colin Percival in March 2009, originally for the Tarsnap online backup service.[2][3] The algorithm was specifically designed to make it costly to perform large-scale custom hardware attacks by requiring large amounts of memory.

Example - `$7$DU..../....2Q9obwLhin8qvQl6sisAO/$sHayJj/JBdcuD4lJ1AxiwCo9e5XSi8TcINcmyID12i8`

# Yescrypt
yescrypt is an extension of scrypt 

Example - - `$y$j9T$F5Jx5fExrKuPp53xLKQ..1$X3DX6M94c7o.9agCG9G317fhZg9SqC.5i5rd.RhAtQ7`