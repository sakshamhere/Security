| Version     | **Security Issues**                                                                                                          | **Status**                  | **Improvements**                                                                                 |
| ----------- | ---------------------------------------------------------------------------------------------------------------------------- | --------------------------- | ------------------------------------------------------------------------------------------------ |
| **SSL 2.0** | - Weak MAC<br>- No handshake integrity<br>- No support for certificate chains<br>- Downgrade attack risk                     | ❌ Deprecated (2011)         | First attempt at securing web communications                                                     |
| **SSL 3.0** | - Vulnerable to **POODLE** attack (CBC padding)<br>- No modern crypto support<br>- Downgrade attacks                         | ❌ Deprecated (2015)         | Improved handshake, added basic message authentication and session keys                          |
| **TLS 1.0** | - **BEAST attack** (CBC chaining)<br>- Weak hashes (MD5/SHA-1)<br>- Lacked AEAD cipher support                               | ❌ Deprecated (2021)         | First official TLS protocol; added HMACs, supported cipher negotiation                           |
| **TLS 1.1** | - Still used weak cipher suites<br>- Poor adoption<br>- Susceptible to BEAST in some cases                                   | ❌ Deprecated (2021)         | Added IVs to CBC mode to mitigate BEAST                                                          |
| **TLS 1.2** | - **FREAK, Logjam, DROWN** (downgrade & weak key attacks)<br>- **Heartbleed** (OpenSSL bug)<br>- Complexity of configuration | ✅ Active (being phased out) | Introduced AEAD (e.g., AES-GCM)<br>Support for SHA-2<br>More flexibility in handshake & crypto   |
| **TLS 1.3** | - **0-RTT replay** risk<br>- Compatibility issues with older systems                                                         | ✅ Recommended (current)     | Removed legacy crypto (SHA-1, RSA key exchange, CBC)<br>Only forward secrecy<br>Faster handshake |

**********************************************************************************************

| Cipher Mode                    | SSL/TLS Versions           | Security Issues & Vulnerabilities                     | Protocol Compatibility                              |
| ------------------------------ | -------------------------- | ----------------------------------------------------- | --------------------------------------------------- |
| **CBC**                        | SSL 3.0, TLS 1.0, 1.1, 1.2 | Padding oracle attacks, BEAST attack, Slow to process | Deprecated in TLS 1.3                               |
| **CBC-MAC (MAC-then-Encrypt)** | SSL 2.0, SSL 3.0, TLS 1.0  | Vulnerable to length extension attacks, Weak security | Deprecated in TLS 1.1 and above                     |
| **RC4**                        | SSL 3.0, TLS 1.0, 1.1      | Vulnerable to key stream biases, weak encryption      | Deprecated in TLS 1.2 and above, Removed in TLS 1.3 |
| **AEAD**                       | TLS 1.2, TLS 1.3           | Highly secure, prevents replay attacks, fast          | Mandatory in TLS 1.3, Optional in TLS 1.2           |
                          |

*********************************************************************************************************************

| **SSL/TLS Version** | **Cipher Modes Supported**                                 | **Description**                                                                                       | **Security Notes**                                                                                                                      | **Example Cipher Suites**                                                          |
| ------------------- | ---------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| **SSL 2.0**         | Proprietary schemes (no proper cipher modes)               | SSL 2.0 does not support standard modern cipher modes. It used weak and proprietary mechanisms.       | ❌ Completely **obsolete** and insecure. No proper cipher modes or encryption standards.                                                 | None (SSL 2.0 is deprecated and not used in modern systems).                       |
| **SSL 3.0**         | **CBC** (Cipher Block Chaining)                            | Introduced **CBC mode** for encryption, using block ciphers like 3DES and AES.                        | ❌ Vulnerable to **padding oracle** attacks (e.g., **BEAST**) and **man-in-the-middle** attacks.                                         | `SSL_RSA_WITH_3DES_EDE_CBC_SHA`, `SSL_RSA_WITH_AES_128_CBC_SHA`                    |
| **TLS 1.0**         | **CBC**, **RC4** (Stream Cipher)                           | Supported **CBC** (for block ciphers) and **RC4** (stream cipher). RC4 was commonly used.             | ⚠️ **RC4** is **insecure** due to known biases; **CBC** vulnerable to **BEAST** attack.                                                 | `TLS_RSA_WITH_AES_128_CBC_SHA`, `TLS_RSA_WITH_3DES_EDE_CBC_SHA`                    |
| **TLS 1.1**         | **CBC**, **RC4** (Stream Cipher)                           | Similar to TLS 1.0 but with **randomized IVs** to prevent **BEAST** attacks. Still uses **CBC**.      | ⚠️ **Lucky13** vulnerability in CBC mode; **RC4** is deprecated and insecure.                                                           | `TLS_RSA_WITH_AES_128_CBC_SHA`, `TLS_RSA_WITH_RC4_128_SHA`                         |
| **TLS 1.2**         | **CBC**, **AEAD** (AES-GCM, AES-CCM), **RC4** (deprecated) | Supported **CBC** for backward compatibility and **AEAD** (AES-GCM, AES-CCM) for more security.       | ✅ **AES-GCM** is highly secure and efficient. **RC4** is deprecated and should not be used.                                             | `TLS_RSA_WITH_AES_128_GCM_SHA256`, `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256`         |
| **TLS 1.3**         | **AEAD-only**: AES-GCM, AES-CCM, ChaCha20-Poly1305         | Only AEAD cipher suites are supported. **AES-GCM** and **ChaCha20-Poly1305** provide strong security. | ✅ **AES-GCM** and **ChaCha20-Poly1305** ensure **authenticated encryption** (confidentiality + integrity). **CBC** and **RC4** removed. | `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256` |


***********************************************************************************************
# CBC (Cipher Block Chaining) Cipher Mode

CBC (Cipher Block Chaining) is a block cipher mode of operation used for encrypting data. It's one of the modes that can be used with block ciphers like AES or 3DES to turn them into stream-like ciphers suitable for encrypting longer messages.

SSL 3.0 and early versions of TLS (1.0 and 1.1) supported CBC mode. It was often used with AES-CBC or 3DES-CBC for encrypting data over the network.

However, CBC in TLS had several issues:

## How CBC works

CBC (Cipher Block Chaining) is a block cipher mode of operation that enhances security by combining each `plaintext block` with the previous ciphertext block before encryption. The process introduces dependency between blocks to make patterns less visible in the encrypted data.

1. The plaintext message is divided into fixed-size blocks (usually 128 bits or 16 bytes for AES).

2. Before encrypting each plaintext block It is XORed with the previous ciphertext block ( for the first block `IV—Initialization Vector` is used).

3. This modified block is then encrypted using AES to produce the ciphertext block.

Note

- Padding is required in CBC because plaintext often isn’t a perfect multiple of the block size

## Vulnerabilities in CBC Mode in SSL/TLS

### POODLE attack (CBC padding) (2014)

The POODLE attack (short for `"Padding Oracle On Downgraded Legacy Encryption"`) is a man-in-the-middle (MitM) cryptographic attack first disclosed by Google researchers in October 2014. It targets the `SSL 3.0` protocol, specifically its use of block cipher modes of encryption, such as `CBC (Cipher Block Chaining).`

In CBC mode, the last byte of a block might contain padding and SSL 3.0 does not validate padding contents properly. An attacker can modify the encrypted data and observe if the padding was accepted or rejected. This gives them an "oracle" to gradually `guess the plaintext` (like cookies or session tokens) byte-by-byte.

### BEAST attack (CBC chaining) (2011)

CBC encryption in `TLS 1.0` uses the ciphertext block of the previous record as the IV(`IV—Initialization Vector`) for a new record. Because the attacker can predict this IV, they can control the XOR input and mount a `blockwise plaintext recovery attack.`

In Blockwise Recovery the attacker repeatedly Crafts payloads with carefully chosen prefixes. Observes how they align in blocks and ` infers the value of one plaintext byte at a time.` Over time, `they recover/extract entire cookies or session tokens encrypted by TLS.`

Data at Risk:

- Authentication cookies
- Session tokens
- Any sensitive data sent early in HTTPS requests

Especially affected web browsers using TLS 1.0 and Most browsers at the time still defaulted to AES-CBC in TLS 1.0

Note - AES-CBC is still vulnerable unless you're on TLS 1.1+

# CBC + HMAC ( MAC-then-encrypt) Cipher Mode

MAC-then-Encrypt was traditionally thought to: Provide integrity and authenticity via MAC adding to confidentiality provided via encryption.

It was standard practice in older protocols, including TLS 1.0 and 1.1, and optionally in TLS 1.2.

## How it works

TLS CBC mode combines MAC-then-encrypt:

1. Compute MAC of the plaintext.
2. Append MAC to plaintext.
3. Add padding to fit block size.
4. Then Encrypt using AES.

Upon receiving a record:

1. Decrypt the ciphertext.
2. Check and remove padding.
3. Validate MAC.
4. If padding or MAC is incorrect, the record is rejected.

### Lucky13 attack (2013)

“Lucky13” refers to the `length of a specific piece of TLS padding (13 bytes)` that causes a detectable time difference during decryption. It arise from how `TLS MAC (Message Authentication Code) and padding validation` are performed in different TLS implementations.

It was first disclosed in 2013 and affects implementations of `TLS 1.0, TLS 1.1, and TLS 1.2` — specifically those using` MAC-then-encrypt` CBC cipher suites.



How the Attack Works

1. Man-in-the-middle attacker observes TLS traffic.
2. Sends modified ciphertext blocks to the server, one byte at a time.
3. Carefully times the server’s response (or lack of one).
4. Uses the response time to infer:
    - How much padding was accepted.
    - Whether the MAC was checked.
5. Repeats this thousands of times to recover individual bytes of plaintext.

Note: This attack is very subtle and requires: Very precise timing measurement. A high volume of traffi and A vulnerable (unconstant-time) implementation.

Mitigation and Fixes

- Avoid CBC Cipher Suites
- Use AEAD (Authenticated Encryption with Associated Data) cipher modes

# RC4 (Rivest Cipher 4) Cipher Mode

RC4 (Rivest Cipher 4), also known as ARC4 (Alleged RC4), is a stream cipher that was designed by Ron Rivest in 1987.
RC4 operates as a `stream cipher`, meaning it `encrypts data one bit or byte at a time rather than in blocks` like block ciphers (AES, DES). It was widely used for securing communication in protocols like `SSL/TLS, WEP, and WPA`. However, over time, vulnerabilities were discovered that significantly reduced its security

## How RC4 Works

RC4 encryption is based on the concept of a `pseudo-random key stream` that is XORed with the plaintext data.

1. The algorithm takes the key and generates an internal state array (S) that is 256 bytes long.
2. The key is used to initialize this array, mixing the state array in a way that makes it difficult to predict.
3. The key is expanded and used to modify the state array through a permutation process.
4. The state array is then used to generate a pseudo-random stream of bytes` (the keystream).`
5. This keystream is XORed with the plaintext (in the encryption process) or ciphertext (in the decryption process) to produce the encrypted output or recover the plaintext.

In TLS 1.2 and earlier, RC4 was allowed, but it has been deprecated due to its insecurity and vulnerabilities like RC4 biases. In TLS 1.3, RC4 is removed entirely. Modern versions of TLS only support AEAD cipher suites like AES-GCM, AES-CCM, and ChaCha20-Poly1305

## Vulnerabilities in RC4

1. When used in SSL/TLS, RC4 became vulnerable to several types of padding oracle and biased keystream attacks.
2. While it was supported in earlier versions of TLS, RC4 was found to be vulnerable to BEAST (Browser Exploit Against SSL/TLS) attacks, which exploited weaknesses in the protocol to allow for chosen-plaintext attacks.
3. `Bias in Keystream`: RC4 generates a pseudo-random keystream. However, it was discovered that early bytes of the keystream are not as random as they should be, which leads to biased output.
4. `WEP (Wired Equivalent Privacy)`, which used RC4 for encryption, was cracked due to the reuse of the same keystream and weak initialization vector (IV). The` FMS attack` could easily break WEP in a matter of minutes using traffic analysis.
5. `WPA (Wi-Fi Protected Access)`, although more secure, also used RC4 in the early stages, which still allowed for vulnerabilities in some cases.

Note:

- Many organizations have moved to `AES (Advanced Encryption Standard)` as the default encryption algorithm for securing communication.
-` NIST` (National Institute of Standards and Technology) officially removed RC4 from its approved algorithms in 2015.

Given its weaknesses, RC4 should not be used in any new systems, especially in protocols like TLS, SSL, or WEP.


# AEAD (Authenticated Encryption with Associated Data) Cipher Mode

It’s a cryptographic mode of operation that provides: Confidentiality (via encryption), Integrity and authenticity (via authentication tag) and Optional associated data authentication (e.g., headers)

Key Features:

| Feature                         | AEAD Provides? |
| ------------------------------- | -------------- |
| Encryption                      | ✅              |
| Message Authentication (MAC)    | ✅              |
| Combined operation              | ✅              |
| Protects non-encrypted data too | ✅ (via AAD)    |

AEAD modes like `AES-GCM`, `AES-CCM`, and `ChaCha20-Poly1305` are now the default encryption mechanisms in TLS 1.3 and recommended in TLS 1.2. They are fast, secure, and solve the serious problems that affected older cipher modes like CBC.