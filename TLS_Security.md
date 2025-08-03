| Version     | **Security Issues**                                                                                                          | **Status**                  | **Improvements**                                                                                 |
| ----------- | ---------------------------------------------------------------------------------------------------------------------------- | --------------------------- | ------------------------------------------------------------------------------------------------ |
| **SSL 2.0** | - Weak MAC<br>- No handshake integrity<br>- No support for certificate chains<br>- Downgrade attack risk                     | ❌ Deprecated (2011)         | First attempt at securing web communications                                                     |
| **SSL 3.0** | - Vulnerable to **POODLE** attack (CBC padding)<br>- No modern crypto support<br>- Downgrade attacks                         | ❌ Deprecated (2015)         | Improved handshake, added basic message authentication and session keys                          |
| **TLS 1.0** | - **BEAST attack** (CBC chaining)<br>- Weak hashes (MD5/SHA-1)<br>- Lacked AEAD cipher support                               | ❌ Deprecated (2021)         | First official TLS protocol; added HMACs, supported cipher negotiation                           |
| **TLS 1.1** | - Still used weak cipher suites<br>- Poor adoption<br>- Susceptible to BEAST in some cases                                   | ❌ Deprecated (2021)         | Added IVs to CBC mode to mitigate BEAST                                                          |
| **TLS 1.2** | - **FREAK, Logjam, DROWN** (downgrade & weak key attacks)<br>- **Heartbleed** (OpenSSL bug)<br>- Complexity of configuration | ✅ Active (being phased out) | Introduced AEAD (e.g., AES-GCM)<br>Support for SHA-2<br>More flexibility in handshake & crypto   |
| **TLS 1.3** | - **0-RTT replay** risk<br>- Compatibility issues with older systems                                                         | ✅ Recommended (current)     | Removed legacy crypto (SHA-1, RSA key exchange, CBC)<br>Only forward secrecy<br>Faster handshake |

**********************************************************************************************

| **TLS Version** | **CBC** | **CBC-MAC (MAC-then-encrypt)** | **AEAD (e.g., AES-GCM)** |
| --------------- | ------- | ------------------------------ | ------------------------ |
| **SSL 3.0**     | ✅ Yes   | ✅ Yes                          | ❌ No                     |
| **TLS 1.0**     | ✅ Yes   | ✅ Yes                          | ❌ No                     |
| **TLS 1.1**     | ✅ Yes   | ✅ Yes                          | ❌ No                     |
| **TLS 1.2**     | ✅ Yes   | ✅ Yes                          | ✅ Optional               |
| **TLS 1.3**     | ❌ No    | ❌ No                           | ✅ Mandatory              |


***********************************************************************************************

| **Factor**                       | **CBC (Cipher Block Chaining)**        | **CBC-MAC (MAC-then-Encrypt)**                                | **AEAD (e.g., AES-GCM, ChaCha20-Poly1305)**          |
| -------------------------------- | -------------------------------------- | ------------------------------------------------------------- | ---------------------------------------------------- |
| 🔐 **Primary Purpose**           | Confidentiality (encryption)           | Confidentiality + integrity (via MAC)                         | Confidentiality + integrity + optional AAD           |
| 📥 **Input**                     | Plaintext                              | Plaintext                                                     | Plaintext + optional Associated Data (AAD)           |
| 📤 **Output**                    | Ciphertext                             | Ciphertext + MAC (appended before encryption)                 | Ciphertext + Auth Tag                                |
| 🔁 **MAC Applied To**            | ❌ No MAC                               | ✅ Plaintext (before encryption)                               | ✅ Ciphertext (integrated, or encrypt + MAC together) |
| 🔑 **Key Usage**                 | One key for encryption                 | Two keys: encryption + MAC                                    | One key (or internally derived subkeys)              |
| 🛡️ **Integrity Protection**     | ❌ None                                 | ✅ Partial (but flawed; see vulnerabilities)                   | ✅ Yes (strong)                                       |
| 🔓 **Decryption Before Verify?** | Yes                                    | ✅ Yes (MAC is on plaintext)                                   | ❌ No (MAC checked first)                             |
| 🧪 **MAC-then-Encrypt?**         | ❌ Not used                             | ✅ Yes (HMAC on plaintext → then encrypted)                    | ❌ No (Encrypt-then-MAC or integrated)                |
| ⚠️ **Known Vulnerabilities**     | Padding oracle, IV reuse               | Lucky13, padding oracle, BEAST (due to decryption before MAC) | Nonce reuse (in AEAD), but mitigatable               |
| 🧠 **Complexity**                | Simple                                 | Moderate (needs HMAC and padding handling)                    | Higher, but cleaner API                              |
| 📏 **Handles Variable Length**   | ✅ Yes (with padding)                   | ❌ No (CBC-MAC itself is for fixed-length)                     | ✅ Yes (built-in handling)                            |
| 🧾 **Used in TLS?**              | ✅ Yes (TLS 1.0–1.2, CBC cipher suites) | ✅ Yes (TLS 1.0–1.2 use MAC-then-encrypt with CBC)             | ✅ Yes (TLS 1.2 optional, TLS 1.3 only allows AEAD)   |
| 🔄 **Replay Protection**         | ❌ No                                   | ❌ No                                                          | ✅ Yes (via nonce/IV and tag verification)            |
| ✅ **Modern Recommendation**      | ❌ Deprecated                           | ❌ Deprecated                                                  | ✅ Strongly recommended                               |

*********************************************************************************************************************
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

# CBC mode + HMAC (CBC-MAC) ( MAC-then-encrypt )

MAC-then-Encrypt was traditionally thought to: Provide integrity and authenticity via MAC adding to confidentiality provided via encryption.

It was standard practice in older protocols, including TLS 1.0 and 1.1, and optionally in TLS 1.2.

### Lucky13 attack (2013)

“Lucky13” refers to the `length of a specific piece of TLS padding (13 bytes)` that causes a detectable time difference during decryption. It arise from how `TLS MAC (Message Authentication Code) and padding validation` are performed in different TLS implementations.

It was first disclosed in 2013 and affects implementations of `TLS 1.0, TLS 1.1, and TLS 1.2` — specifically those using` MAC-then-encrypt` CBC cipher suites.

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


# AEAD (Authenticated Encryption with Associated Data) Cipher Mode