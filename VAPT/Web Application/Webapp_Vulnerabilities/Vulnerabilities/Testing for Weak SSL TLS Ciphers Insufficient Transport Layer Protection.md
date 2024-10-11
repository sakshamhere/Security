# Testing for Weak SSL TLS Ciphers Insufficient Transport Layer Protection

It is important to check the SSL configuration being used to avoid putting in place cryptographic support which could be easily defeated. 

To reach this goal SSL-based services should not offer the possibility to choose weak cipher suite. 

A cipher suite is specified by 
 
    - an encryption protocol (e.g. DES, RC4, AES), 
    - the encryption key length (e.g. 40, 56, or 128 bits), 
    - and a hash algorithm (e.g. SHA, MD5) used for integrity checking

# Checks
https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices
https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_SSL_TLS_Ciphers_Insufficient_Transport_Layer_Protection
https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html#use-tls-for-all-pages

# 1. `Checks for Certificate` 
# 2. `Checks for Server Configuration`
    #  Use Secure Cipher Suites
    #  Server Should use `Forward Secrecy`
    #  Use Strong Key Exchange
    #  Use Secure TLS Protocol
# 2. `Application level checks`
    # Use TLS for All Pages
    # Do Not Mix TLS and Non-TLS Content
    # Use the "Secure" Cookie Flag
    # Prevent Caching of Sensitive Data
    # Use HTTP Strict Transport Security
    
**********************************************************************************************************************************************************
# 1. `Checks for Certificate` (important is to have a valid and strong certificate)
    
- Use 2048-Bit Private Keys

- Protect Private Keys 
    - Generate private keys on a trusted computer with sufficient entropy. Some CAs offer to generate private keys for you; run away from them.

- Use Strong Certificate Signature Algorithms ie SHA-256

---------------------------------------------------------------------------------------------------------------------------------------------------------

# 2. `Checks for Server Configuration`
    
#  Use Secure Cipher Suites

- `Anonymous Diffie-Hellman (ADH)` suites do not provide authentication and should not be use

- `Weak ciphers must not be used`  Ciphers less than 128 bits use encryption that can easily be broken and are insecure.

- `RC4` (also known as Rivest Cipher 4) should not be used, due to crypto-analytical attacks.

-  `MD5` (Message Digest Method 5 a cryptographic hash algorithm used to generate a 128-bit digest from a string of any length) should not be used, due to known collision attacks.

- 64-bit block cipher (`3DES / DES / RC2 / IDEA`) are weak encryption algorithms.

- `TLS_RSA` - Cipher suites with RSA key exchange are weak i.e. `TLS_RSA`

* RECOMMEDATIONS

> You should always use `Ephemeral Diffie-Hellman`,  `Elliptic-curve Diffie-Hellman`(ECDHE) or  classic `Diffie-Hellman`(DHE) because it provides `PFS`(Perfect Forward Secrecy). You can specify ephemeral methods by providing "`kEECDH:kEDH`" in your call to SSL_set_cipher_list.

> Recommended Cipher Suite Configurations (there can be more) 

            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
            TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
            TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
            TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
            TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
            TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
            TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
            TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
            TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
            TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
            TLS_DHE_RSA_WITH_AES_128_CBC_SHA
            TLS_DHE_RSA_WITH_AES_256_CBC_SHA
            TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
            TLS_DHE_RSA_WITH_AES_256_CBC_SHA256

#  Server Should use `Forward Secrecy`

Forward secrecy (sometimes also called perfect forward secrecy) is a protocol feature that enables secure conversations that are not dependent on the server’s private key. With cipher suites that do not provide forward secrecy, someone who can recover a server’s private key can decrypt all earlier recorded encrypted conversations

You need to support and prefer `ECDHE suites` in order to enable forward secrecy with modern web browsers. 

Avoid the RSA key exchange unless absolutely necessary.

To support a wider range of clients, you should also use `DHE` suites as fallback after ECDHE. 

#  Use Strong Key Exchange

For the key exchange, public sites can typically choose between the classic `ephemeral Diffie-Hellman key exchange (DHE)` and its `elliptic curve variant, ECDHE`. 

There are other key exchange algorithms, but they're generally insecure in one way or another. `The RSA key exchange is still very popular, but it doesn't provide forward secrecy`.

# Use Secure TLS Protocol

# 2. `Application level checks`

# Use TLS for All Pages

TLS should be used for all pages, not just those that are considered sensitive such as the login page.

# Do Not Mix TLS and Non-TLS Content

A page that is available over TLS should not include any resources (such as JavaScript or CSS) files which are loaded over unencrypted HTTP

# Use the "Secure" Cookie Flag

All cookies should be marked with the "Secure" attribute, which instructs the browser to only send them over encrypted HTTPS connections

# Prevent Caching of Sensitive Data

Where sensitive data is returned in responses, HTTP headers should be used to instruct the browser and any proxy servers not to cache the information, in order to prevent it being stored or returned to other users.
Cache-Control: no-cache, no-store, must-revalidate

# Use HTTP Strict Transport Security

HTTP Strict Transport Security (HSTS) instructs the user's browser to always request the site over HTTPS, and also prevents the user from bypassing certificate warnings