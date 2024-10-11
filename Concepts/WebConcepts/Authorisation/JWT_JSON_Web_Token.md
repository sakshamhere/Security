# JWT Token

https://portswigger.net/web-security/jwt

https://www.youtube.com/watch?v=5mUDRQfwXuE

jwt.io

JSON web tokens (JWTs) are a standardized format for sending cryptographically signed JSON data between systems. 

They can theoretically contain any kind of data, but are most commonly used to send information ("claims") about users as part of authentication, session handling, and access control mechanisms. 

Unlike with classic session tokens, all of the data that a server needs is stored client-side within the JWT itself. This makes JWTs a popular choice for highly distributed websites where users need to interact seamlessly with multiple back-end servers. 

these are stored on client in cookies,local storage or anywehere, but these are sent in HTTP authorisation header which starts from bearer

# JWT format

A JWT consists of 3 parts: 

    a header, 

    a payload, 
    
    and a signature. 
    
    These are each separated by a dot

The header and payload parts of a JWT are just base64url-encoded JSON objects. The header contains metadata about the token itself, while the payload contains the actual "claims" about the user. 

In most cases, this data can be easily read or modified by anyone with access to the token. Therefore, the security of any JWT-based mechanism is heavily reliant on the cryptographic signature

# JWT signature

The server that issues the token typically generates the signature by hashing the header and payload. In some cases, they also encrypt the resulting hash. Either way, this process involves a secret signing key.

As the signature is directly derived from the rest of the token, changing a single byte of the header or payload results in a mismatched signature.

Without knowing the server's secret signing key, it shouldn't be possible to generate the correct signature for a given header or payload.


# JWT vs JWS vs JWE

The JWT specification is actually very limited. It only defines a format for representing information ("claims") as a JSON object that can be transferred between two parties. In practice, JWTs aren't really used as a standalone entity. The JWT spec is extended by both the JSON Web Signature (JWS) and JSON Web Encryption (JWE) specifications, which define concrete ways of actually implementing JWTs. 

In other words, a JWT is usually either a JWS or JWE token. When people use the term "JWT", they almost always mean a JWS token. JWEs are very similar, except that the actual contents of the token are encrypted rather than just encoded.

Note

For simplicity, throughout these materials, "JWT" refers primarily to JWS tokens, although some of the vulnerabilities described may also apply to JWE tokens.

NOTE - like we have session hijacking without TLS we can also have JWT hijacking so we should always send token in TLS / encryption


# (JOSE Headers) /  JWT Header Parameters

According to the JWS specification, only the alg header parameter is mandatory. In practice, however, JWT headers (also known as JOSE headers) often contain several other parameters.

* jwk (JSON Web Key) - an optional jwk header parameter, which servers can use to embed their public key directly within the token itself in JWK format.  

* jku (JSON Web Key Set URL) - Provides a URL from which servers can fetch a set of keys containing the correct key. 

* kid (Key ID) - Servers may use several cryptographic keys for signing different kinds of data, not just JWTs. For this reason, the header of a JWT may contain a kid (Key ID) parameter, which helps the server identify which key to use when verifying the signature. 

* Example

{
    "kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG",
    "typ": "JWT",
    "alg": "RS256",
    "jwk": {
        "kty": "RSA",
        "e": "AQAB",
        "kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG",
        "n": "yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9m"
    }
}




# helpfuls sites

JWT.IO allows you to decode, verify and generate JWT.













