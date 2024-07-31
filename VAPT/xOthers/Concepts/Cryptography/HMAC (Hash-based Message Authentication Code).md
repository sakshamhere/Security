https://www.geeksforgeeks.org/what-is-hmachash-based-message-authentication-code/

# HMAC (Hash-based Message Authentication Code)

So Basically HMAC (Hash-based Message Authentication Code) is a type of (MAC)Message Authentication code which is created by executing a cryptographic hash function on the sensitive data and the secret key.

HMAC = cryptographic hash func( sesnitive data + secret key )

The cryptographic hash function may be MD-5, SHA-1, or SHA-256.


# NOTE
HMACs are almost similar to digital signatures. They both enforce integrity and authenticity. They both use cryptography keys. And they both employ hash functions. The main difference is that digital signatures use asymmetric keys, while HMACs use symmetric keys (no public key)



# How it works (on high level)

The hash function will be applied to the plain text, but before applying we compute S bits and append it to plain text, and that S bit is computed using the private key whicb both sender and reciever have.

# Working

Client makes unique HMAC and sends it to server , the server uses the shared private key and creates its own HMAC and then compares for validation.

# Use

- HTTPS, SFTP, FTPS, and other transfer protocols use HMAC.

- Verification of e-mail address during activation or creation of an account.

- Authentication of form data that is sent to the client browser and then submitted back.

- HMACs can be used for Internet of things (IoT) due to less cost.

- Whenever there is a need to reset the password, a link that can be used once is sent without adding a server state.

- It can take a message of any length and convert it into a fixed-length message digest. That is even if you got a long message, the message digest will be small and thus permits maximizing bandwidth.


# Disadvantages 

HMACs uses shared key which may lead to non-repudiation. If either sender or receiver’s key is compromised then it will be easy for attackers to create unauthorized messages.

