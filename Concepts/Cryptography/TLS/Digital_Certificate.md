https://imgur.com/gallery/ssl-conversation-between-computer-server-5T2fJsG

TLS Digital Certificate
Digital Certificate is the foundation to implement Public Key Infrastructure  security, its an electronic file that is used to validate identity of a website.
Digital Certificate provides a third-party validation, it is issued by a CA (Certificate Authority) to verify the identity of certificate holder (ie website).

Below is The Process without Certificate

1. Client requests Server to use HTTPs connection.
2. Web Server sends public key to browser, browser can encrypt the initial URL and request details with this public key. Server can then decrypt using its private key and know details, this is done using asymmetric encryption.
3. Now the server knows what the client wants to access but it can’t send it using asymmetric encryption, because the client does not have a private key to decrypt.
4. To Solve this, the client generates a symmetric key and encrypts it using the Public key which the server gave it and sends it to the server, now both client and server can use this symmetric key encryption for further data transmission.

# Now what if an attacker impersonates a server?, how would the client know if the Server’s public key is coming from a valid server or not? - This is where the Digital Certificate comes into picture!!

So when the Server’s public key is sent to the client, it will be sent with a Certificate (including CA’s public key) which tells who this public key belongs to.if its a website then this certificate will contain domain name, IP address and other details. This certificate is issued by a trusted Certificate Authority like digicert, symantec etc, the certificate is digitally signed by CA and it  confirms that the public key belongs to a particular domain only.

The browsers already have a known CA list,  it doesn't need to contact CA to verify the certificate, since CA is having a Digital Signature, the browser can simply use the CA’s public key to decrypt the signature and get the hash. Now this hash can be compared by the hash you get from the certificate sent by the server. If both matched then the server is valid.
