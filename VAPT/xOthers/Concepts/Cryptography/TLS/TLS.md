# Transport Layer Security

Best video exaplins why and how - https://www.youtube.com/watch?v=0TLDTodL7Lc


Transport Layer Security, or TLS, is a widely adopted security protocol designed to facilitate privacy and data security for communications over the Internet. A primary use case of TLS is encrypting the communication between web applications and servers, such as web browsers loading a website

So back then when there was concern of security in web, they discovered SSL and then later TLS was discovered which is kind of advance version to SSL with some improvements

So TLS basically works on top of TCP, below are some points of concern

1. What ciphers we use to encrypt

2. Secret key

3. Server Authentication (SSL Certificate by CA)


# SSL/TLS family

There are six protocols in the SSL/TLS family: SSL v2, SSL v3, TLS v1.0, TLS v1.1, TLS v1.2, and TLS v1.3:

- `SSL v2` is insecure and must not be used. This protocol version is so bad that it can be used to attack RSA keys and sites with the same name even if they are on an entirely different servers (the DROWN attack).

- `SSL v3` is insecure when used with HTTP (the SSLv3 POODLE attack) and weak when used with other protocols. It’s also obsolete and shouldn’t be used.

- `TLS v1.0 and TLS v1.1 are legacy protocol that shouldn't be used`, but it's typically still necessary in practice. Its major weakness (BEAST) has been mitigated in modern browsers, but other problems remain. TLS v1.0 has been deprecated by PCI DSS. Similarly, TLS v1.0 and TLS v1.1 has been deprecated in January 2020 by modern browsers. Check the SSL Labs blog link

- `TLS v1.2 and v1.3` are both without known security issues.

Sumary - Latest version of TLS is 1.3, 1.2 is also in use but 1.1 is deprecated


# CA / Certificate Authority

- These are governing entities that issues TLS Certificate.

- These are trusted by both client and Server

- There are 5 organisations that secure 98% of the internet

    (IdenTrust (Let's encrypt), DigiCert, Sectigo, GoDaddy, GlobalSign)



# TLS Handshake
https://www.youtube.com/watch?v=86cQJ0MMses - best

https://www.cloudflare.com/learning/ssl/what-happens-in-a-tls-handshake/

https://learn.microsoft.com/en-us/windows/win32/secauthn/tls-handshake-protocol#establishing-a-secure-session-by-using-tls

http://www.cs.bc.edu/~straubin/crypto2017/demosteps.pdf

A TLS handshakes occur after a TCP connection has been opened via a TCP handshake.

In a nutshell, TLS handshake process — entails exchanging messages between the server and the client. They define the settings of the encrypted communication, including enabled cipher suites, protocol version, renegotiation security, and others. 

The SSL handshake contains components like `ClientHello`, `ServerHello`, `server’s certificate`, `ServerHelloDone`, `ClientKeyExchange`, `ChangeCipherSpec`, `Finished`, `Renegotiated SSL sessions`, and `Renegotiation settings`. 

The exact steps of the TLS handshake will depend on which TLS version is supported by the client and server, below is for TLS 1.2



                                                    (Client Hello!)
     CLIENT  ------>----------->----------->------------->------------->---------->----------->---------->--------->------->  Server
                                        (Max TLS version that client support)
                                        (Random number (to prevent replay attacks))
                                        (List of Ciphers/Cipher suite that clinet supports)


                                                (Server Hello!)
    Client <---------<----------<--------------<---------------<------------<------------<----------<------------<------------- Server
                                       <-- (A chosen TLS version)
                                       <---(A SSL certificate with public key)
                                       <---(Server-key exchage) (Diffie helmon thing started)
                                       <---(A Digital Signature)


     CLIENT  ------>----------->----------->------------->------------->---------->----------->---------->--------->------->  Server
                                        --> (Client key Exchange) (Diffe hellmon in process)
                                        --> (ChangeCipherSpec)
                                        --> sends a Finished message encrypted with `master key`




Now at this point both Client and Server have the  `pre-master secret`, so they both use it with the random numbers (`Client Random`, `Server Random`) to create a `Master` key which will be used to create session keys


    Client <---------<----------<--------------<---------------<------------<------------<----------<------------<------------- Server
                                        Server also creates a master key using pre-master key he decrypted by is private key
                                        If verfication is succeddful, ie both master key are same then:
                                        
                                        --> server sebds (change cipher spec)
                                        --> Finished (summary of all messages so far)


1. First Client approaches server on port 443 with a `ClientHello1` message, This message contains following:

    - Maximum TLS version supported by the client
    - A 32-byte random number known as `Client Random` (This is to prevent replay attacks)
    - List of Ciphers that client supports
 
 2. Server then decides what TLS version, Ciphers are availible and the resplies with `ServerHello` with following:

    - Selected TLS version and Cipher

    - A newly generated random number `Server Random`

    - Server's own SSL Certificate with a public key and a Signature signed using private key by CA

    - The server also sends the `Server Key Ecxhange` this will have

        - Parameters for `Diffie-Hellman`, most probably using elliptic curve diffie-hellman key exchange

    - Digital Signature (created by hashing previous message recieved from client and signing using private key)

3. Client then performs following

    - Verifies Certificate 

    In this The client then generates the `pre-master secret` (a 48 byte random number) and encrypts it with the agreed public key between both as part of Diffie-Hellman

    - The Client then this as  `Client key Exchange` to server as part Diffie-hellmon process 

    - The client also sends `ChangeCipherSpec` saying that he is ready to create a session key,and start communicating through an encrypted tunnel using that key.

    - The client generates a `master key` by using agreed cipher (encr algo) on (`Client Random`, `Server Random` and `pre-master secret`). 
    
    - Client also sends `Finished` mesage to server in that it hashes all handshake records up to that point, encrypts them and send it.


4. Now server first decrypts the `ClientKeyExchange` message to get `pre-master secret` using its private key as part of Diffie-hellman to verify.

    - Now Since both client and server have `Client Random`, `Server Random` and `pre-master secret`, both can use these to derive a `master key` 

    - Later this 'master key' is used to genrates all `session keys` related stuff.

    - Now server sends the client that yes I verified we have same keys and I am also ready to use same `session key` 

    - It also created hash of all handshake records up to that point, encrypts them and sends a `Finished` message 


NOw the TLS handshake is complete


# Renegotiated SSL sessions, and Renegotiation settings.

Now for exmaple a user intitiated TLS handshake with a shopping site, so TLS handshake gets complete

Now user decides to log in (authenticate) and buy some stuff, so now TLS Renegotiation would be required and so `Renegotiation is making a new handshake while in the middle of a SSL/TLS connection.`

The specific site requires or at least demands certificate-based client authentication, the server triggers a new handshake, this time with a `CertificateRequest` message.

There are two potential cyberattack scenarios related to the SSL/TLS renegotiation:

- A `Man-in-the-Middle attack` (injection vulnerability) that inserts malicious data (plain text can be inserted as a prefix to a TLS connection) into HTTPS sessions through an unauthenticated request (CVE-2009-3555). By doing this, the attacker may run commands with the credentials of an already authorized user and even gather other users’ credentials. 

- A `Denial of Service` condition starts hundreds of handshakes from clients for the same TCP connection, abusing the fact that a secure SSL connection is 15 times more resource consuming for servers than for clients.



If your clients and server support "Secure Renegotiation" then things are fine for now (it prevents all currently known attacks). Otherwise there exist Renegotiation Vulnerabilities

NOTE - As of 2020 TLS 1.2 clients used to abuse renegotiation to perform authentication, but renegotiation in TLS 1.3 is removed as it was unsecure. Clients must be upgraded to do post-handshake authentication.


# How Does Client verify Certificate
https://stackoverflow.com/questions/35374491/how-does-the-client-verify-servers-certificate-in-ssl

- The server sends a certificate to the user agent while making a TLS connection.

- Then the user agent(browser) looks at the certificate checks whether the certificate is from trusted CA's.

- If its from trusted CA, then user agent parses certificate, it gets CSR and a digital signature which is encrypted(hash(CSR)).

- Now user agent creates a hash of CSR hash1(CSR) and also it decrypts the digital signature using its public key to get hash2(CSR).

- So now if hash1(CSR) == hash2(CSR), then the certificate is valid.


# Summarize

1. Client sends ClientHello, with cipher suite (supported Ciphers,TLS version, etc) and ClientRandom

2. Server sends Certificate, Selected Cipher, TLS version, Server Random, and a DH parameter (Server exchange key)

3. Client verifies certificate, Client generates a Pre-master secret encrypt it using CA public key and send it to server

4. Server decrypts message sent by client using CA private key and it also gets Pre-master key.

5. So now both Client and Server has pre-master key, Client Randome, and Server Random.

6. So using all these 3 things they both generate a Master key. using this master key symmetric keys will be derived.

7. So now Using MAster key 4 keys are derived


********************************************************************************************************************************************************

# More on Cipher Suite

Example - `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`

ECDHE - Key Exchange

ECDSA - Signature

AES_128_GCM - Bul Encryption of message

SHA256 - Message Authentication

means Elliptic Curve Diffie Hellman for establishing the symmetric key, Elliptic Curve Digital
Signature Algorithm for signatures, AES with 128-bit keys in Galois Counter Mode (that's a new
one for me!) for symmetric encryption, and SHA256 for hashing.

https://learn.microsoft.com/en-us/windows/win32/secauthn/cipher-suites-in-schannel
https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/cipher-suite-breakdown/ba-p/259302