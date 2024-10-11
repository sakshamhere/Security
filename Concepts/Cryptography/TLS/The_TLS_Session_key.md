
This `Session key / session exhange key` / `Master key` 

In TLS (historically known as "SSL"), the two communicating parties (the client and the server) generate session keys at the start of any communication session, during the TLS handshake. The official RFC for TLS does not actually call these keys "session keys", but functionally that's exactly what they are.

These considerations compare DH (Diffie Hellman) with RSA regarding how an SSL session key is created and exchanged, not how the communication partners are authenticated.

    - The main advantage of DH over RSA is the fact that a session key is never sent over the network, and therefore provides “perfect forward secrecy” (PFS). With PFS, it is not possible to decrypt a recorded SSL session in future when the RSA private key potentially got compromised or broken.

    - The main disadvantage of DH is its higher CPU consumption. Establishing an SSL session by using DH consumes approximately 30% more CPU than compared to RSA.


RSA
One method of exchanging the session key, is by protecting it with an RSA public key.

Diffie-Hellman
Another method of exchanging the session key, is by using Diffie-Hellman. Using Diffie-Hellman, the session key is never sent over the network and is 
therefore never part of the network session data.


