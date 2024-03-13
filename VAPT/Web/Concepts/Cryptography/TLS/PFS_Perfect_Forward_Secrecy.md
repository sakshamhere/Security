# Perfect Forward Secrecy (PFS), also called forward secrecy (FS)

Best video - https://www.youtube.com/watch?v=zSQtyW_ywZc

So There 

So The main advantage of using Diffie Hellnam DH over RSA is the fact that a session key is never sent over the network, and therefore provides “perfect forward secrecy” (PFS). With PFS, it is not possible to decrypt a recorded SSL session in future when the RSA private key potentially got compromised or broken.

# Why PFS concept is there

To understand why we have PFS Concept we need to understand the `HeartBleed` vulnerablity found in systems protected by `vulnerable versions of the OpenSSL` software

Breif - Basically The Heartbleed bug allows anyone on the Internet to read the memory of the systems protected by the `vulnerable versions of the OpenSSL` software. 

So if he/she is able to read memory then he/she can also get to know about the private key which is horrible

Best video - https://www.youtube.com/watch?v=zSQtyW_ywZc


> ` What and How attacker is doing `

1. Lets consider user has initiated TLS handshake with server. 

2. lets assume Attacker sits in between basically did a MITM by sitting on router or something and sniffs the traffic.

3. So you sent symmetric encrypted key with messages you sent to server and attacker records it, but obviously he can't read anything as eveything is encryptted and he cant decrypt as he dont kow the private key which exist only on server, So what he does is he just records all the traffic and saved it.

4. Now few months later the same server has a bug 'Heartbleed' which will read more data in the memory, and that returned data might contain the `private key  `. so now its a problem.

5. So now since attacker managed to get 'private key' and he already had encrypted messgaes save months ago, he now starts decrypting them and hence sensitive data is exposed now


# So What is PFS

Perfect forward secrecy is the ability that even if servers private key is leaked no one can see my messges in future.

So What PFS says is that Do Not send encrypted key in the client server conversation, as it is being done by RSA asymmentric alg


This issue is only upto TLS 1.2, Because TLS 1.3 Forces `Diffie Hellman` which is very strong conept of key exchange no one can break through it, because we dont send the `Master key` / session key on network , because both client and server are able to generate it using the math and then uses it to encrpt messages.

Dieffie Hellman provides Perfect Forward Secrecy

So The main advantage of using `Diffie Hellnam` DH over `RSA` is the fact that a session key is never sent over the network, and therefore provides “perfect forward secrecy” (PFS). With PFS, it is not possible to decrypt a recorded SSL session in future when the RSA private key potentially got compromised or broken.