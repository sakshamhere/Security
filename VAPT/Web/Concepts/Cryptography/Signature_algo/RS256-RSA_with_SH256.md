# RSA with SHA-256

It is an algorithm for Digital signature

https://www.youtube.com/watch?v=cZYFIipgBXg


In RSA256 you have a public key and a Private key

- Private key (create only)

- Public key (verify only)

# How it works

For example in JWT, in RSA256 first create a hash/message digest with SHA-256 hash algorithm taking header,claimset. and after that uses cipher with private key to create signature

Now at reciever end you dont create again the signature like in case of HMAC, instead you use Public key to verify if signature is valid on or not.