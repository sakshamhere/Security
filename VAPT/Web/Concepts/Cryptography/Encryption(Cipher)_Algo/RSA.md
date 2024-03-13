
best - https://www.youtube.com/watch?v=GSIDS_lvRv4

RSA is an Asymmetric encryption algotithm, where in

Both partes has their own Public and Private key

They share their public key with each other

Now Client uses server public key sent by server and encrypts message usingi it , It then send encrypted message to server which can then decrypt it using its private key

However RSA is used very popularly in various aspects.

but in case of TLS connectiion

there is risk in this algo, that we are sending keys on network and if by chance private key of server gets compromised (as in Hearbleed bug) then someone who had recorded previous messages can decrypt them and sesitive data is exposed


Thats why in TLS connection It is recommended to use Diffie-Hellman in TLS senerio, also now TLS 1.3 forces DH only
