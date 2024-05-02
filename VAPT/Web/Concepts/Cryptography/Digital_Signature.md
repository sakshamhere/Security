# Digital Signature

Best video  - https://www.youtube.com/watch?v=s22eJ1eVLTU

A digital signature is a way to validate the authenticity and integrity of a digital document and sender with the help of asymmetric public key cryptography. 

Like `HMACs`, digital signatures also employ a hash function and a shared key. However, `HMACs use a symmetric key` -- i.e., the same key is shared between the sender and recipient -- while a `digital signature uses asymmetric keys`, meaning the sender and recipient use two different keys.

exmple - RS256


So how this works is like you hash the document/message and then encrypt using private key,  now you send the signature and and public key to reciever

reciever now takes your document and generates a hash, also he decrypts the signature using public key, if both results match then only it is accepted.

s
# why we hash before encrypting using private key?

We encrypt is because document can be verry large or very small, and algorithm like RSA would create same lenght of signature.

its not feisible to send gigabytes of signature, so we can simply convert it into 256 bits using SHA-256 and then encrypt it using private key, and the result signature is very small in lenght which can be sent with public key