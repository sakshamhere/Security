

Both are concepts (not technoque) which are implemented by various techniques

# Encryption

Encryption is the process of putting data in the form of plaintext into an encryption algorithm, and producing a ciphertext. Ciphertext is a form of data where all the patterns of letters that create words in the plaintext are scrambled into a new text that cannot be read without decrypting the data. Encryption uses a key to ensure the ciphertext cannot be deciphered by anyone but the authorized recipient.

for example - AES

# Signature

Signing works oppositely. The data is signed by hashing the message with a hashing algorithm and the sender’s private key. This produces a hash digest, which can only be recreated through use of one of the keys in the key pair created by the sender. The recipient then receives the message, the hash digest, and the public key, if they did not already have it. The recipient then uses the sender’s public key to hash the message they have received. If the resulting hash digest matches the hash digest that has been sent along with the message, then the identity of the sender has been confirmed. This also confirms that the data has not been changed in transit. 

for examplle - HMAC, RS256