
# Brute Force weak secret

https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-weak-signing-key

Many signing algorithms, such as HS256 (HMAC + SHA-256), use an arbitrary, standalone string as the secret key.

Just like a password, it’s crucial that this secret can’t be easily guessed or brute-forced by an attacker. Otherwise, they may be able to create JWTs with any header and payload values they like, then use the key to re-sign the token with a valid signature.

To brute force the key we will use Hashcat tool and the command for the same is :

```
hashcat -a 0 -m 16500 <jwt> <wordlist>
```

Here’s what each part of the command does:
```
hashcat: This is the command to run Hashcat, the password recovery tool.
-a 0: This option specifies the attack mode. In this case, -a 0 indicates a straight brute-force attack. In a straight brute-force attack, Hashcat tries all possible combinations within the specified character set and length range.
-m 16500: This option specifies the hash mode. Hashcat supports various hash algorithms and modes. The 16500 mode corresponds to JWT tokens.
<jwt>: This is a placeholder for the path to the file containing the JWT tokens that you want to crack. We replace <jwt> with the actual path to your JWT token file or can directly replace it with the token itself.
<wordlist>: This is a placeholder for the path to the wordlist that Hashcat will use for the brute-force attack. A wordlist is a file containing a list of words, passwords, or patterns that Hashcat will try when attempting to crack the hashes. We replace <wordlist> with the actual path to your wordlist file.
```

Hashcat signs the header and payload from the JWT using each secret in the wordlist, then compares the resulting signature with the original one from the server. If any of the signatures match, hashcat outputs the identified secret in the following format, along with various other details: