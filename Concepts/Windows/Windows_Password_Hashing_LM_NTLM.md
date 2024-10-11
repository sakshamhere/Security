
The Windows OS stores hashed user account passwords locally in `SAM (Security Accounts Manager)` database.

Authentication and Verification of credentials is facilated by the `Local Service Authority (LSA)` 

Windows versions upto Windows Server 2003 utilizes two types of hashes
- `LM`
- `NTLM`

From Windows Vista onwards only `NTLM` is utilized

# LM `(LanMan) HASH`

LM is default hashing algorithm that was implemented in windows operating system priro to `NT4.0`

The protocol is/was used to hash user passwords.

- All the password are broken into two chunks , conververted to uppercase and each chunk is hashed seperately using `DES` hashing algo

The LM hash is generally considred to be weak and can be easily cracked, primarily because password hashes dosent include salts, consequently making brute-force and rainbow table attack effective against LM hashes.

# NTLM `(NT HASH)`

NTLM is collection of authentication protocols that are utilized in windows to facilitate authentication between computers.

When a user account is created it is encrypted using `MD4` hashing algorithm, while the original password is disposed.

NTLM does not split hash into chunks, it is case sensitive and allows use of symbols and unicode characters.