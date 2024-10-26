
# Kerberos Attacks
https://www.hackthebox.com/blog/8-powerful-kerberos-attacks
https://www.hackthebox.com/blog/what-is-kerberos-authentication#the_lyre_of_orpheus_is_kerberos_really_bulletproof_
https://www.prosec-networks.com/en/blog/kerberos-attacks/
https://www.thehacker.recipes/ad/movement/kerberos/pre-auth-bruteforce

## Username Enumeration
###### (preauth burteforced)
Kerberos is all about getting service ticket by preseting valid TGT to KDC's TGS, but to get this TGT user first needs to authenticate itself to KDC's AS by presenting its pre-authentication details.

When sending an authentication request (AS-REQ), an attacker can use the response from the KDC to determine whether a user exists or not. This allows attackers to effectively brute force by using word lists of usernames. 

However, performing a brute force attack may result in user accounts being suspended. Therefore, the attackers should be careful with this Kerberos attack.

Attackers use the enumeration of usernames via the following Kerberos error codes out:
```
user            status	                    Kerberos error
Present/Enabled	KDC_ERR_PREAUTH_REQUIRED    Additional preauthentication required
Locked/Disabled	KDC_ERR_CLIENT_REVOKED      The client's credentials have been revoked
Does not exist	KDC_ERR_C_PRINCIPAL_UNKNOWN Client not found in Kerberos database
```

## AS-REP Roasting 
###### (preauthentication disabled)

Kerberos is all about getting service ticket by preseting valid TGT to KDC's TGS, but to get this TGT user first needs to authenticate itself to KDC's AS by presenting its pre-authentication details.

AS-REP Roasting is a technique that enables adversaries to steal the password hashes of user accounts that have Kerberos preauthentication disabled, which they can then attempt to crack offline.

Pre-authentication - This contains UPN (user principal name) + Timestamp encrypted with users password hash
- A time stamp is required in the request to prove that the request is happening at that time. This prevents relay attacks that could be used at a later time.


When pre-authentication is enabled, pre-authentication details are sent with AS-REQ to AS, the authentication service then decrypts the timestamp using its own user's password hash from DC, if decryption is successfull and timestamp matches recent time window then authentication is success and KDC will reply with a TGT with a session key, this session key is encrypted with user's NT hash.

When pre-authentication is is disabled, the attacker can request TGT for any user and get the TGT and session key encrypted with his choice of user. The attacker can then attempt to crack the user's password offline. 

Remediation: 
1. Make sure all accounts in your domain have the Kerberos pre-authentication enabled . Luckliy the pre-auth is enabled by default.
2. Effective Password Policy essential for Active Directory to ensure your environment is not vulnerable to AS-REP roasting. If a strong password is used on a vulnerable account, it is virtually impossible to "break" the encryption by guessing the password.

![alt text](https://cdn-blog.netwrix.com/wp-content/uploads/2022/11/AS-REP-Roasting-1.png.webp)

NOTE:
- If we dont have domain user access/intial foothold then there is no way to find users disabled for pre-auth, we can only guess credentials.
- If we already have domain user/intial foothold then we can use an LDAP query to find users in the domain without Kerberos pre-authentication.



