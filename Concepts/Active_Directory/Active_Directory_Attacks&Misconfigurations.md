
# Kerberos Attacks
https://www.hackthebox.com/blog/8-powerful-kerberos-attacks
https://www.hackthebox.com/blog/what-is-kerberos-authentication#the_lyre_of_orpheus_is_kerberos_really_bulletproof_

## AS-REP Roasting 

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
- there is no way of finding out users with Do not require Kerberos preauthentication set without prior foothold, ie if we dont have domain user access, then we can only guess username/password
- If we already have domain user/intial foothold then we can use an LDAP query to find users in the domain without Kerberos pre-authentication.


### Misonfig: Kerberos preauthentication disabled
