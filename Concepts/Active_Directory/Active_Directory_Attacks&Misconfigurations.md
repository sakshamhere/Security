
# Kerberos Attacks
https://www.hackthebox.com/blog/8-powerful-kerberos-attacks
https://www.hackthebox.com/blog/what-is-kerberos-authentication#the_lyre_of_orpheus_is_kerberos_really_bulletproof_
https://www.prosec-networks.com/en/blog/kerberos-attacks/
https://www.thehacker.recipes/ad/movement/kerberos/pre-auth-bruteforce
https://www.cybertriage.com/blog/dfir-breakdown-kerberoasting/
https://blog.netwrix.com/2022/12/02/unconstrained-delegation/
https://www.qomplx.com/blog/qomplx-knowledge-kerberos-delegation-attacks-explained/
https://adsecurity.org/?p=1667

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

Tools like `kerbrute` (Go) and `smartbrute` (Python) can be used to bruteforce credentials through the Kerberos pre-authentication. The smartbrute utility can be used in a brute mode (standard bruteforcing features) or in a smart mode (requires prior knowledge of a low-priv user credentials, but operates LDAP enumeration and avoid locking out accounts, fetches the users list and so on).


![alt text](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEiWIeARP6j9o46YNN1siF9A_lpyfcw1RTrNp2tiVBlxgPM68QpWa1wag2eQkAuUBZ7HjWwptspLbeMaRJ7vwkygwU4sAYRv8NPXovgQMOhuoXOcnByVrSUp85uM2k_a4YZSgE-xn_q8KtXOPRL7jGrZ6ZVSsGEzkobKFLYf3X9ey0cu43ceeHLAoRlMVg/s16000/4.png)

Remediation

The Kerberos user enumeration can be difficult to troubleshoot because it depends on good Kerberos monitoring. This monitoring must be able to detect unrealistic amounts of AS-REQ requests without follow-up requests.

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

## Kerberosting
###### (user/admin accounts with SPN)

In Kerberos auth user asks for a (service ticket) ST from KDC, for this user needs to present a valid TGT (Ticket Granting Ticket) along with SPN (Service Principal Name) of the service it want to access.

The ST is encrypted with the requested service account's NT hash. If an attacker has a valid TGT and knows a service (SPN), he can request a ST for this service and crack it offline later in an attempt to retrieve that service account's password. This is Kerberosing.

This requires an attacker to have access to a domain account prior to performing any Kerberoasting activity.

Kerberosting can only be perfomed for accounts that have SPN, only for these account service ticket is encrypted with password hash. These are often computer accounts and service accounts that are associated with a service like MS SQL. However, normal user accounts can have a SPN as well. These are the core targets of a Kerberoasting attack.

Attacker can query to find all such account ie kerberostable account, using Kerberoasting tools out there like `Rubeus`, `Invoke-Kerberoast`, and Impackets `GetUsersSPNs.py`.

NOTE:

Kerberosting is useless for machine accuonts and service accounts,  due to the strong password management on such accounts. Computer account passwords are updated every 30 days, by default, and contain a 120 unicode character password. Similarly, managed service accounts have passwords that are managed by AD and have similar password age and length requirements that computer accounts have.

Kerberosting focus on user accounts with atleast one SPN , specially admin accounts, since they probably have human-defined passwords.

Once hash is obtained, Hashcat and JohnTheRipper can then be used to try cracking the hash

## Delegation Attacks

Kerberos Delegation is a feature that allows an application to reuse the end-user credentials to access recourses hosted on a different server. You should only allow that if you really trust the application server, otherwise the application may use your credentials to purposes that you didn't think of, like sending e-mails on your behalf or changing data in a mission critical application pretending that you made that change.

For that reason, delegation is not enabled by default in Active Directory. You - or more likely the domain administrator - must explicit make the decision that this particular application is trusted for delegation. 

![alt text](https://cdn-blog.netwrix.com/wp-content/uploads/2022/12/Unconstrained-Delegation-1.png.webp)

Note that another option is resource-based constrained delegation (RBCD), in which delegation is configured on the resource, rather than on the accounts accessing the resource. RBCD can be set up using Windows PowerShell.

### Unconstrained delegations 

In Unconstrained delegation a service can impersonate user to access any other service on behalf of user.

What actually happens:

When user request TGS for a ST of server/service which is having unconstrained delegation on, the TGS will attach a copy of TGT into the ST in this case and send back.

When user presents this ST to a service/server on which unconstrained delegation is on, then that server/service stores takes the copy TGT from this ST and stores it in its memory ie LSASS ( Local Security Authority Subsystem Service ) and now it can use this TGT on behalf of that user again for lifetime until the ST service ticket expires.

Discovering computers with Kerberos unconstrained delegation is fairly easy using the Active Directory PowerShell module cmdlet, Get-ADComputer.
- Unconstrained Delegation: TrustedForDelegation = True
- Constrained Delegation: TrustedToAuthForDelegation = True
![alt text](https://adsecurity.org/wp-content/uploads/2015/08/KerberosUnConstrainedDelegation-PowerShell-DiscoverServers2.png)


As an Attacker, once you have found a server with Kerberos Unconstrained Delegation you will then

1. First Compromise the server via an admin or service account.
2. Then Social engineer a Domain Admin/user or wait for him to connect to any service on the server with unconstrained delegation.

When the admin/user connects to this service, his TGS service ticket (with the TGT) is delivered to the server and placed into LSASS. Now the user's authentication (TGT) ticket can be extracted using `Mimikatz` and re-used (until the ticket lifetime expires).

![alt text](https://adsecurity.org/wp-content/uploads/2015/08/KerberosUnConstrainedDelegation-Mimikatz-Ticket-Export-LS-TGT-TicketDetail2.png)
![alt text](https://adsecurity.org/wp-content/uploads/2015/08/KerberosUnConstrainedDelegation-Mimikatz-PTT-LS-Ticket2.png)

And if this user is Domain Admin, then the ticket can be used immediately in order to get the domain KRBTGT account password hash using `Mimikatz`

![alt text](https://adsecurity.org/wp-content/uploads/2015/08/KerberosUnConstrainedDelegation-PSRemote-ADSDC02-Mimikatz-KRBTGT2.png)

Remediation
- Don’t use Kerberos Unconstrained Delegation – configure servers that require delegation with Constrained Delegation.
- Configure all elevated administrator accounts to be “Account is sensitive and cannot be delegated”.
- The “Protected Users” group, available starting with Windows Server 2012 R2 Domain Functional Level also mitigates against this issue since delegation is not allowed for accounts in this group.




### Constrained delegations 

### Resource based constrained delegations 