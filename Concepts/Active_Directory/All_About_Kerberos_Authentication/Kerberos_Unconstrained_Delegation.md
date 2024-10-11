https://adsecurity.org/?p=1667
https://www.guidepointsecurity.com/blog/delegating-like-a-boss-abusing-kerberos-delegation-in-active-directory/

# `In Simple words when Uncaonstained Delegation is enabled, the TGT is copied in LSASS memory for later use which can be easily extracted by toll like Mimikatz.`

# Why important to learn?

Credential Delegation is very common and needed aspect in active directory, this is a functionality that can be abused, this helps in lareral movement.


# What is Kerberos Delegation

In Simple words Kerberos delegations allow services to access other services on behalf of domain users.

Kerberos delegations can be abused by attackers to obtain access to valuable assets and sometimes even escalate to domain admin privileges.


# Discovering computers with Kerberos unconstrained delegation

Discovering computers with Kerberos unconstrained delegation is fairly easy using the Active Directory PowerShell module cmdlet, Get-ADComputer.

    Unconstrained Delegation: TrustedForDelegation = True
    Constrained Delegation: TrustedToAuthForDelegation = True


# How does Kerberos `Unconstrained Delegation` really work?

1. User logs on with username & password.

    - Password converted to NTLM hash, a timestamp is encrypted with the hash and sent to the KDC as an authenticator request (AS-REQ).The Domain Controller (KDC) checks user information (logon restrictions, group membership, etc) & creates Ticket-Granting Ticket (TGT) sends it back to user.

2. User presents TGT and recieved TGS.

    - The User presents the TGT to the DC when requesting a Ticket Granting Service (TGS) ticket (TGS-REQ). The DC opens the TGT & validates PAC checksum – If the DC can open the ticket & the checksum check out, TGT = valid. The data in the TGT is effectively copied to create the TGS ticket, The TGS is encrypted using the target service accounts’ NTLM password hash and sent to the user (TGS-REP).

3. The user connects to the server hosting the service on the appropriate port & presents the TGS (AP-REQ).

`When Kerberos Unconstrained Delegation is enabled on the server hosting the service specified in the Service Principal Name referenced in the TGS-REQ (step 3), the Domain Controller the DC places a copy of the user’s TGT into the service ticket. When the user’s service ticket (TGS) is provided to the server for service access, `the server opens the TGS and places the user’s TGT into LSASS for later use`. The Application Server can now impersonate that user without limitation!`

NOTE: In order for an application server to be configured with “Kerberos Unconstrained Delegation”, a Domain or Enterprise Admin needs to configure this setting on the computer account in the domain.

# Credential Theft Leveraging Unconstrained Delegation

As an attacker, once you have found a server with Kerberos Unconstrained Delegation, what’s next?

- Compromise the server via an admin or service account.

- Social engineer a Domain Admin to connect to any service on the server with unconstrained delegation.

`When the admin connects to this service, the admin’s TGS service ticket (with the TGT) is delivered to the server and placed into LSASS in case it’s needed later.`

In case when Domain Account is there, the ticket can be used immediately in order to get the domain KRBTGT account password hash 


We can extract TGS with TGT using Mimikatz.


# What After we are able to Abuse

If you’re able to compromise a computer/user account that is configured for Constrained Delegation (i.e., the account’s UserAccountControl attribute contains the value TRUSTED_TO_AUTH_FOR_DELEGATION), the next important AD attribute to look at is that account’s `msDS-AllowedToDelegateTo` property. 

This property will list one or more hostnames/SPNs where the account is permitted to impersonate any (non-sensitive / unprotected) user in the domain.


# Mitigation

- Don’t use Kerberos Unconstrained Delegation – configure servers that require delegation with `Constrained Delegation`.

- Configure all elevated administrator accounts to be “Account is sensitive and cannot be delegated”.

- The “Protected Users” group, available starting with Windows Server 2012 R2 Domain Functional Level also mitigates against this issue since delegation is not allowed for accounts in this group.