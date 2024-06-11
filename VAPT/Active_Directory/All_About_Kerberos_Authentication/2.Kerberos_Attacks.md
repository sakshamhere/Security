https://www.hackthebox.com/blog/8-powerful-kerberos-attacks#8_pass_the_ticket

# There are 3 Vital Kerberos Attacks

1. `Roasting Attacks`
    - AS-REQ Roasting
    - Kerberoasting

2. `Delegation Attacks`
    - Unconstrained delegation
    - Constrained delegation
    - Resource-based constrained delegation

3. `Ticket Abuse`
    - Golden Ticket
    - Silver Ticket
    - Pass-the-Ticket

********************************************************************************************************************


# 1. `AS-REQ Roasting`

AS-REQ Roasting is possible when Kerberos `pre-authentication` is not configured.

This allows anyone to request authentication data for a user and In return, the KDC would provide an AS-REP message.

If an account has pre-authentication disabled, an attacker can obtain an encrypted Ticket Granting Ticket (TGT) for the affected account without any prior authentication

We know AS-REP includes a `TGT and sesion key` encrypted with user password.

It is possible to perform an offline brute-force attack to try and retrieve the user's password.

The only information an attacker requires is the username they want to attack, which can also be found using other enumeration techniques.

When `preauthentication` is enabled, a user who needs access to a resource begins the Kerberos authentication process by sending an Authentication Server Request (AS-REQ) message to the domain controller (DC). 

However, if preauthentication is disabled, an attacker could request authentication data for any user and the DC would return an AS-REP message. 

Luckily, preauthentication is enabled by default in Active Directory.


# 2. `Kerberosting`

Kerberoasting is a `technique that finds Service Principal Names (SPN) in Active Directory that are associated with normal user accounts on the domain`, and `then requesting Ticket Granting Service (TGS) tickets for those accounts from the KDC`. These TGS tickets are encrypted with the Service’s password, which may be weak - and susceptible to brute force attacks.

Services are normally configured to use computer accounts which have very long and secure passwords, but `services associated with normal user accounts will have passwords entered by a human and may be short and weak - and a good target for Kerberosting / brute force attacks`.

It is similar to AS-REQ Roasting but does require prior authentication to the domain. In other words, we need a valid domain user account and password (even the lowest privileged) or a SYSTEM (or low privileged domain account) shell on a domain-joined machine to perform the attack


# Delegation attacks

Kerberos Delegation allows a service to impersonate a user to access another resource. Authentication is delegated, and the final resource responds to the service as if it had the first user's rights.

# 3. `Unconstrained Delegation`

When Kerberos Unconstrained Delegation is enabled on the server hosting the service specified in the Service Principal Name referenced in the TGS-REQ (step 3), the Domain Controller the DC places a copy of the user’s TGT into the service ticket. When the user’s service ticket (TGS) is provided to the server for service access, `the server opens the TGS and places the user’s TGT into LSASS for later use`. The Application Server can now impersonate that user without limitation!

`In Simple words when Uncaonstained Delegation is enabled, the TGT is copied in LSASS memory for later use which can be easily extracted by toll like Mimikatz.`


# 4. `Constrained delegation`

Constrained delegation is a “more restrictive” version of unconstrained delegation. In this case, a service has the right to impersonate a user to a well-defined list of services only.

