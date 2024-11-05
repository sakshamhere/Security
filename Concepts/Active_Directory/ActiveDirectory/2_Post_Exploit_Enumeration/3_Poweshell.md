
Benefits

The PowerShell cmdlets can enumerate significantly more information than the net commands from Command Prompt.
We can specify the server and domain to execute these commands using runas from a non-domain-joined machine.
We can create our own cmdlets to enumerate specific information.
We can use the AD-RSAT cmdlets to directly change AD objects, such as resetting passwords or adding a user to a specific group.

Drawbacks

PowerShell is often monitored more by the blue teams than Command Prompt.
We have to install the `AD-RSAT` tooling or use other, potentially detectable, scripts for PowerShell enumeration.

*****************************************************************************************************************
┌──(kali㉿kali)-[~]
└─$ `ssh za.tryhackme.com\\stuart.byrne@thmjmp1.za.tryhackme.com`
za.tryhackme.com\stuart.byrne@thmjmp1.za.tryhackme.com's password: 
Microsoft Windows [Version 10.0.17763.1098]
(c) 2018 Microsoft Corporation. All rights reserved.

za\stuart.byrne@THMJMP1 C:\Users\stuart.byrne>powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.


1. Enumerate User `Get-ADUser`

We can use the `Get-ADUser` cmdlet to enumerate AD users:

`Get-ADUser -Identity stuart.byrne -Server za.tryhackme.com -Properties *`

-Identity - The account name that we are enumerating
-Properties - Which properties associated with the account will be shown, * will show all properties
-Server - Since we are not domain-joined, we have to use this parameter to point it to our domain controller

2. Enumerate Group `Get-ADGroup`

- `Get-ADGroup -Identity Administrators -Server za.tryhackme.com`

3. Enumerate Group Membership `Get-ADGroupMember`

We can also enumerate group membership using the Get-ADGroupMember cmdlet

`Get-ADGroupMember -Identity Administrators -Server za.tryhackme.com`

4. Enumerate AD Objects `Get-ADObject`

We can provide Filter of object we want, like User, Container etc, or * for all



*****************************************************************************************************

# Enumerate user

PS C:\Users\stuart.byrne> `Get-ADUser -Identity stuart.byrne -Server za.tryhackme.com -Properties *`


AccountExpirationDate                :
accountExpires                       : 9223372036854775807
AccountLockoutTime                   :
AccountNotDelegated                  : False
AllowReversiblePasswordEncryption    : False
AuthenticationPolicy                 : {}
AuthenticationPolicySilo             : {}
BadLogonCount                        : 0
badPasswordTime                      : 0
badPwdCount                          : 0
CannotChangePassword                 : False
CanonicalName                        : za.tryhackme.com/People/Finance/stuart.byrne 
Certificates                         : {}
City                                 :
CN                                   : stuart.byrne
codePage                             : 0
Company                              :
CompoundIdentitySupported            : {}
Country                              :
countryCode                          : 0
Created                              : 2/24/2022 10:04:45 PM
createTimeStamp                      : 2/24/2022 10:04:45 PM
Deleted                              :
Department                           : Finance
Description                          :
DisplayName                          : Stuart Byrne
DistinguishedName                    : CN=stuart.byrne,OU=Finance,OU=People,DC=za,DC=tryhackme,DC=com
Division                             :
DoesNotRequirePreAuth                : False
dSCorePropagationData                : {1/1/1601 12:00:00 AM}
EmailAddress                         :
EmployeeID                           :
EmployeeNumber                       :
Enabled                              : True
Fax                                  :
GivenName                            : Stuart
HomeDirectory                        :
HomedirRequired                      : False
HomeDrive                            :
HomePage                             :
HomePhone                            :
Initials                             :
instanceType                         : 4
isDeleted                            :
KerberosEncryptionType               : {}
LastBadPasswordAttempt               :
LastKnownParent                      :  
lastLogoff                           : 0
lastLogon                            : 133579962276213782
LastLogonDate                        : 4/19/2024 11:30:27 AM
lastLogonTimestamp                   : 133579962276213782
LockedOut                            : False
logonCount                           : 1
LogonWorkstations                    :
Manager                              :
MemberOf                             : {CN=Internet Access,OU=Groups,DC=za,DC=tryhackme,DC=com}
MNSLogonAccount                      : False
MobilePhone                          :
Modified                             : 4/19/2024 11:30:27 AM
modifyTimeStamp                      : 4/19/2024 11:30:27 AM
msDS-User-Account-Control-Computed   : 0
Name                                 : stuart.byrne
nTSecurityDescriptor                 : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                       : CN=Person,CN=Schema,CN=Configuration,DC=za,DC=tryhackme,DC=com
ObjectClass                          : user
ObjectGUID                           : 8f30d7ca-72c0-4fdb-8d34-bd8492b4f442
objectSid                            : S-1-5-21-3330634377-1326264276-632209373-1171
Office                               :
OfficePhone                          :
Organization                         :
OtherName                            :
PasswordExpired                      : False
PasswordLastSet                      : 2/24/2022 10:04:45 PM
PasswordNeverExpires                 : False
PasswordNotRequired                  : False
POBox                                :  
PostalCode                           :
PrimaryGroup                         : CN=Domain Users,CN=Users,DC=za,DC=tryhackme,DC=com
primaryGroupID                       : 513
PrincipalsAllowedToDelegateToAccount : {}
ProfilePath                          :
ProtectedFromAccidentalDeletion      : False
pwdLastSet                           : 132902138851242303
SamAccountName                       : stuart.byrne
sAMAccountType                       : 805306368
ScriptPath                           :
sDRightsEffective                    : 0
ServicePrincipalNames                : {}
SID                                  : S-1-5-21-3330634377-1326264276-632209373-1171
SIDHistory                           : {}
SmartcardLogonRequired               : False
sn                                   : Byrne
State                                :
StreetAddress                        :
Surname                              : Byrne
Title                                : Associate
TrustedForDelegation                 : False
TrustedToAuthForDelegation           : False
UseDESKeyOnly                        : False
userAccountControl                   : 512
userCertificate                      : {}
UserPrincipalName                    :
uSNChanged                           : 278618
uSNCreated                           : 13360
whenChanged                          : 4/19/2024 11:30:27 AM
whenCreated                          : 2/24/2022 10:04:45 PM



PS C:\Users\stuart.byrne>

# Enumerate Group (ex Administrator grp)

PS C:\Users\stuart.byrne> `Get-ADGroup -Identity Administrators -Server za.tryhackme.com`


DistinguishedName : CN=Administrators,CN=Builtin,DC=za,DC=tryhackme,DC=com
GroupCategory     : Security
GroupScope        : DomainLocal
Name              : Administrators
ObjectClass       : group
ObjectGUID        : f4d1cbcd-4a6f-4531-8550-0394c3273c4f
SamAccountName    : Administrators
SID               : S-1-5-32-544



PS C:\Users\stuart.byrne>

# Enumerating Group

PS C:\Users\stuart.byrne> `Get-ADGroupMember -Identity Administrators -Server za.tryhackme.com`


distinguishedName : CN=Domain Admins,CN=Users,DC=za,DC=tryhackme,DC=com
name              : Domain Admins
objectClass       : group
objectGUID        : 8a6186e5-e20f-4f13-b1b0-067f3326f67c
SamAccountName    : Domain Admins
SID               : S-1-5-21-3330634377-1326264276-632209373-512

distinguishedName : CN=Enterprise Admins,CN=Users,DC=za,DC=tryhackme,DC=com 
name              : Enterprise Admins
objectClass       : group
objectGUID        : 93846b04-25b9-4915-baca-e98cce4541c6
SamAccountName    : Enterprise Admins
SID               : S-1-5-21-3330634377-1326264276-632209373-519

distinguishedName : CN=vagrant,CN=Users,DC=za,DC=tryhackme,DC=com 
name              : vagrant
objectClass       : user
objectGUID        : ed901eff-9ec0-4851-ba32-7a26a8f0858f
SamAccountName    : vagrant
SID               : S-1-5-21-3330634377-1326264276-632209373-1000

distinguishedName : CN=Administrator,CN=Users,DC=za,DC=tryhackme,DC=com 
name              : Administrator
objectClass       : user
objectGUID        : b10fe384-bcce-450b-85c8-218e3c79b30f
SamAccountName    : Administrator
SID               : S-1-5-21-3330634377-1326264276-632209373-500



PS C:\Users\stuart.byrne>


# Enumerating AD Objects

PS C:\Users\stuart.byrne> `Get-ADObject`

cmdlet Get-ADObject at command pipeline position 1
Supply values for the following parameters:
(Type !? for Help.)
Filter: `* `

DistinguishedName                                                                                                             Name                                    ObjectClass              ObjectGUID                           
-----------------                                                                                                             ----                                    -----------              ----------
DC=za,DC=tryhackme,DC=com                                                                                                     za                                      domainDNS                518ee1e7-f427-4e91-a081-bb75e655ce7a        
CN=Users,DC=za,DC=tryhackme,DC=com                                                                                            Users                                   container                522362e6-dcc8-4c43-addd-0fc7417b4f69        
CN=Computers,DC=za,DC=tryhackme,DC=com                                                                                        Computers                               container                ad12d5a8-c532-4999-a6d8-859d2b55bf64        
OU=Domain Controllers,DC=za,DC=tryhackme,DC=com                                                                               Domain Controllers                      organizationalUnit       260c8742-4afb-4f84-a1f4-21648b798312        
CN=System,DC=za,DC=tryhackme,DC=com                                                                                           System                                  container                16ff1ea9-e855-4d4a-b9fd-af236e39afa4        
CN=LostAndFound,DC=za,DC=tryhackme,DC=com                                                                                     LostAndFound                            lostAndFound             5f4efcfb-564e-409f-b681-6c4bb2c644f2        
CN=Infrastructure,DC=za,DC=tryhackme,DC=com                                                                                   Infrastructure                          infrastructureUpdate     66422fc1-7de9-41cc-9a73-f7b2d028ebbf        
CN=ForeignSecurityPrincipals,DC=za,DC=tryhackme,DC=com                                                                        ForeignSecurityPrincipals               container                da044019-3ef8-4983-ab26-d7e17ffc6002        
CN=Program Data,DC=za,DC=tryhackme,DC=com                                                                                     Program Data                            container                82395145-6d04-47e8-80fe-e3e07fadf14e        
CN=Microsoft,CN=Program Data,DC=za,DC=tryhackme,DC=com                                                                        Microsoft                               container                2a8d894a-cefb-4f18-91ed-d9b277cbdb8d        
CN=NTDS Quotas,DC=za,DC=tryhackme,DC=com
CN=Managed Service Accounts,DC=za,DC=tryhackme,DC=com                                                                         Managed Service Accounts                container                cccb931c-fb5f-4c67-a4be-0b293a4fbbe9        
CN=Keys,DC=za,DC=tryhackme,DC=com
CN=WinsockServices,CN=System,DC=za,DC=tryhackme,DC=com                                                                        WinsockServices                         container                a4fff731-ab04-423e-aeea-c14eaccd72a7        
CN=RpcServices,CN=System,DC=za,DC=tryhackme,DC=com                                                                            RpcServices                             rpcContainer             1c78b0c8-f58a-4265-90ef-2b5feedfb611        
CN=FileLinks,CN=System,DC=za,DC=tryhackme,DC=com                                                                              FileLinks                               fileLinkTracking         83a8b921-311b-4df6-ae93-bbeb7c77b7c5 
CN=VolumeTable,CN=FileLinks,CN=System,DC=za,DC=tryhackme,DC=com
CN=ObjectMoveTable,CN=FileLinks,CN=System,DC=za,DC=tryhackme,DC=com                                                           ObjectMoveTable                         linkTrackObjectMoveTable d82f7392-75f2-4247-8afa-31a6428ac582        
CN=Default Domain Policy,CN=System,DC=za,DC=tryhackme,DC=com                                                                  Default Domain Policy                   domainPolicy             9d2b55db-3926-48e8-812b-ff3d862e576b        
CN=AppCategories,CN=Default Domain Policy,CN=System,DC=za,DC=tryhackme,DC=com                                                 AppCategories                           classStore               b25f7002-e81d-4d99-a8bf-700290d92d25        
CN=Meetings,CN=System,DC=za,DC=tryhackme,DC=com                                             
.
.
.
..
.
.

