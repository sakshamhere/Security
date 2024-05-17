┌──(kali㉿kali)-[~]
└─$ mimikatz                    

> mimikatz ~ Uses admin rights on Windows to display passwords in plaintext

/usr/share/windows-resources/mimikatz
├── kiwi_passwords.yar
├── mimicom.idl
├── Win32
│   ├── mimidrv.sys
│   ├── mimikatz.exe
│   ├── mimilib.dll
│   ├── mimilove.exe
│   └── mimispool.dll
└── x64
    ├── mimidrv.sys
    ├── mimikatz.exe
    ├── mimilib.dll
    └── mimispool.dll
┌──(kali㉿kali)-[/usr/share/windows-resources/mimikatz]

****************************************************************************************************************************************8

`Mimikatz` is a windows post exploitation tool it `allows extraction of Clear-Text Passwords, Hashes and Kerberos Tickets from memory`.

Windows store passwords in the registry in a hashed (`NTLM Hash`) format using the NTLM algorithm. The registry file is called `SAM (Security Access Manager) database file` and is located in `C:\windows\system32\config\SAM`

The `SAM` Database fle cannot be copied while OS us running.

Thw Windows NT Kernel keeps the SAM database file lokcked and as a result, attackers typically utilize in-memory (utilizing cache in RAM)  technique and tools to dump `SAM ` hashes from `LSASS (Local Security Authority Service) ` also called `LSA (Local Security Authority)`

`LASASS ` This particular service also have cache of memory that will also contain these `hashes` as it interacts with the `SAM` database

`Mimikatz` interacts with the `LASASS` process and try and dump the cache of these process in order to identify the `NTLM hashes`


We can utilize `pre-compiled mimikatz executable`. Alternatively if we already have a meterpreter session on target we can utlize `inbuilt meterpreter extension Kiwi.`


