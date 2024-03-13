# SAM (Security Access Manager) database file

Windows store passwords in the registry in a hashed (`NTLM Hash`) format using the NTLM algorithm. The registry file is called `SAM (Security Access Manager) database file` and is located in `C:\windows\system32\config\SAM`

The `SAM` Database fle cannot be copied while OS us running.

Thw Windows NT Kernel keeps the SAM database file lokcked and as a result, attackers typically utilize in-memory technique and tools to dump `SAM ` hashes from `LSASS (Local Security Authority Service) ` also called `LSA (Local Security Authority)`

`LASASS ` This particular service also have cache of memory that will also contain these `hashes` as it interacts with the `SAM` database

Tools like `Mimikatz` interacts with the `LASASS` process and try and dump the cache of these process in order to identify the `NTLM hashes`

In Modern versions of Windows the SAM database is encrypted with a `syskey`


NOTE - `Elevated/Administrative privileges are required in order to access and interct with LASASS process`

***************************************************************************************************************************************

This area of the registry has restrictive permissions so that a normal user cannot see the contents of HKLM\SAM deep enough to access the hash.

In order to view the hashes one must change the permissions on the registry keys, this requires an administrative account on the system

There are many places on the internet that you can find information about brute forcing a `NTLM hash`

the hash is stored under the key

`HKLM\SAM\SAM\Domains\Account\Users\00000XXX `

with a value named V. The hash is stored at a variable offset that is stored at offset 0x9C and is a 4 byte little endian value.



