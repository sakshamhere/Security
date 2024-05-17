
# What is system root in windows?
When it is said system root then it is the C:// drive and more precisely the C://windows/system32 folder


# Windows password are stored in?
https://superuser.com/questions/235300/where-does-windows-os-store-user-passwords

Normally, Windows store passwords on single computer systems in the registry in a hashed format using the NTLM algorithm. The registry file is located in

`C:\windows\system32\config\SAM`

This area of the registry has restrictive permissions so that a normal user cannot see the contents of HKLM\SAM deep enough to access the hash.

In order to view the hashes one must change the permissions on the registry keys, this requires an administrative account on the system

There are many places on the internet that you can find information about brute forcing a NTLM hash

the hash is stored under the key

`HKLM\SAM\SAM\Domains\Account\Users\00000XXX `

with a value named V. The hash is stored at a variable offset that is stored at offset 0x9C and is a 4 byte little endian value.