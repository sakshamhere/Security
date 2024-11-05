https://github.com/nickvourd/Windows-Local-Privilege-Escalation-Cookbook/blob/master/Notes/UnquotedServicePath.md

https://medium.com/@SumitVerma101/windows-privilege-escalation-part-1-unquoted-service-path-c7a011a8d8ae

https://infosecwriteups.com/enterprise-tryhackme-writeup-aee8691afa17

# About 

In Windows When a service is created whose executable path contains `spaces` and isn’t enclosed within quotes, it would handle the space as a break and pass the rest of the service path as an argument. 

It leads to a vulnerability known as Unquoted Service Path which allows a user to gain SYSTEM privileges (`only if the vulnerable service is running with SYSTEM privilege level which most of the time it is`).


For example, consider we have the following executable path.

`C:\Program Files\A Subfolder\B Subfolder\C Subfolder\SomeExecutable.exe`

In order to run SomeExecutable.exe, the system will interpret this path in the following order from 1 to 5.

    1. C:\Program.exe
    2. C:\Program Files\A.exe
    3. C:\Program Files\A Subfolder\B.exe
    4. C:\Program Files\A Subfolder\B Subfolder\C.exe
    5. C:\Program Files\A Subfolder\B Subfolder\C Subfolder\SomeExecutable.exe

If C:\Program.exe is not found, then C:\Program Files\A.exe would be executed. If C:\Program Files\A.exe is not found, then C:\Program Files\A Subfolder\B.exe would be executed and so on.

# Exploitation

Find the unquoted service path

> `wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v """`

/i means ignore the case
/v means except <this argument> find others.

Check if we/Users have write access to that folder using `icacls`

> `icacls "C:\Program Files\Target Folder`

Considering we have the write permissions in the context of the user shell (more on this later) in any of the spaced folders above, we as an attacker can drop our malicious executable in that folder to get a reverse shell as SYSTEM. 

To get reverse shell we will have to run the service using powershell,  or else if its 'autorun' enabled it will run automatically on system restart

*************************************************************************************
# POC

check above mentioned medium articles

check Enterprise room tryhackme soleved
