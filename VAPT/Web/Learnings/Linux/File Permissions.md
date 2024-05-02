# File Permissions

# Permission notations

Octal Mode Number 	Description
0400 	Allows the owner to read
0200 	Allows the owner to write
0100 	Allows the owner to execute files and search in the directory
0040 	Allows group members to read
0020 	Allows group members to write
0010 	Allows group members to execute files and search in the directory
0004 	Allows everyone or the world to read
0002 	Allows everyone or the world to write
0001 	Allows everyone or the world to execute files and search in the directory
1000 	Sets the sticky bit
2000 	Sets the setgid bit
4000 	Sets the setuid bit

First digit in the above mode number is used to set setuid, setgid, or sticky bit. Each remain digit set permission for the owner, group, and world as follows:

    4 = r (Read)
    2 = w (Write)
    1 = x (eXecute)

---     ---     ---
rwx     rwx     rwx
user    group   other 

# SUID (Set Owner User Id) Permission

In addition to the `rwx (read, write, execute)` permission linux also provide user with specialised permissions that can be utilizsed in specific situations one of these access permission is `SUID (Set Owner User Id)` permission.

When applied this permission provide user with ability to execute a script or a binary with the permission of file owner instead of user that is running the script.

`SUID` permissions are typically used to provide unprivileged users with ability to run specific scripts or binaries with root privileges.

By `SUID` the elevation of privilege is limited to execution of binary or script only it dosent elevate the users privilege, however if improperly configured unprivileged user can exploit misconfigurations or vulnerabilities in the binary or script to obtain an elevates session.   
 

# SUID and GUID Permissions

* Finding Files With SUID and SGID Permissions in Linux

https://www.geeksforgeeks.org/finding-files-with-suid-and-sgid-permissions-in-linux/

`SUID(Set-user Identification) and SGID(Set-group identification)` are two special permissions that can be set on executable files, and These permissions allow the file being executed to be executed with the privileges of the owner or the group.

`SUID`: It is special file permission for executable files. This enables other users to run the file with the effective permissions of the file owner. But Instead of normal x which represents executable permissions. We will see s(this indicates SUID) special permission for the user.

`SGID:` This is also special file permission for executable files that enables other users to inherit the effective GID(Group Identifier) of a group owner. Here rather than x which represents executable permissions, we will see s(which indicates SGID) special permission for group users

# Finding Files With SUID and SGID Permissions in Linux
https://www.geeksforgeeks.org/finding-files-with-suid-and-sgid-permissions-in-linux/
https://askubuntu.com/questions/532952/what-does-perm-4000-o-perm-2000

If you want to only find files with SUID

`find /home -user root -perm -4000`

If you want to only find files with SGID

`find /home -user root -perm -2000`

If you want to find files with either SUID or SGUID

`find / -type f \( -perm -4000 -o -perm -2000 \) -print`