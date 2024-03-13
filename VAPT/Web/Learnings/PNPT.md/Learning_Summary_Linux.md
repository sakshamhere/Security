# Web Footprinting

- host information - `host`, `whois`, `whatweb`, `wafw00f`, `dig`, `dnsenum`, `DNSRecon`

- Public Information - `robots.txt`, `Google Dorks`, `TheHarvester`

# Basic Enumeration

- Basic Nmap Network Mapping - `-sV , -sC  -O,  -p-, -sU, -open`

# SAMBA
(`Nmap`, `smbmap`, `Metasploit`, `smbclient`, `rpcclient`, `enum4linux`)

- SAMBA version                             
- SAMBA server OS version
- Server description
- Workgroup name
- NetBios computer name
- SMB Users
- User's SID
- Domain Groups
- Configured for Printing
- Anonymous connection allowed
- list Network shares and its content
- Remote code Execution
- Uploading and downloading file to network share

Brute force for Credentials (`Hydra`, `Metasploit - smb_login`)

# FTP Enumeration

(`Nmap`)
- Version 
- Anonymous Connection Allowed

Brute force for Credentials (`Nmap - ftp-brute`,`Hydra`,`Metasploit - ftp_login`)

# SSH Enumeration

(`Nmap`, `Netcat`)
- Version
- Pre-Login Banner
- Encryption Algorithms supported
- SSH Host Key, RSA Key
- Authentication methods supported for specific user
- Anonymous Connection Allowed

Brute force for Credentials (`Nmap - ssh-brute`,`Hydra`,`Metasploit - ssh_login`)





*************************************************************************************************************************************************************

# `Exploitation`

# Apache Server Exploitation
- Apache web server configured to run `CGI Scripts` or `.sh` scripts are possible to vulnerbale to `Remote Code Execution` by attacker by gaiing access to bash shell through exlploitation of `CGI Scripts` or `.sh` scripts configured to run on web server.
- Checking if `ShellShock` vulnerability exist
- start listening on kali machine (`netcat`)
- Exploiting Manually using Burp.
- Exploiting Automatically using metasploit module (`multi/http/apache_mod_cgi_bash_env_exec`)

# Exploiting SAMBA
- checking samba version and if its vulnerable (`nmpa`)
- bruteforcing to get cred (`hydra`)
- enumnnerating SAMBA server using (`smbmap`, `smbclient`, `enum4linux`)
- accessing samba server share using (`smbclient`)

# Exploiting FTP
- Checking the file server type and version (`nmap`)
- Checking if anonymous auth is allowed (`metasploit`,`nmap`)
- bruteforcing to get cred (`hydra`,`ftp-brute`,`ftp_login`)
- Using `SearchSploit` to check exploits available
- exploiting if explopit available

# Exploiting SSH
- Check auth methods supported or if auth not requied for user
- bruteforcing to get cred (`hydra`,`ssh-brute`,`ssh_login`)


# `Post Exploitation`

# Post Exploitation Enumeration

- `enum_config` Enumerating all existing configuration files
- `enum_network` network related information on the system
- `enum_protections`, this gives prottections in place
- `enum_system`, this gives and system and user info

# Linux (root) Privilege Escalation

# PE by Kernel Exploits

- Considering we already have initial acess by exploiting vul and obtaining a shell on target
- We can downbload the `Linux Exploit Suggestors` from git
- Uploading the `les.sh` to targte using meterpreter
- Providing the execute permission to les.sh file and Executing it
- After its execution we automatically have the privilege escalated

# PE by Misconfigured SUDO permissions

- Considering we already have initial access by exploiting SSH.
- Using `/usr/bin/man` access provided as sudo permission to get root privileges by command execution privided by binary
- Using `/usr/bin/nano` access provided as sudo permission to edit and change permissions of user same as root in `/etc/sudoers`
- Using `/usr/bin/nano` access provided as sudo permission to get root privileges by command execution privided by binary utilising `GTFOBins`
- Using env variable like `LD_PRELOAD` , `LD_LIBRARY_PATH` to preload our malicious binary at runtime thereby replacing the actuaal shared library/dynamically linjked library assosiated with /usr/bin/nano

# PE by Misconfigured Cron Jobs

- Considering we already have initial acess by exploiting vul and obtaining a shell on target
- Enueraring user privileges and groups and crong jobs assosiated with user
- Identifying cron jobs created by `root user` and its purpose
- checking if the we have read write access to the file in action for cron job
- Editing the file to change the privileges for the current user by trying to make changes in `/etc/sudoers` file

- Identifying all the system-wide cron job by `/etc/crontab`
- OBserving scripts attached with the cron jobs
- Tampering script go get a reverse shell

- Obseriving existing cron jobs whose attached scripts cant be located
- Using such scripts name to put our reveser shell code in case the full path of script was not defined as in that case it will use same path defined in /etc/crontab 

# PE by Misconfigured SUID Binaries

- Considering we already have initial acess by exploiting vul and obtaining a shell on target
- Finding `SUID binary` with `owner as root` and `of which we have execute permission`.
- Finding more details about the binary (`file`,`strings`)
- figuring out a way to execute bash with this binary as it will run it with root privilege

# PE by Vulnerable Programs and services
- Consider we already gained access by exploiting SSH
- After enumerating processess (`ps aux`) we found program/binary/script `/bin/check-down` with command `/bin/bash`, in this case the binary executes `chkrootkit` vulnerable version in every 60 seconds
- this vulnerable version when exploited provides local privilege escalation
- exploiting it using metasploit module `unix/local/chkrootkit`


# PE by Misconfigured file permissions file

- Find file with improper permissions, like in this lab /etc/shadow was having read write permission for all users in system due to which we are able to add hashed password for root in it and use it to elevate privileges
- In real world this will be some other file with misconfigured permissions we can use to elevate privileges or do certain damage 

# PE by Folders in PATH env variable
- If a folder for which your user has write permission is located in the path, you could potentially hijack an application to run a script. PATH in Linux is an environmental variable that tells the operating system where to search for executables. 
- Below are conditions required
    1. What folders are located under $PATH
    2. Does your current user have write privileges for any of these folders?
    3. Can you modify $PATH?
    4. Is there a script/application you can start that will be affected by this vulnerability?

# PE by NFS Root Sqashing


# `Linux Password Hash Dumping and Cracking`
- Basic dumping of hash by gaining root privilege and accessing `etc/shadow` file
- Dumping hashes using metaploit module (`linux/gather/hashdump`)

# `Persistence Techniqies`

# Persistence Establishment manually

- After we gained root user access, we create a backdoor user and give a password.
- Add this user to group which root user belongs
- This needs to be created in such a way that it dosent get detected by administrator, by giving name like a service account, by changeing user id etc etc
- Later in case we lose connection we can simply do ssh by our backdoor user and gain access again

# Persistence Establishment by metasploit module

- After we gained access to root user, we can utilise metasploit module like `linux/manage/sshkey_persistence`
- this module add ssh keys toall user home directores and provides us the private key
- In case we lose access to target we can simply use this private key and gain back the access