# Web Footprinting

- host information - `host`, `whois`, `whatweb`, `wafw00f`, `dig`, `dnsenum`, `DNSRecon`

- Public Information - `robots.txt`, `Google Dorks`, `TheHarvester`

# Basic Enumeration

- Basic Nmap Network Mapping - `-sV , -sC  -O,  -p-, -sU, -open`

# SMB Enumeration

(`Nmap`)

- SMB version, 
- Security controls 
- Active sessions
- List network shares and its content
- SMB Users
- SMB Statestics, 
- Domains
- Groups

Brute force for Credentials (`Hydra`, `Metasploit - smb_login`)

# HTTP Enumeration

(`Nmap`, `Curl`, `Whatweb`, `wget`, `dirb`, `Metasploit`)
- Web Server
- Services
- Banner
- robots.txt
- Directories
- Webdav

Brute force for Credentials (`Metasploit - http_login`)

****************************************************************************************************************************************************************
# `Genetrating and Encoding Payloads`

# Encoding Msfvenom payloads
- Using msfvenom encoders, the one with excellent rank , we used `x86/shikata_ga_nai `
- Generating it with multiple iterations to avoid being easily detected by `AV`

# Injecting msfvenom payload into portable executables
- Utilising `-x` flag with msfvenom payload generation, which allows us to specify any portable executable (we used winrar) as a template in which we want to inject our payload
- Getting meterpreter session on execution of this executable

****************************************************************************************************************************************************************

# `Exploitation`

# WebDAV Exploitation 
(`hydra`,`Nmap`, `davtest` , `cadaver`, `metasploit` (`msfvenom`, `windows/meterpreter/reverse_tcp`,`multi/handler`, `exploit/windows/iis/iis_webdav_upload_asp`))
- Identifying if WebDav is configured to run on the webserver (`http-webdav-scan`)
- BruteForce to get credentials for the webdav dir (`hydra`)
- Checking files that can be uploaded to webdav server (`davtest`)
- Genrating payload using (`msfvenom`)
- Uploading webshell on webdav server (`cadaver`)
- Start listener for payload port using (`multi/handler`)
- Getting reverse shell by browsing webshell manually
- Deleting webshell on webdav server (`cadaver`)
- Performing all above steps automated by metasploit module (`exploit/windows/iis/iis_webdav_upload_asp`)

# SMB Exploitation 
(`Nmap`, `metasploit`(`smb_login`, `exploit/windows/smb/psexec`))
- checking SMB version and security controls (message signing is not required)
- BruteForcing to get credentials (`smb_login`)
- Getting Meterpreter session / reverse shell using PsExec by metasploit module(`exploit/windows/smb/psexec`)
- Checking if SMBv1 is used and if is vulnerable to EternalBlue(`smb-vuln-ms17-010`,`auxillry/scanner`)
- Manually exploiting EternalBlue (CVE-2017-0144) (`AutoBlue`)
- Automated exploit by metasploit module (`exploit/windows/smb/smb_ms17_010_eternablue`)

# RDP Exploitation
(`Nmap`, `Metasploit`(`rdp_scanner, `), `Hydra`, `xfreerdp`)
- Finding the port on whic RDP service is running (`nmap`,`auxiliary/scanner/rdp/rdp_scanner`)
- BruteForcing to get credentials (`hydra`)
- Connecting to machine using rdp client (`xfreerdp`)
- Checking if BlueKeep (CVE-2019-0708) is present (`auxiliary/scanner/rdp/cve_2019_0708_bluekeep `)
- Exploiting BlueKeep (CVE-2019-0708) (`exploit/windows/rdp/cve_2019_0708_bluekeep_rce`)

# WinRM Exploitation
(`Nmap`, `crackmapexec`, `evil-winrm`)
- Finding WinRM service port is open
- BruteForcing to get credentials (`crackmapexec`)
- Executing arbitiary commands on remote system (`crackmapexec`)
- Obtaining command shell using ruby script (`evil-winrm.rb`)
- Getting meterpreter session using metasploit module (`windows/winrm/winrm_script_exec`)


**************************************************`Windows POST Exploitation stuff`********************************************

# `Privilege Escalation`

# PE by Kernel Exploits
- Considering we already have initial acces.
- Finding Kernel Exploits automatically using to Escalate privilege by Metasploit (`multi/recon/local_exploit_suggester`)
- Finding Kernel Exploits manually by using github repo which utlises windows `hotfixes`

# PE by Bypassing `UAC (User Access Control)`
- Consider we already have Intial acess by Exploiting Rejetto HTTP Server and getting meterpreter sesion
- Migrating to 64 bit process, since system is 64 bit, this also helps in persistence and sometimes increasing privileges
- Checking if user is part of `Local Admininstrator Group` which is a prerequisite to bypass UAC (`net localgroup administrators `)
- Creating payload (`msfvenom`) and uploading it.
- Start listening for payload port using (`multi/handler`) on diff terminal.
- uploading the `Akagai` executable to target sytstem to execute our payload by bypassing UAC.
- Executing the Akagai executable and getting response on our listener, thereby getting the same user with more privileges after bypassing UAC.
- Now we have more process available to migrate and after migrating to them we have highest privilege ie NT authority

- Bypassing UAC using metasploit `Memory Injection` module
- Consider user is very underprivileges and we are not able to escalate privileges by using `getsystem`
- Using `windows/local/bypassuac_injection` module the UAC gets disabled for the user
- Now we can elevate privileges by simply using `getsystem` and perform all administrative tasks without any error or providing credentials or needing apprioval

# Privilege Escalation by Impersonating `Windows Access Token `
- Consider we already have Intial acess by Exploiting Rejetto HTTP Server and getting meterpreter sesion
- Migrating to 64 bit process, since system is 64 bit, this also helps in persistence and sometimes increasing privileges
- Checking we have any of privileges (`SeAssignPrimaryToken`,`SeCreateToken`,`SeImpersonatePrivileges`)
- Loading meterpreter in-built module ('`incognito`)
- Listing the `Delegate Level` or `Delegation Tokens` available.
- Impersonating token with higher privilege.

by automated by `Meterpreter Incognito Mdodule`

# `Windows Credential(Hash) Dumping`

# Windows Configuration Files
- Searching Password in utilities that utilises `Windows Configuration file ` for example `Unattended Windows setup Utility`
    - Searching and downloading the unattentend.xml
    - Finding the credentials in file

# Mimikatz
- Using `Mimikatz` that interacts with the `LASASS` process and tries and dump the cache of these process in order to identify the `NTLM hashes` from `SAM` database
- Consider we already have Intial acess by Exploiting BadBlue service and getting meterpreter sesion
- Migrating to `LSASS` process
- Uploading `mimikatz.exe` to target system using metrerpreter
- Executing mimikatz.exe and dumping SAM database hashes
- Trying to get logon password if possible
- Automatiing above process using meterpreter in-build mimikatz module (`Kiwi`)

# Hashdump
- Dumping hashes using meterpreter in-built module `hashdump`
- Consider we already have Intial acess by Exploiting BadBlue service and getting meterpreter sesion
- Migrating to `LSASS` process and dumping hashes uising command `hashdump`


# `Detection Evasion Techniques`

# Resource Data Stream
- Using Windows `File System Vulnerabilities` to evade detection, Using Windows `Resource Data Stream` to Evade Static scans/ AV Detection
- Hiding the payload in resource stream of legitimate file.


# `Persistence Techniques`

# Pass The Hash Attack
- Using `Pass The Hash` technique that uses windows NTLM hashes or clear text passwords via `PsExec module`, `crackmapexec` etc... for `SMB`, this technique is basically maintain persistence
- Cool thing is we can simply use hash to authenticate

# Establishing persistence by Metasploit module
- Using `exploit/windows/local/persistence_service` module to establish persistence, after running this module we are able to gain acces to target again even after losing all sessions
- To get access back we simply need to run our listener on`multi/handler`  with same payload and same port which we used while establishing persistence


# Persistence Enabling RDP and addin backdoor user

- Using `windows/manage/enable_rdp` or `enable_rdp` module to enable RDP ervice and Firewall exception on target
- This module also allow us to Forward port 3389 to local port, create another user on target
- Getting user password either by dumping hashes and cracking them, or by creating another user, or in case if we have Highest NT Authority privilege we can simply change password of user (which is not recommended but done in this lab)

- Using meterpreter utility `getgui` to enable RDP, adding backdoor user, hiding user from windows login screen, adding user to Remote desktop Users and Administratos group 

# `Keylogging`
- Enabling Keylogging on target by using meterpreter `keyscan` commands

# `Pivoting `
- Adding a network route to target's internal netowork subnet (`auotoroute`)
- Portscanning the other target which directly inaccessible and is part of internal network
- Doing Nmap service scan on identifid port by enabling portforwarding on localhost/kali instance by meterpreter command `portfwd`
- Exploiting the vulnerablity utilising the route we already created before.

# `Clearing Tracks`

- Clrearing `Windows Event Logs` using meterpreter command `clearev`
- Remove artifacts left by post exploitation metasploit modules by `Resource Scripts`