# Checkin service on port 80, we observe Apache linux server is there

root@INE:~# `nmap 192.102.102.3 -sV -p 80`
Starting Nmap 7.92 ( https://nmap.org ) at 2023-12-11 15:50 IST
Nmap scan report for 8es64jde993445ldonm0uj66b.temp-network_a-102-102 (192.102.102.3)
Host is up (0.000032s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
MAC Address: 02:42:C0:66:66:03 (Unknown)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.52 seconds

# checking Banner info, which gives same info

root@INE:~# `nmap 192.102.102.3 -p 80 -sV --script banner`
Starting Nmap 7.92 ( https://nmap.org ) at 2023-12-11 15:56 IST
Nmap scan report for 8es64jde993445ldonm0uj66b.temp-network_a-102-102 (192.102.102.3)
Host is up (0.000034s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
MAC Address: 02:42:C0:66:66:03 (Unknown)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.51 seconds

# checking same info using metasploit

msf6 > `use auxiliary/scanner/http/http_version `
msf6 auxiliary(scanner/http/http_version) > `options`

Module options (auxiliary/scanner/http/http_version):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                    yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT    80               yes       The target port (TCP)
   SSL      false            no        Negotiate SSL/TLS for outgoing connections
   THREADS  1                yes       The number of concurrent threads (max one per host)
   VHOST                     no        HTTP server virtual host

msf6 auxiliary(scanner/http/http_version) > `set rhosts 192.102.102.3`
rhosts => 192.102.102.3
msf6 auxiliary(scanner/http/http_version) > `run`

[+] 192.102.102.3:80 Apache/2.4.18 (Ubuntu)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

# checking same info using curl

root@INE:~# `curl 192.102.102.3 | more`
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 11321  100 11321    0     0  8219k      0 --:--:-- --:--:-- --:--:-- 10.7M

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
  <!--
    Modified from the Debian original for Ubuntu
    Last updated: 2014-03-19
    See: https://launchpad.net/bugs/1288690
  -->
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <title>Apache2 Ubuntu Default Page: It works</title>
    <style type="text/css" media="screen">
  * {
    margin: 0px 0px 0px 0px;
    padding: 0px 0px 0px 0px;
  }

  body, html {
    padding: 3px 3px 3px 3px;

    background-color: #D8DBE2;

    font-family: Verdana, sans-serif;
    font-size: 11pt;
    text-align: center;
  }

  div.main_page {
    position: relative;
    display: table;

# checking same info using `wget`

root@INE:~# `wget http://192.102.102.3/index`
root@INE:~# `cat index | more`

# checking same info using `browsh` a CLI based browser

root@INE:~# `browsh --startup-url 192.102.102.3`

# checking same info using `lynx` a CLI based browser

root@INE:~# `lynx http://192.102.102.3`

# checking directories using metasploit

msf6 > `use auxiliary/scanner/http/brute_dirs`
msf6 auxiliary(scanner/http/brute_dirs) > `options`

Module options (auxiliary/scanner/http/brute_dirs):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   DELAY    0                yes       The delay between connections, per thread, in milliseconds
   FORMAT   a,aa,aaa         yes       The expected directory format (a alpha, d digit, A upperalpha)
   JITTER   0                yes       The delay jitter factor (maximum value by which to +/- DELAY) in milliseconds.
   PATH     /                yes       The path to identify directories
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                    yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT    80               yes       The target port (TCP)
   SSL      false            no        Negotiate SSL/TLS for outgoing connections
   THREADS  1                yes       The number of concurrent threads (max one per host)
   TIMEOUT  20               yes       The socket connect/read timeout in seconds
   VHOST                     no        HTTP server virtual host

msf6 auxiliary(scanner/http/brute_dirs) > `set rhosts 192.102.102.3`
rhosts => 192.102.102.3
msf6 auxiliary(scanner/http/brute_dirs) > `run`

[*] Using code '404' as not found.
[+] Found http://192.102.102.3:80/dir/ 200
[+] Found http://192.102.102.3:80/src/ 200
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

# checking same using dirb

root@INE:~# `dirb http://192.102.102.3 /usr/share/metasploit-framework/data/wordlists/directory.txt `

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Mon Dec 11 16:36:19 2023
URL_BASE: http://192.102.102.3/
WORDLIST_FILES: /usr/share/metasploit-framework/data/wordlists/directory.txt

-----------------

GENERATED WORDS: 24                                                            

---- Scanning URL: http://192.102.102.3/ ----
+ http://192.102.102.3//data (CODE:301|SIZE:313)                                                                                                     
+ http://192.102.102.3//dir (CODE:301|SIZE:312)                                                                                                      
                                                                                                                                                     
-----------------
END_TIME: Mon Dec 11 16:36:19 2023
DOWNLOADED: 24 - FOUND: 2

# checking robots

msf6 > `use auxiliary/scanner/http/robots_txt `
msf6 auxiliary(scanner/http/robots_txt) > `options`

Module options (auxiliary/scanner/http/robots_txt):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   PATH     /                yes       The test path to find robots.txt file
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                    yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT    80               yes       The target port (TCP)
   SSL      false            no        Negotiate SSL/TLS for outgoing connections
   THREADS  1                yes       The number of concurrent threads (max one per host)
   VHOST                     no        HTTP server virtual host

msf6 auxiliary(scanner/http/robots_txt) > `set rhosts 192.102.102.3`
rhosts => 192.102.102.3
msf6 auxiliary(scanner/http/robots_txt) > `run`

[*] [192.102.102.3] /robots.txt found
[+] Contents of Robots.txt:
User-agent: *
Disallow: /cgi-bin/
Disallow: Disallow: /junk/

User-agent: BadBot
Disallow: /no-badbot-dir/

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

# checking diallowed dir and it givs 403

root@INE:~# curl http://192.102.102.3/cgi-bin/ | more
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   296  100   296    0     0  32877      0 --:--:-- --:--:-- --:--:-- 37000
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access /cgi-bin/
on this server.<br />
</p>
<hr>
<address>Apache/2.4.18 (Ubuntu) Server at 192.102.102.3 Port 80</address>
</body></html>
