
# Conider we have below scope

┌──(kali㉿kali)-[~]
└─$ `cat scope_list`
app.inlanefreight.local
dev.inlanefreight.local
drupal-dev.inlanefreight.local
drupal-qa.inlanefreight.local
drupal-acc.inlanefreight.local
drupal.inlanefreight.local
blog.inlanefreight.local
10.129.36.247
                   
# Service scan

┌──(kali㉿kali)-[~]
└─$ `sudo  nmap -p 80,443,8000,8080,8180,8888,10000 --open -sV -sC -iL scope_list`
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-04 02:04 EDT

Nmap scan report for app.inlanefreight.local (10.129.36.247)
Host is up (0.14s latency).
Not shown: 6 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Home
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-robots.txt: 15 disallowed entries 
| /joomla/administrator/ /administrator/ /bin/ /cache/ 
| /cli/ /components/ /includes/ /installation/ /language/ 
|_/layouts/ /libraries/ /logs/ /modules/ /plugins/ /tmp/
|_http-generator: Joomla! - Open Source Content Management

Nmap scan report for dev.inlanefreight.local (10.129.36.247)
Host is up (0.14s latency).
rDNS record for 10.129.36.247: app.inlanefreight.local
Not shown: 6 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-generator: Joomla! - Open Source Content Management
|_http-title: Home
| http-robots.txt: 15 disallowed entries 
| /joomla/administrator/ /administrator/ /bin/ /cache/ 
| /cli/ /components/ /includes/ /installation/ /language/ 
|_/layouts/ /libraries/ /logs/ /modules/ /plugins/ /tmp/

Nmap scan report for drupal-dev.inlanefreight.local (10.129.36.247)
Host is up (0.14s latency).
rDNS record for 10.129.36.247: app.inlanefreight.local
Not shown: 6 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-generator: Drupal 8 (https://www.drupal.org)
|_http-title: Home | Inlanefreight Dev
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-robots.txt: 22 disallowed entries (15 shown)
| /core/ /profiles/ /README.txt /web.config /admin/ 
| /comment/reply/ /filter/tips/ /node/add/ /search/ /user/register/ 
| /user/password/ /user/login/ /user/logout/ /index.php/admin/ 
|_/index.php/comment/reply/

Nmap scan report for drupal-qa.inlanefreight.local (10.129.36.247)
Host is up (0.14s latency).
rDNS record for 10.129.36.247: app.inlanefreight.local
Not shown: 6 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-title: drupal-qa.inlanefreight.local
|_http-generator: Drupal 7 (http://drupal.org)

Nmap scan report for drupal-acc.inlanefreight.local (10.129.36.247)
Host is up (0.14s latency).
rDNS record for 10.129.36.247: app.inlanefreight.local
Not shown: 6 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-generator: Drupal 7 (http://drupal.org)
|_http-title: Drupal ACC Environment

Nmap scan report for drupal.inlanefreight.local (10.129.36.247)
Host is up (0.14s latency).
rDNS record for 10.129.36.247: app.inlanefreight.local
Not shown: 6 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-robots.txt: 22 disallowed entries (15 shown)
| /core/ /profiles/ /README.txt /web.config /admin/ 
| /comment/reply/ /filter/tips /node/add/ /search/ /user/register/ 
| /user/password/ /user/login/ /user/logout/ /index.php/admin/ 
|_/index.php/comment/reply/
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-generator: Drupal 8 (https://www.drupal.org)
|_http-title: Home | Inlanefreight Blog

Nmap scan report for blog.inlanefreight.local (10.129.36.247)
Host is up (0.14s latency).
rDNS record for 10.129.36.247: app.inlanefreight.local
Not shown: 6 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-generator: WordPress 5.8
|_http-title: Inlanefreight Blog
|_http-server-header: Apache/2.4.41 (Ubuntu)

Nmap scan report for app.inlanefreight.local (10.129.36.247)
Host is up (0.14s latency).
Not shown: 6 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-robots.txt: 15 disallowed entries 
| /joomla/administrator/ /administrator/ /bin/ /cache/ 
| /cli/ /components/ /includes/ /installation/ /language/ 
|_/layouts/ /libraries/ /logs/ /modules/ /plugins/ /tmp/
|_http-generator: Joomla! - Open Source Content Management
|_http-title: Home

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 8 IP addresses (8 hosts up) scanned in 107.92 seconds

# From the scan we observed following services

app.inlanefreight.local	          - Joomla! - Open Source Content Management
dev.inlanefreight.local           - Joomla! - Open Source Content Management
drupal-dev.inlanefreight.local    - Drupal 8 (https://www.drupal.org)
drupal-qa.inlanefreight.local     - Drupal 7 (http://drupal.org)
drupal-acc.inlanefreight.local    - Drupal 7 (http://drupal.org)
drupal.inlanefreight.local        - Drupal 8 (https://www.drupal.org)
blog.inlanefreight.local          - WordPress 5.8
10.129.36.247                     - Joomla! - Open Source Content Management



It is important at this point to remember that we are still in the information gathering phase, and every little detail could make or break our assessment. We should not get careless and begin attacking hosts right away, as we may end up down a rabbit hole and miss something crucial later in the report. During an External Penetration Test, I would expect to see a mix of custom applications, some CMS, perhaps applications such as Tomcat, Jenkins, and Splunk, remote access portals such as Remote Desktop Services (RDS), SSL VPN endpoints, Outlook Web Access (OWA), O365, perhaps some sort of edge network device login page, etc.